package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/simonmittag/procspy"
)

type ConnectionLogEntry struct {
	Timestamp   time.Time `json:"timestamp"`
	Action      string    `json:"action"`
	ProcessName string    `json:"process_name"`
	PID         uint32    `json:"pid"`
	Destination string    `json:"destination"`
	PacketInfo  string    `json:"packet_info"`
}

type ConnectionLogger struct {
	logFile *os.File
	entries []ConnectionLogEntry
}

// DNSCache stores mappings between IPs and domains
type DNSCache struct {
	mu    sync.RWMutex
	cache map[string]string // ip -> domain
}

// Add adds an IP-domain mapping to the cache
func (d *DNSCache) Add(ip, domain string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cache[ip] = domain
}

// Get returns the domain for an IP if it exists
func (d *DNSCache) Get(ip string) (string, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	domain, ok := d.cache[ip]
	return domain, ok
}

var CurrentFirewallMode FirewallMode
var connectionLogger *ConnectionLogger
var dnsCache *DNSCache

func main() {
	firewallMode := flag.String("firewall-mode", "audit", "The firewall mode to apply. One of: audit, block, block-with-dns")
	tetragonAddress := flag.String("tetragon-address", "localhost:54321", "The address of the Tetragon gRPC server.")
	nfqueueNum := flag.Int("nfqueue-num", 0, "The nfqueue number to listen on.")
	allowedIPsStr := flag.String("allowed-ips", "", "Comma-separated list of allowed IP addresses")
	allowedDomainsStr := flag.String("allowed-domains", "", "Comma-separated list of allowed domains (supports wildcards)")
	dnsPolicy := flag.String("dns-policy", "allowed-domains-only", "DNS policy: allowed-domains-only or any")

	flag.Parse()

	allowedIPs := parseIPList(*allowedIPsStr)
	allowedDomains := parseDomainList(*allowedDomainsStr)

	IPAllowedList = allowedIPs
	DomainAllowedList = allowedDomains
	DNSSetting = *dnsPolicy
	CurrentFirewallMode = FirewallMode(*firewallMode)

	dnsCache = &DNSCache{
		cache: make(map[string]string),
	}

	connectionLogger = NewConnectionLogger("connection_log.json")
	defer connectionLogger.Close()

	fmt.Printf("Applying firewall mode: %s\n", *firewallMode)
	fmt.Printf("Allowed IPs: %v\n", allowedIPs)
	fmt.Printf("Allowed domains: %v\n", allowedDomains)
	fmt.Printf("DNS Policy: %s\n", *dnsPolicy)

	if err := ApplyFirewallRules(FirewallMode(*firewallMode)); err != nil {
		log.Fatalf("Failed to apply firewall rules: %v", err)
	}

	fmt.Println("Successfully applied firewall rules.")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	processCache := NewProcessCache()

	go func() {
		fmt.Printf("Connecting to Tetragon at %s\n", *tetragonAddress)
		tgClient, err := NewTetragonClient(*tetragonAddress)
		if err != nil {
			log.Fatalf("Failed to create Tetragon client: %v", err)
		}
		defer tgClient.Close()

		events := make(chan *tetragon.GetEventsResponse)
		go tgClient.GetEvents(ctx, events)

		fmt.Println("Waiting for events...")
		for {
			select {
			case <-ctx.Done():
				return
			case res := <-events:
				switch event := res.GetEvent().(type) {
				case *tetragon.GetEventsResponse_ProcessExec:
					processCache.Add(event.ProcessExec.Process.Pid.Value, event.ProcessExec.Process)
				case *tetragon.GetEventsResponse_ProcessExit:
					processCache.Delete(event.ProcessExit.Process.Pid.Value)
				}
			}
		}
	}()

	fmt.Printf("Listening on nfqueue %d\n", *nfqueueNum)
	nfq, err := NewNFQueue(uint16(*nfqueueNum))
	if err != nil {
		log.Fatalf("Failed to create nfqueue: %v", err)
	}
	defer nfq.Close()

	packetCallback := func(data CallbackData) {
		packet := data.Packet
		packetID := data.PacketID
		var srcPort uint16
		var dstIP net.IP

		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			dstIP = net.IP(ip.DstIP)
		} else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv6)
			dstIP = net.IP(ip.DstIP)
		}

		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			srcPort = uint16(tcp.SrcPort)
		} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			srcPort = uint16(udp.SrcPort)
		}

		// Check if this is DNS traffic
		if isDNSTraffic(packet) {
			// Check if this is a DNS response (incoming traffic to port 53)
			var isResponse bool
			if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
				udp, _ := udpLayer.(*layers.UDP)
				isResponse = uint16(udp.DstPort) == 53
			} else if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)
				isResponse = uint16(tcp.DstPort) == 53
			}

			if isResponse {
				// This is a DNS response, parse it and update the DNS cache
				domain, ipAddrs, dnsIsResponse := parseDNSResponse(packet)
				if dnsIsResponse && len(ipAddrs) > 0 {
					for _, ip := range ipAddrs {
						fmt.Printf("DNS RESPONSE: %s -> %s\n", domain, ip.String())
						dnsCache.Add(ip.String(), domain)
					}
				}
			}

			// Handle DNS requests based on DNS policy
			if DNSSetting == "allowed-domains-only" {
				// For now, allow all DNS traffic but the cache will be used for
				// blocking connections to non-allowed domains
				fmt.Printf("DNS TRAFFIC: Allowing DNS request to %s\n", dstIP)
				nfq.SetVerdict(packetID, 1)
				return
			} else {
				nfq.SetVerdict(packetID, 1)
				return
			}
		}

		if srcPort != 0 {
			cs, err := procspy.Connections(true)
			if err != nil {
				log.Printf("could not get connections: %v", err)
				nfq.SetVerdict(packetID, 1)
				return
			}

			var matchedConn *procspy.Connection
			for c := cs.Next(); c != nil; c = cs.Next() {
				if c.LocalPort == srcPort {
					matchedConn = c
					break
				}
			}

			if matchedConn != nil {
				if process, ok := processCache.Get(uint32(matchedConn.PID)); ok {
					isAllowed := isConnectionAllowed(dstIP, process, allowedIPs, allowedDomains)

					binaryName := process.Binary
					if binaryName == "" {
						binaryName = "unknown"
					}

					if isAllowed {
						fmt.Printf("ALLOWED: Packet from %s (%d) -> %s: %s\n", binaryName, matchedConn.PID, dstIP, packet.String())
						if connectionLogger != nil {
							connectionLogger.LogConnection("ALLOWED", binaryName, uint32(matchedConn.PID), dstIP.String(), packet.String())
						}
						nfq.SetVerdict(packetID, 1)
					} else {
						fmt.Printf("BLOCKED: Packet from %s (%d) -> %s: %s\n", binaryName, matchedConn.PID, dstIP, packet.String())
						if connectionLogger != nil {
							connectionLogger.LogConnection("BLOCKED", binaryName, uint32(matchedConn.PID), dstIP.String(), packet.String())
						}
						nfq.SetVerdict(packetID, 0)
					}
				} else {
					nfq.SetVerdict(packetID, 1)
				}
			} else {
				nfq.SetVerdict(packetID, 1)
			}
		} else {
			nfq.SetVerdict(packetID, 1)
		}
	}

	if err := nfq.Register(ctx, packetCallback); err != nil {
		log.Fatalf("Failed to register nfqueue callback: %v", err)
	}

	go func() {
		http.HandleFunc("/update-allowed-ips", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}

			ips := r.FormValue("ips")
			newIPs := parseIPList(ips)

			IPAllowedList = newIPs

			if err := ApplyFirewallRules(CurrentFirewallMode); err != nil {
				http.Error(w, fmt.Sprintf("Failed to update firewall rules: %v", err), http.StatusInternalServerError)
				return
			}

			fmt.Fprintf(w, "Updated allowed IPs to: %v", newIPs)
		})

		http.HandleFunc("/update-allowed-domains", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}

			domains := r.FormValue("domains")
			newDomains := parseDomainList(domains)

			DomainAllowedList = newDomains

			fmt.Fprintf(w, "Updated allowed domains to: %v", newDomains)
		})

		http.HandleFunc("/update-dns-policy", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}

			policy := r.FormValue("policy")
			if policy != "allowed-domains-only" && policy != "any" {
				http.Error(w, "Invalid DNS policy. Must be 'allowed-domains-only' or 'any'", http.StatusBadRequest)
				return
			}

			DNSSetting = policy

			fmt.Fprintf(w, "Updated DNS policy to: %s", policy)
		})

		http.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "Allowed IPs: %v\n", IPAllowedList)
			fmt.Fprintf(w, "Allowed Domains: %v\n", DomainAllowedList)
			fmt.Fprintf(w, "DNS Policy: %s\n", DNSSetting)
		})

		http.HandleFunc("/report", func(w http.ResponseWriter, r *http.Request) {
			if connectionLogger == nil {
				http.Error(w, "Logger not initialized", http.StatusInternalServerError)
				return
			}

			report := connectionLogger.GetReport()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(report)
		})

		fmt.Println("Starting policy update server on :8080")
		if err := http.ListenAndServe(":8080", nil); err != nil {
			log.Printf("HTTP server error: %v", err)
		}
	}()

	<-ctx.Done()
}

func NewConnectionLogger(filename string) *ConnectionLogger {
	file, err := os.Create(filename)
	if err != nil {
		log.Printf("Failed to create log file: %v", err)
		return &ConnectionLogger{entries: make([]ConnectionLogEntry, 0)}
	}

	return &ConnectionLogger{
		logFile: file,
		entries: make([]ConnectionLogEntry, 0),
	}
}

func (cl *ConnectionLogger) LogConnection(action, processName string, pid uint32, destination string, packetInfo string) {
	entry := ConnectionLogEntry{
		Timestamp:   time.Now(),
		Action:      action,
		ProcessName: processName,
		PID:         pid,
		Destination: destination,
		PacketInfo:  packetInfo,
	}

	cl.entries = append(cl.entries, entry)

	jsonData, err := json.Marshal(entry)
	if err != nil {
		log.Printf("Failed to marshal log entry: %v", err)
		return
	}

	if cl.logFile != nil {
		cl.logFile.Write(jsonData)
		cl.logFile.WriteString("\n")
		cl.logFile.Sync()
	}
}

func (cl *ConnectionLogger) Close() {
	if cl.logFile != nil {
		cl.logFile.Close()
	}
}

func (cl *ConnectionLogger) GetReport() map[string]interface{} {
	report := make(map[string]interface{})

	blockedCount := 0
	allowedCount := 0
	blockedByProcess := make(map[string]int)
	allowedByProcess := make(map[string]int)

	for _, entry := range cl.entries {
		if entry.Action == "BLOCKED" {
			blockedCount++
			blockedByProcess[entry.ProcessName]++
		} else if entry.Action == "ALLOWED" {
			allowedCount++
			allowedByProcess[entry.ProcessName]++
		}
	}

	report["blocked_count"] = blockedCount
	report["allowed_count"] = allowedCount
	report["blocked_by_process"] = blockedByProcess
	report["allowed_by_process"] = allowedByProcess
	report["total_connections"] = len(cl.entries)

	return report
}

func parseIPList(ipStr string) []net.IP {
	var ips []net.IP
	if ipStr == "" {
		return ips
	}

	ipStrings := strings.Split(ipStr, ",")
	for _, ipStr := range ipStrings {
		ipStr = strings.TrimSpace(ipStr)
		if ip := net.ParseIP(ipStr); ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips
}

func parseDomainList(domainStr string) []string {
	var domains []string
	if domainStr == "" {
		return domains
	}

	domainStrings := strings.Split(domainStr, "\n")
	for _, domainStr := range domainStrings {
		domainStr = strings.TrimSpace(domainStr)
		if domainStr != "" {
			domains = append(domains, strings.ToLower(domainStr))
		}
	}
	return domains
}

func isIPAllowed(dstIP net.IP, allowedIPs []net.IP) bool {
	for _, allowedIP := range allowedIPs {
		if dstIP.Equal(allowedIP) {
			return true
		}
	}
	if dstIP.IsLoopback() {
		return true
	}
	return false
}

func matchesDomain(hostname string, allowedDomains []string) bool {
	hostname = strings.ToLower(hostname)
	for _, domain := range allowedDomains {
		if domain == hostname {
			return true
		}
		if strings.HasPrefix(domain, "*.") {
			suffix := domain[2:]
			if strings.HasSuffix(hostname, "."+suffix) {
				return true
			}
		}
	}
	return false
}

func isConnectionAllowed(dstIP net.IP, process *tetragon.Process, allowedIPs []net.IP, allowedDomains []string) bool {
	if isIPAllowed(dstIP, allowedIPs) {
		return true
	}

	// Check if the IP corresponds to an allowed domain using DNS cache
	ipStr := dstIP.String()
	if domain, ok := dnsCache.Get(ipStr); ok {
		if matchesDomain(domain, allowedDomains) {
			return true
		}
	}

	return false
}

func isDNSTraffic(packet gopacket.Packet) bool {
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		return uint16(udp.DstPort) == 53 || uint16(udp.SrcPort) == 53
	}
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		return uint16(tcp.DstPort) == 53 || uint16(tcp.SrcPort) == 53
	}
	return false
}

// parseDNSResponse extracts domain names and IP addresses from DNS response packets
func parseDNSResponse(packet gopacket.Packet) (domain string, ipAddrs []net.IP, isResponse bool) {
	var dnsPayload []byte

	// Extract DNS payload from the packet
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		dnsPayload = udp.Payload
	} else if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		dnsPayload = tcp.Payload
		// TCP DNS has 2-byte length prefix, skip it
		if len(dnsPayload) >= 2 {
			dnsPayload = dnsPayload[2:]
		}
	} else {
		return "", nil, false
	}

	if len(dnsPayload) < 12 {
		return "", nil, false
	}

	// Check if this is a DNS response (QR bit set)
	flags := binary.BigEndian.Uint16(dnsPayload[2:4])
	isResponse = (flags & 0x8000) != 0

	if !isResponse {
		return "", nil, false
	}

	// Extract query name
	queryName := parseDomainName(dnsPayload, 12, len(dnsPayload))
	if queryName == "" {
		return "", nil, false
	}

	// Find answers section (skip header and question)
	queryEnd := 12
	// Skip query name
	for queryEnd < len(dnsPayload) {
		if dnsPayload[queryEnd] == 0 {
			queryEnd++
			break
		} else if dnsPayload[queryEnd]&0xC0 == 0xC0 {
			// Compressed label
			queryEnd += 2
			break
		} else {
			// Regular label - skip length + label content
			queryEnd += 1 + int(dnsPayload[queryEnd])
		}
	}

	// Skip QTYPE (2 bytes) and QCLASS (2 bytes)
	queryEnd += 4

	// Process resource records in the answer section
	var ipAddresses []net.IP
	ancount := binary.BigEndian.Uint16(dnsPayload[6:8])
	current := queryEnd

	for i := 0; i < int(ancount) && current < len(dnsPayload); i++ {
		// Skip record name (same as query name or compressed pointer)
		if current >= len(dnsPayload) {
			break
		}
		if dnsPayload[current]&0xC0 == 0xC0 {
			// Compressed name (2 bytes)
			current += 2
		} else {
			// Uncompressed name - parse until we hit a null terminator
			for current < len(dnsPayload) && dnsPayload[current] != 0 {
				if dnsPayload[current]&0xC0 == 0xC0 {
					current += 2
					break
				} else {
					current += 1 + int(dnsPayload[current])
				}
			}
			if current < len(dnsPayload) {
				current++
			}
		}

		if current+10 >= len(dnsPayload) {
			break
		}

		// Extract record type (2 bytes)
		recordType := binary.BigEndian.Uint16(dnsPayload[current : current+2])
		current += 8 // Skip type (2), class (2), TTL (4)

		// Get data length (2 bytes)
		dataLen := binary.BigEndian.Uint16(dnsPayload[current : current+2])
		current += 2

		if current+int(dataLen) > len(dnsPayload) {
			break
		}

		// Handle A records (type 1) - IPv4 addresses
		if recordType == 1 && dataLen == 4 {
			ip := net.IP(dnsPayload[current : current+4])
			ipAddresses = append(ipAddresses, ip)
		} else if recordType == 28 { // AAAA records (IPv6, type 28)
			if dataLen == 16 {
				ip := net.IP(dnsPayload[current : current+16])
				ipAddresses = append(ipAddresses, ip)
			}
		}

		current += int(dataLen)
	}

	return queryName, ipAddresses, true
}

// parseDomainName parses a DNS domain name from raw bytes
func parseDomainName(data []byte, offset, maxOffset int) string {
	if offset >= len(data) {
		return ""
	}

	var labels []string
	current := offset

	for {
		if current >= len(data) {
			break
		}

		labelLen := int(data[current])
		if labelLen == 0 {
			// End of name
			break
		} else if labelLen&0xC0 == 0xC0 {
			// Compressed pointer - not handling this in simple parser
			break
		} else if current+1+labelLen > len(data) {
			// Would read past end of data
			break
		}

		labels = append(labels, string(data[current+1:current+1+labelLen]))
		current += 1 + labelLen

		// Prevent infinite loops
		if current > maxOffset {
			break
		}
	}

	return strings.Join(labels, ".")
}
