package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os/signal"
	"syscall"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/simonmittag/procspy"
)

func main() {
	firewallMode := flag.String("firewall-mode", "audit", "The firewall mode to apply. One of: audit, block, block-with-dns")
	tetragonAddress := flag.String("tetragon-address", "localhost:54321", "The address of the Tetragon gRPC server.")
	nfqueueNum := flag.Int("nfqueue-num", 0, "The nfqueue number to listen on.")
	flag.Parse()

	fmt.Printf("Applying firewall mode: %s\n", *firewallMode)

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

	packetCallback := func(packet gopacket.Packet) {
		var srcPort uint16
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			srcPort = uint16(tcp.SrcPort)
		} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			srcPort = uint16(udp.SrcPort)
		}

		if srcPort != 0 {
			cs, err := procspy.Connections(true)
			if err != nil {
				log.Printf("could not get connections: %v", err)
				return
			}
			for c := cs.Next(); c != nil; c = cs.Next() {
				if c.LocalPort == srcPort {
					if process, ok := processCache.Get(uint32(c.PID)); ok {
						fmt.Printf("Packet from %s (%d): %s\n", process.Binary, c.PID, packet.String())
					}
					break
				}
			}
		}
	}

	if err := nfq.Register(ctx, packetCallback); err != nil {
		log.Fatalf("Failed to register nfqueue callback: %v", err)
	}

	<-ctx.Done()
}
