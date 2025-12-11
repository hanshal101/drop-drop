package main

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

type FirewallMode string

const (
	FirewallModeAudit        FirewallMode = "audit"
	FirewallModeBlock        FirewallMode = "block"
	FirewallModeBlockWithDNS FirewallMode = "block-with-dns"
)

var (
	IPAllowedList     []net.IP
	DomainAllowedList []string
	DNSSetting        string
)

func ApplyFirewallRules(mode FirewallMode) error {
	var ruleset string
	switch mode {
	case FirewallModeAudit:
		ruleset = createAuditRules()
	case FirewallModeBlock:
		ruleset = createBlockRules()
	case FirewallModeBlockWithDNS:
		ruleset = createBlockWithDNSRules()
	default:
		return fmt.Errorf("unknown firewall mode: %s", mode)
	}

	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(ruleset)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to apply nftables rules: %w", err)
	}
	return nil
}

func ClearFirewallRules() error {
	cmd := exec.Command("nft", "flush", "ruleset")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to flush nftables rules: %w", err)
	}
	return nil
}

func createAuditRules() string {
	baseRules := `table inet roc_drop {
	chain output {
		type filter hook output priority 0; policy accept;
		queue num 0
	}
}`
	return baseRules
}

func createBlockRules() string {
	var allowedIPRules string
	for _, ip := range IPAllowedList {
		ipStr := ip.String()
		allowedIPRules += fmt.Sprintf("\tip daddr %s accept\n", ipStr)
		allowedIPRules += fmt.Sprintf("\tip saddr %s accept\n", ipStr)
	}

	baseRules := fmt.Sprintf(`table inet roc_drop {
	chain output {
		type filter hook output priority 0; policy drop;
		%s
	}
}`, allowedIPRules)
	return baseRules
}

func createBlockWithDNSRules() string {
	var allowedIPRules string
	for _, ip := range IPAllowedList {
		ipStr := ip.String()
		allowedIPRules += fmt.Sprintf("\tip daddr %s accept\n", ipStr)
		allowedIPRules += fmt.Sprintf("\tip saddr %s accept\n", ipStr)
	}

	baseRules := fmt.Sprintf(`table inet roc_drop {
	chain output {
		type filter hook output priority 0; policy drop;
		udp dport 53 accept
		tcp dport 53 accept
		%s
	}
}`, allowedIPRules)
	return baseRules
}
