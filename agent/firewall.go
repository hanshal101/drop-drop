package main

import (
	"fmt"
	"os/exec"
	"strings"
)

// FirewallMode represents the different modes of operation for the firewall.
type FirewallMode string

const (
	FirewallModeAudit FirewallMode = "audit"
	FirewallModeBlock FirewallMode = "block"
	FirewallModeBlockWithDNS FirewallMode = "block-with-dns"
)

// ApplyFirewallRules applies the firewall rules for the given mode.
func ApplyFirewallRules(mode FirewallMode) error {
	var ruleset string
	switch mode {
	case FirewallModeAudit:
		ruleset = auditRules
	case FirewallModeBlock:
		ruleset = blockRules
	case FirewallModeBlockWithDNS:
		ruleset = blockWithDNSRules
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

// ClearFirewallRules clears all firewall rules.
func ClearFirewallRules() error {
	cmd := exec.Command("nft", "flush", "ruleset")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to flush nftables rules: %w", err)
	}
	return nil
}

const auditRules = `
table inet roc_drop {
	chain output {
		type filter hook output priority 0; policy accept;
		queue num 0
	}
}
`

const blockRules = `
table inet roc_drop {
	chain output {
		type filter hook output priority 0; policy drop;
	}
}
`

const blockWithDNSRules = `
table inet roc_drop {
	chain output {
		type filter hook output priority 0; policy drop;
		udp dport 53 accept
		tcp dport 53 accept
	}
}
`
