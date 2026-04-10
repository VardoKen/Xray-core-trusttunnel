package trusttunnel

import (
	"bytes"
	"encoding/hex"
	"fmt"
	stdnet "net"
	"strings"
)

func isTrustTunnelAllowed(rules []*Rule, remoteAddr string, clientRandom string) (bool, string) {
	if len(rules) == 0 {
		return true, ""
	}

	sourceIP := extractTrustTunnelSourceIP(remoteAddr)
	actualRandom := normalizeTrustTunnelHex(clientRandom)

	for idx, rule := range rules {
		matched, detail := matchTrustTunnelRule(rule, sourceIP, actualRandom)
		if !matched {
			continue
		}

		action := "deny"
		if rule.GetAllow() {
			action = "allow"
		}

		return rule.GetAllow(), fmt.Sprintf("trusttunnel rules: matched rule[%d] action=%s%s", idx, action, detail)
	}

	return true, "trusttunnel rules: no rules matched; allowed by default"
}

func matchTrustTunnelRule(rule *Rule, sourceIP stdnet.IP, clientRandom string) (bool, string) {
	if rule == nil {
		return false, ""
	}

	var details []string

	if cidr := strings.TrimSpace(rule.GetCidr()); cidr != "" {
		_, network, err := stdnet.ParseCIDR(cidr)
		if err != nil || sourceIP == nil || !network.Contains(sourceIP) {
			return false, ""
		}
		details = append(details, " cidr="+cidr)
	}

	if spec := strings.TrimSpace(rule.GetClientRandom()); spec != "" {
		ok, err := matchTrustTunnelClientRandom(clientRandom, spec)
		if err != nil || !ok {
			return false, ""
		}
		details = append(details, " clientRandom="+strings.ToLower(spec))
	}

	if len(details) == 0 {
		return true, " catch-all"
	}

	return true, strings.Join(details, "")
}

func matchTrustTunnelClientRandom(actual string, spec string) (bool, error) {
	actualHex := normalizeTrustTunnelHex(actual)
	if actualHex == "" {
		return false, nil
	}

	actualBytes, err := hex.DecodeString(actualHex)
	if err != nil {
		return false, err
	}

	spec = strings.TrimSpace(strings.ToLower(spec))
	parts := strings.SplitN(spec, "/", 2)

	prefixHex := normalizeTrustTunnelHex(parts[0])
	if prefixHex == "" {
		return false, nil
	}

	prefixBytes, err := hex.DecodeString(prefixHex)
	if err != nil {
		return false, err
	}

	if len(actualBytes) < len(prefixBytes) {
		return false, nil
	}

	if len(parts) == 1 {
		return bytes.Equal(actualBytes[:len(prefixBytes)], prefixBytes), nil
	}

	maskHex := normalizeTrustTunnelHex(parts[1])
	maskBytes, err := hex.DecodeString(maskHex)
	if err != nil {
		return false, err
	}

	if len(maskBytes) != len(prefixBytes) {
		return false, fmt.Errorf("client_random mask length mismatch")
	}

	for i := range prefixBytes {
		if (actualBytes[i] & maskBytes[i]) != (prefixBytes[i] & maskBytes[i]) {
			return false, nil
		}
	}

	return true, nil
}

func extractTrustTunnelSourceIP(remoteAddr string) stdnet.IP {
	if remoteAddr == "" {
		return nil
	}

	host, _, err := stdnet.SplitHostPort(remoteAddr)
	if err == nil {
		return stdnet.ParseIP(host)
	}

	return stdnet.ParseIP(remoteAddr)
}

func normalizeTrustTunnelHex(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "\t", "")
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	return s
}
