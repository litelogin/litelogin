package cli

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// parentDelegation finds the zone above domain and asks each of its name
// servers which name servers it delegates domain to.
func parentDelegation(ctx context.Context, domain string) (string, []parentAnswer, error) {
	parent, servers, err := parentZone(ctx, domain)
	if err != nil {
		return "", nil, err
	}
	answers := make([]parentAnswer, len(servers))
	for i, server := range servers {
		ns, err := queryNS(ctx, server, domain)
		answers[i] = parentAnswer{Server: server, NS: ns, Err: err}
	}
	return parent, answers, nil
}

// parentZone is the nearest zone above domain that has name servers, and
// them, sorted. Looking the parent's own NS records up through a resolver is
// fine: they're not what's being checked.
func parentZone(ctx context.Context, domain string) (string, []string, error) {
	name := strings.TrimSuffix(domain, ".")
	for {
		dot := strings.IndexByte(name, '.')
		if dot < 0 {
			return "", nil, fmt.Errorf("no parent zone of %s has name servers", domain)
		}
		name = name[dot+1:]
		if !strings.Contains(name, ".") {
			return "", nil, fmt.Errorf("no parent zone of %s has name servers", domain)
		}
		records, err := net.DefaultResolver.LookupNS(ctx, name)
		if err != nil || len(records) == 0 {
			continue
		}
		hosts := make([]string, len(records))
		for i, r := range records {
			hosts[i] = r.Host
		}
		ns := normalizeNS(hosts)
		slices.Sort(ns)
		return name, ns, nil
	}
}

// queryNS sends one NS query for domain to server, without recursion, and
// returns the NS records for domain in its answer (if the server serves
// domain itself) or authority (a referral, which is what a delegation
// looks like) section. None means the server doesn't delegate domain.
func queryNS(ctx context.Context, server, domain string) ([]string, error) {
	name, err := dnsmessage.NewName(strings.TrimSuffix(domain, ".") + ".")
	if err != nil {
		return nil, err
	}
	// A random ID, so a spoofed answer is harder to make match.
	var idBytes [2]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return nil, err
	}
	id := binary.BigEndian.Uint16(idBytes[:])
	query, err := (&dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id},
		Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeNS, Class: dnsmessage.ClassINET}},
	}).Pack()
	if err != nil {
		return nil, err
	}

	var resp dnsmessage.Message
	var lastErr error
	for _, network := range []string{"udp4", "udp6"} {
		resp, lastErr = exchange(ctx, network, server, id, query)
		if lastErr == nil {
			break
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	switch resp.RCode {
	case dnsmessage.RCodeSuccess:
	case dnsmessage.RCodeNameError:
		return nil, nil
	default:
		return nil, fmt.Errorf("%s answered %s", server, resp.RCode)
	}
	if resp.Truncated {
		return nil, fmt.Errorf("%s's answer was truncated", server)
	}
	var ns []string
	for _, rr := range append(resp.Answers, resp.Authorities...) {
		if rr.Header.Type != dnsmessage.TypeNS || !strings.EqualFold(rr.Header.Name.String(), name.String()) {
			continue
		}
		if body, ok := rr.Body.(*dnsmessage.NSResource); ok {
			ns = append(ns, body.NS.String())
		}
	}
	ns = normalizeNS(ns)
	slices.Sort(ns)
	return slices.Compact(ns), nil
}

func exchange(ctx context.Context, network, server string, id uint16, query []byte) (dnsmessage.Message, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, network, net.JoinHostPort(server, dnsPort))
	if err != nil {
		return dnsmessage.Message{}, err
	}
	defer func() { _ = conn.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if _, err := conn.Write(query); err != nil {
		return dnsmessage.Message{}, err
	}
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return dnsmessage.Message{}, err
		}
		var resp dnsmessage.Message
		if err := resp.Unpack(buf[:n]); err != nil {
			continue // not a DNS message; keep waiting for ours
		}
		if resp.ID == id && resp.Response {
			return resp, nil
		}
	}
}

// dnsPort is where queryNS asks; tests change it.
var dnsPort = "53"

// normalizeNS lowercases name server names and drops the trailing dot.
func normalizeNS(names []string) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = strings.TrimSuffix(strings.ToLower(n), ".")
	}
	return out
}
