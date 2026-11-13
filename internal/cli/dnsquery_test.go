package cli

import (
	"context"
	"net"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// fakeParent is a name server on 127.0.0.1 that answers NS queries the way a
// parent zone does: a referral in the authority section for names it
// delegates, NXDOMAIN for others.
func fakeParent(t *testing.T, delegations map[string][]string) {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_, port, _ := net.SplitHostPort(conn.LocalAddr().String())
	old := dnsPort
	dnsPort = port
	t.Cleanup(func() { dnsPort = old })

	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			var q dnsmessage.Message
			if q.Unpack(buf[:n]) != nil || len(q.Questions) != 1 {
				continue
			}
			question := q.Questions[0]
			resp := dnsmessage.Message{
				Header:    dnsmessage.Header{ID: q.ID, Response: true, Authoritative: false},
				Questions: q.Questions,
			}
			if q.RecursionDesired {
				resp.RCode = dnsmessage.RCodeRefused // the check must not ask for recursion
			} else if servers, ok := delegations[strings.ToLower(question.Name.String())]; ok {
				for _, s := range servers {
					resp.Authorities = append(resp.Authorities, dnsmessage.Resource{
						Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeNS, Class: dnsmessage.ClassINET, TTL: 300},
						Body:   &dnsmessage.NSResource{NS: dnsmessage.MustNewName(s)},
					})
				}
			} else {
				resp.RCode = dnsmessage.RCodeNameError
			}
			out, err := resp.Pack()
			if err == nil {
				_, _ = conn.WriteTo(out, addr)
			}
		}
	}()
}

func TestQueryNSReadsTheReferral(t *testing.T) {
	fakeParent(t, map[string][]string{
		"login.example.com.": {"NS-2.awsdns-02.net.", "ns-1.awsdns-01.org."},
	})
	ns, err := queryNS(context.Background(), "127.0.0.1", "login.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(ns, ",") != "ns-1.awsdns-01.org,ns-2.awsdns-02.net" {
		t.Errorf("NS = %v", ns)
	}

	ns, err = queryNS(context.Background(), "127.0.0.1", "other.example.com")
	if err != nil || len(ns) != 0 {
		t.Errorf("undelegated name: NS = %v, err = %v; want none", ns, err)
	}
}
