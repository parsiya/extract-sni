package svr

import (
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// DestinationServer represents a target server for the application.
type DestinationServer struct {
	// sni is the exact text from the SNI extension in ClientHello.
	sni string
	// port is the destination port. Typically 443.
	port int
	// A comma separated string of IP addresses for the server.
	ips string
}

// String is the stringer for the server.
func (s DestinationServer) String() string {
	return fmt.Sprintf("%s:%d", s.sni, s.port)
}

// Lookup does a DNS lookup on the server and returns its IP address(es).
func (s DestinationServer) Lookup(server string) (string, error) {

	// Based on
	// https://github.com/bogdanovich/dns_resolver/blob/a8e42bc6a5b6c9a93be01ca204be7e17f7ba4cd2/dns_resolver.go#L51
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(s.sni), dns.TypeA)
	msg.RecursionDesired = true

	ans, err := dns.Exchange(msg, server)
	if err != nil {
		return "", err
	}

	if ans != nil && ans.Rcode != dns.RcodeSuccess {
		return "", errors.New(dns.RcodeToString[ans.Rcode])
	}

	var ipStrings []string

	for _, record := range ans.Answer {
		if t, ok := record.(*dns.A); ok {
			ipStrings = append(ipStrings, t.A.String())
		}
	}

	return strings.Join(ipStrings, ", "), nil
}

// Populate does a DNS lookup on each svr and populates the ips field.
func (s *DestinationServer) Populate(server string) (err error) {
	s.ips, err = s.Lookup(server)
	return err
}

// HostsString is the represenation of the svr. It can be pasted into the hosts
// file to redirect the endpoint to the redirectIP. It does not check if
// redirectIP is in the correct format.
func (s DestinationServer) HostsString(redirectIP string) (string, error) {
	if s.ips == "" {
		return "", fmt.Errorf("ips is not populated")
	}
	return fmt.Sprintf("%s %s # %s - %d", redirectIP, s.sni, s.ips, s.port), nil

}

// LocalHostsString calls HostsString with "127.0.0.1."
func (s DestinationServer) LocalHostsString() (string, error) {
	return s.HostsString("127.0.0.1")
}
