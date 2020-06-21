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
	SNI string
	// port is the destination port. Typically 443.
	Port int
	// An array of IP addresses for the server.
	IPs []string
}

// String is the stringer for the server.
func (s DestinationServer) String() string {
	return fmt.Sprintf("%s:%d", s.SNI, s.Port)
}

// Lookup does a DNS lookup on the server and populates the IPs field.
func (s *DestinationServer) Lookup(server string) error {

	// Based on
	// https://github.com/bogdanovich/dns_resolver/blob/a8e42bc6a5b6c9a93be01ca204be7e17f7ba4cd2/dns_resolver.go#L51
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(s.SNI), dns.TypeA)
	msg.RecursionDesired = true

	ans, err := dns.Exchange(msg, server)
	if err != nil {
		return err
	}

	if ans != nil && ans.Rcode != dns.RcodeSuccess {
		return errors.New(dns.RcodeToString[ans.Rcode])
	}

	var ipStrings []string

	for _, record := range ans.Answer {
		if t, ok := record.(*dns.A); ok {
			ipStrings = append(ipStrings, t.A.String())
		}
	}

	s.IPs = ipStrings
	return nil
}

// HostsString is the representation of the svr. It can be pasted into the hosts
// file to redirect the endpoint to redirectIP. It does no format validation on
// redirectIP.
func (s DestinationServer) HostsString(redirectIP string) (string, error) {
	if len(s.IPs) == 0 {
		return "", fmt.Errorf("The IPs field is not populated.")
	}
	// Convert s.IPs to a comma separated string.
	strIPs := strings.Join(s.IPs, ", ")
	return fmt.Sprintf("%s %s # %s:%d", redirectIP, s.SNI, strIPs, s.Port), nil
}
