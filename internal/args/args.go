package args

import "fmt"

const appName = "extract-sni"
const version = "0.1.0"
const description = "Extracts SNIs from a pcap and generates output usable in etc/hosts file and a Burp config for thick client proxying."

// Args represents the application's arguments.
type Args struct {
	PCAP   string      `arg:"positional,required" help:"pcap file to parse" placeholder:"traffic.pcap"`
	DNS    DNSParam    `arg:"-d" help:"DNS server as Address/IP:Port" placeholder:"address/ip:port"`
	Output OutputParam `arg:"-o" default:"both" help:"output format"`
}

// Version returns the application's version.
func (Args) Version() string {
	return fmt.Sprintf("Version %s", version)
}

// Description returns the application's description.
func (Args) Description() string {
	return fmt.Sprintf("%s", description)
}
