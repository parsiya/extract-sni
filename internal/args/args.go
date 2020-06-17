package args

import "fmt"

const appName = "extract-sni"
const version = "0.2.0"
const description = "Extracts SNIs from a pcap and generates output usable in " +
	"etc/hosts file and a Burp config that can be used for proxying thick clients."

// Args represents the application's arguments.
type Args struct {
	PCAP       string      `arg:"positional,required" help:"pcap file to parse" placeholder:"traffic.pcap"`
	DNS        DNSParam    `arg:"-d" default:"8.8.8.8:53" help:"DNS server as Address/IP:Port" placeholder:"address/ip:port"`
	Output     OutputParam `arg:"-o" default:"both" help:"output format" placeholder:"both"`
	RedirectIP string      `arg:"-r" default:"127.0.0.1" help:"IP address to redirect the hosts to" placeholder:"127.0.0.1"`
}

// Version returns the application's version.
func (Args) Version() string {
	return fmt.Sprintf("Version %s", version)
}

// Description returns the application's description.
func (Args) Description() string {
	return fmt.Sprintf("%s", description)
}
