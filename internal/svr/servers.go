package svr

import (
	"fmt"
	"log"
	"strings"

	"github.com/bradleyfalzon/tlsx"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Servers is an alias for map[string]DestinationServer
type Servers map[string]DestinationServer

// ReadPCAP reads a pcap file and returns a map of unpopulated servers. If useIP
// is false then we are going to use the IP addresses from the pcap and skip DNS
// lookups later.
func ReadPCAP(pcapFile string, useIP bool) (Servers, error) {

	// Open the pcap file.
	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	err = handle.SetBPFFilter("tcp")
	if err != nil {
		return nil, err
	}

	// Placeholder for the return value.
	servers := make(Servers)

	// layers.LayerTypeTCP
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	// Parse all packets.
	for packet := range packetSource.Packets() {

		// Based on
		// https://github.com/bradleyfalzon/tlsx/blob/master/example/main.go

		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {

			tcp, ok := tcpLayer.(*layers.TCP)
			if !ok {
				log.Println("Could not decode the TCP layer for packet with timestamp", packet.Metadata().Timestamp)
				continue
			}

			payload := tcp.LayerPayload()

			if len(payload) > 2 {

				// Check if the payload starts with `16 03`.
				if !((payload[0] == 0x16) && (payload[1] == 0x03)) {
					// If it's not a ClientHello, parse the next packet.
					continue
				}

				var hello = tlsx.ClientHello{}
				err := hello.Unmarshall(payload)

				switch err {
				case nil:

					s := DestinationServer{
						sni:  hello.SNI,
						port: int(tcp.DstPort),
					}

					// Check if the key already exists in the servers.
					if _, ok := servers[s.String()]; ok {
						// Key exists, continue.
						continue
					}

					if useIP {
						// Get the IP layer and the destination IP address.
						if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
							if ip, ok := ipLayer.(*layers.IPv4); ok {
								s.IPs = ip.DstIP.String()
							}
						}
						// If this doesn't work the IP address stays empty.
					}

					// Add the new server to the servers map.
					servers[s.String()] = s

				case tlsx.ErrHandshakeWrongType:
					continue
				default:
					log.Println("Error reading Client Hello:", err)
					log.Println("Raw Client Hello:", tcp.LayerPayload())
					continue
				}
			}
		}
	}

	return servers, nil
}

// PopulateServers calls Populate on a map of servers.
func (servers Servers) PopulateServers(dns string) {

	// Parallelization here will not save much time. If this turns out to be a
	// huge bottleneck, we can return here and add it.

	// Range over the servers.
	for key, s := range servers {

		// Populate each server.
		if err := s.Lookup(dns); err != nil {
			// If there was an error print it and continue.
			log.Println(err)
			continue
		}
		// We cannot modify map values so we overwrite the old svr with the new
		// one.
		servers[key] = s
	}
}

// Hosts creates the hosts file output for servers. Be sure to call
// PopulateServers() first if you have passed a DNS server to the app.
func (servers Servers) Hosts() string {

	var sb strings.Builder
	for _, s := range servers {
		hostStr, err := s.LocalHostsString()
		if err != nil {
			// The only time LocalHostsString() returns an error is if the IPs
			// field is nil.
			log.Println(err)
			continue
		}

		sb.WriteString(hostStr)
		sb.WriteString("\n")
	}
	return sb.String()
}

// Burp creates the "hostname_resolution" json array that can be pasted in Burp
// config.
func (servers Servers) Burp() string {

	jString := `
{
    "enabled": true,
    "hostname": "%s",
    "ip_address": "%s"
}`

	// {
	// 	"enabled":true,
	// 	"hostname":"example.net",
	// 	"ip_address":"93.184.216.34"
	// }

	var ipStrings []string

	for _, s := range servers {

		tmpString := fmt.Sprintf(jString, s.sni, strings.Split(s.IPs, ",")[0])
		ipStrings = append(ipStrings, tmpString)
	}

	// Join everything together and spit it out.
	return strings.Join(ipStrings, ", ")
}
