package main

import (
	"fmt"
	"log"

	"github.com/parsiya/extract-sni/internal/args"
	"github.com/parsiya/extract-sni/internal/svr"

	"github.com/alexflint/go-arg"
)

func main() {

	// Parse arguments.
	var cliArgs args.Args
	arg.MustParse(&cliArgs)
	log.Printf("%#v\n", cliArgs)

	// If dns is not provided then it's empty and we need to use the IP address
	// from the pcap file.
	useIP := false
	if len(cliArgs.DNS.Host) == 0 {
		useIP = true
		log.Println("useIP is set to true, getting server IPs from the pcap file.")
	}

	// Read the pcap file.
	servers, err := svr.ReadPCAP(cliArgs.PCAP, useIP)
	if err != nil {
		// An error here means there was an error accessing the file so it's
		// unrecoverable and we must terminate to troubleshoot.
		log.Fatal(err)
	}

	log.Printf("Extracted %d servers from the pcap file at %s.\n", len(servers), cliArgs.PCAP)

	// Populate the servers if useIP == false.
	if !useIP {
		log.Printf("Performing DNS lookups using %s.\n", cliArgs.DNS.String())
		servers.PopulateServers(cliArgs.DNS.String())
		log.Printf("Finished populating %d servers.\n", len(servers))
	}

	fmt.Println("Printing the output to stdout.")
	// Check the output format and print to stdout.
	switch cliArgs.Output.String() {

	// TODO: This can be better, we can reuse functions.

	case "hosts":
		fmt.Printf("# hosts file for %s\n\n", cliArgs.PCAP)
		fmt.Println(servers.Hosts(cliArgs.RedirectIP))
	case "burp":
		fmt.Printf("// Burp file for %s", cliArgs.PCAP)
		fmt.Println(servers.Burp())
	case "both":
		fmt.Printf("# hosts file for %s\n\n", cliArgs.PCAP)
		fmt.Println(servers.Hosts(cliArgs.RedirectIP))
		fmt.Printf("\n\n\n")
		fmt.Printf("// Burp file for %s", cliArgs.PCAP)
		fmt.Println(servers.Burp())
	}
}
