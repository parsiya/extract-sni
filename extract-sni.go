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
	// fmt.Printf("%#v", cliArgs)

	// Read the pcap file.

	servers, err := svr.ReadPCAP(cliArgs.PCAP)
	if err != nil {
		// An error here is unrecoverable.
		log.Fatal(err)
	}

	log.Println("Finished reading pcap file: ", cliArgs.PCAP)

	// Populate the servers.
	servers.PopulateServers(cliArgs.DNS.String())

	log.Printf("Finished populating %d servers.\n", len(servers))

	// Check the output and print.
	switch cliArgs.Output.String() {

	case "hosts":
		fmt.Printf("# %s file for %s\n\n", cliArgs.Output.String(), cliArgs.PCAP)
		fmt.Println(servers.Hosts())
	case "burp":
		fmt.Printf("// %s file for %s", cliArgs.Output.String(), cliArgs.PCAP)
		fmt.Println(servers.Burp())
	}
}
