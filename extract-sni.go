package main

import (
	"log"
	"path/filepath"

	"github.com/parsiya/extract-sni/internal/args"
	"github.com/parsiya/extract-sni/internal/report"
	"github.com/parsiya/extract-sni/internal/svr"
	"github.com/parsiya/go-helpers/filehelper"

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

	// Create the report.

	// First create the hosts string.
	hosts := servers.Hosts(cliArgs.RedirectIP)

	// Create the report and config file names.
	var reportFilename, configFilename string

	if len(cliArgs.Output) != 0 {
		// If the output param is provided, remove its extension and add html to it.
		reportFilename = filehelper.AddExtension(cliArgs.Output, "html")
		// Config file name is the same as the report with the `json` extension.
		configFilename = filehelper.AddExtension(reportFilename, "json")
	} else {
		// If no output is provided, use the name of the pcap file.
		reportFilename = filehelper.AddExtension(cliArgs.PCAP, "html")
		configFilename = filehelper.AddExtension(reportFilename, "json")
	}

	info := report.Info{
		PcapFileName:   cliArgs.PCAP,
		Hosts:          hosts,
		ConfigFileName: filepath.Base(configFilename), // This makes the file clickable in the PDF.
	}

	// Generate the report.
	rpt, err := info.Generate()
	if err != nil {
		panic(err)
	}

	// Create the Burp config.
	cfg, err := servers.Burp(cliArgs.RedirectIP)
	if err != nil {
		panic(err)
	}

	// Write the report to file. if cliArgs.Output is empty or there is an error
	// we print to stdout.
	if err := filehelper.WriteFileString(rpt, reportFilename, true); err != nil {
		log.Printf("Error writing the report to %s: %s.\n", reportFilename, err)
		// log.Println("Printing the report to stdout.")
		// fmt.Println(rpt)
		// log.Println("Printing the Burp config to stdout.")
		// fmt.Println(cfg)
		return
	}
	log.Printf("Report written to %s.\n", reportFilename)
	// Write the Burp config to file.
	if err := filehelper.WriteFileString(cfg, configFilename, true); err != nil {
		log.Printf("Error writing the config file to %s: %s.\n", configFilename, err)
		// log.Println("Printing the Burp config to stdout.")
		// fmt.Println(cfg)
		return
	}
	log.Printf("Config file written to %s.\n", configFilename)
	log.Printf("Done.")
}
