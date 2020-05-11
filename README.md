# extract-sni
Extracts SNIs from a pcap and generates output usable in `etc/hosts` file and
Burp config for proxying thick clients.

## Quickstart

1. `go get github.com/parsiya/extract-sni`
2. Capture traffic for an application and store it in a pcap file.
3. `go run extract-sni.go whatever.pcap -o both > whatever.txt`
4. Paste the section for the `hosts` file into `etc/hosts`. This will redirect
   all endpoints to localhost.
5. Paste the Burp section into a Burp config file and load it into Burp.
6. ???
7. Profit

## Why?
Identifying endpoints, redirecting them to Burp and telling Burp's invisible
proxying where to send these endpoints is a manual process. This script
automates some of it for me.

Please see this blog post for this technique:

* https://parsiya.net/blog/2020-05-09-thick-client-proxing-part-10-the-hosts-file/

## Parameters

### pcap file
Pass the pcap file that should be parsed as a positional parameter. This is the
only required parameter.

* `go run extract-sni.go whatever.pcap`

### DNS
Optional DNS to use to resolve these domains. If this parameter is not provided
then the application uses the destination IP address from the pcap file.

Pass with `-d` or `--dns`. The value can be a complete `server:port` like
`dns.google:53`. Or `IP:port` like `8.8.8.8:53`. Port is optional and will
default to `53` if not passed so `8.8.8.8` and `dns.google` are both valid
values.

The application does some validation checks here but it's mostly the
responsibility of the user to pass a valid and reachable DNS server.

### Output
The output format for the results. Default is `hosts`. Pass with `-o` or
`--output`. The application currently supports two output formats `hosts`
(default) and `burp`. `both` creates both formats in one file.

The output is sent to standard output. Logs and error messages are sent to
`os.Stderr` so they do not interfere with the output. You can (and probably
should) pipe the output of the app to a text file.

* `go run extract-sni.go whatever.pcap > whatever-hosts.txt`

#### hosts
Creates the entries to redirect these domains to localhost by adding them to the
`hosts` file. The values look like the following:

`127.0.0.1 example.net # 93.184.216.34 - 443`

Note the extra info such as the resolved IP address and the destination port in
the comments in each line. These can come in handy to quickly lookup where each
domain is.

#### Burp
Creates the entries to be added to a Burp project configuration file. These
entries should be added to the
`project_options > connections > hostname_resolution` array in the Burp's config
file.

```json
"project_options":{
    "connections":{
        "hostname_resolution":[
            // paste here
            {
                "enabled":true,
                "hostname":"example.net",
                "ip_address":"93.184.216.34"
            },
            // more
        ],
    }
}
```

For more information please see:

* https://portswigger.net/burp/documentation/desktop/options/connections#hostname-resolution

## Usage

```
$ go run extract-sni.go -h
Extracts SNIs from a pcap and generates output usable in etc/hosts file and a Burp config for thick client proxying.
Version 0.1.0
Usage: extract-sni.exe [--dns address/ip:port] [--output OUTPUT] traffic.pcap

Positional arguments:
  traffic.pcap           pcap file to parse

Options:
  --dns address/ip:port, -d address/ip:port
                         DNS server as Address/IP:Port
  --output OUTPUT, -o OUTPUT
                         output format [default: both]
  --help, -h             display this help and exit
  --version              display version and exit
```

## Questions

1. Why doesn't it capture pcaps, too?
    1. It's a small tool that does one thing. I do not like feature creep.
    2. A pcap file from the traffic on one interface will have lots of noise.
    3. Things might have changed but last I checked, the `gopacket` package was
       OS specific and I do not want to deal with that headache.

