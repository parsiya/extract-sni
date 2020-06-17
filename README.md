# extract-sni
Extracts SNIs from a pcap and generates output usable in `etc/hosts` file and
Burp config for proxying thick clients.

## Quickstart

1. `go get github.com/parsiya/extract-sni`
2. Capture traffic for an application and store it in a pcap file.
3. `go run extract-sni.go whatever.pcap > whatever.txt`
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

## npcap
On Windows, you need to install [npcap](https://nmap.org/npcap/#download) for
the pcap library to work. Be sure to check
`Install Npcap in WinPcap API-compatible Mode`
(which I think is enabled by default).

I have not tested this on other operating systems. The overwhelming majority of
my work (videogames) happen on Windows.

## Parameters
The only required parameter is the pcap file. `extract-sni traffic.pcap`. The
output be printed to stdout (you can pipe it into a file). The default DNS is
`8.8.8.8:53` and the default redirect IP is `127.0.0.1`.

When specifying the DNS address with `-d/-dns` there is no need to specify a
port. The default port `53` will be used. E.g.,
`extract-sni -d 1.1.1.1 traffic.pcap`.

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
Extracts SNIs from a pcap and generates output usable in etc/hosts file and a Burp config that can be used for proxying thick clients.
Version 0.2.0
Usage: extract-sni.exe [--dns address/ip:port] [--output both] [--redirectip 127.0.0.1] traffic.pcap

Positional arguments:
  traffic.pcap           pcap file to parse

Options:
  --dns address/ip:port, -d address/ip:port
                         DNS server as Address/IP:Port [default: 8.8.8.8:53]
  --output both, -o both
                         output format [default: both]
  --redirectip 127.0.0.1, -r 127.0.0.1
                         IP address to redirect the hosts to [default: 127.0.0.1]
  --help, -h             display this help and exit
  --version              display version and exit
```

## Questions

1. Why doesn't it capture pcaps, too?
    1. It's a small tool that does one thing. I do not like feature creep.
    2. A pcap file from the traffic on one interface will have lots of noise.
    3. Things might have changed but last I checked, the `gopacket` package was
       OS specific and I do not want to deal with that headache.

## Troubleshooting

### My Output File is Noisy
It's because your pcap is noisy. Try to filter as much unrelated traffic as you
can. I use the techniques described in `Network Traffic Attribution on Windows`:

* https://parsiya.net/blog/2015-08-01-network-traffic-attribution-on-windows/

I usually use [Microsoft Network Monitor][netmon] or Netmon. With Netmon you can
filter traffic by process. However, this adds an extra step. Netmon's cap file
must be converted to pcap using Wireshark (or other tools). Keep in mind that
sometimes Wireshark cannot [convert cap files to pcap][cap-to-pcap].

[netmon]: https://www.microsoft.com/en-ca/download/details.aspx?id=4865
[cap-to-pcap]: https://parsiya.net/cheatsheet/#open-a-network-monitor-cap-file-in-wireshark-and-save-is-disabled

### Error `Couldn't load wpcap.dll`
This happens if [npcap](https://nmap.org/npcap/#download) is not installed. See
the [npcap](#npcap) section above for more info.
