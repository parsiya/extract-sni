# extract-sni
Extracts SNIs from a pcap and generates output usable in `etc/hosts` file and
Burp config for proxying thick clients.

## Quickstart

1. `go get github.com/parsiya/extract-sni`
2. Capture traffic for an application and store it in a pcap file.
3. `go run extract-sni.go whatever.pcap -output report`
4. Open `report.html` to view the instructions.
    1. Some data need to be copied into `etc/hosts` to redirect traffic.
5. Import `report.json` in Burp to setup proxy listeners 
6. ???
7. Profit

![report screenshot](.github/screenshot.png)

See a report sample:

* [Report](report-sample/file.html)
* [Burp config](report-sample/file.json)

## Why?
Identifying endpoints, redirecting them to Burp and telling Burp's invisible
proxying where to send these endpoints is a manual process. This script
automates most of it for me.

Please see this blog post for this technique ats:

* https://parsiya.net/blog/2020-05-09-thick-client-proxing-part-10-the-hosts-file/

## npcap
On Windows, you need to install [npcap](https://nmap.org/npcap/#download) for
the Golang's pcap library to work. Be sure to check
`Install Npcap in WinPcap API-compatible Mode` in the installer
(it's enabled by default).

## Parameters
The only required parameter is the pcap file. `extract-sni traffic.pcap`. In the
absence of the `output` parameter, the report will be `traffic.html` and the
Burp config file will be stored in `traffic.json` in the same path as the pcap
file.

When specifying the DNS address with `-d/-dns` there is no need to specify a
port, the default port `53` will be used. E.g.,
`extract-sni -d 1.1.1.1 traffic.pcap` will use `1.1.1.1:53`.

### pcap file
Pass the pcap file that should be parsed as a positional parameter. This is the
only required parameter.

* `extract-sni.go whatever.pcap`

### DNS -d/-dns
Optional DNS to use for domain lookup. If this parameter is not provided then
the the application uses the destination IP address from the pcap file for each
domain.

If provided, the DNS server will be used to do lookups. The value can be a
complete `server:port` like `dns.google:53`, or `IP:port` like `8.8.8.8:53`.
Port is optional and will default to `53`. Both `8.8.8.8` and
`dns.google` are both valid values.

The application does some validation checks here but it's mostly the
responsibility of the user to pass a valid and reachable DNS server.

### Redirect IP -r/-redirectip
Use the IP address that you want the traffic to be redirected to. This is used
in two places:

1. The `hosts` file.
2. The Burp proxy listener will also listen on this IP address.

For most uses cases this parameter does not need to be provided and the default
`127.0.0.1` is good enough.

Note: Only use IP addresses here, not domains like `example.net` or `localhost`.

### Output -o/-output
The path of the report. The report contains the instructions on how to set up
and get started in proxying. The Burp config file will appear in the same path
but with the `json` extension.

Any extension here will be ignored. For example, `-o report.txt` will result in two
files:

1. `report.html`: Report with instructions.
2. `report.json`: Burp config file.

If this parameter is not used, the name of the pcap file is used. For example
`extract-sni app-capture.pcap` creates: `app-capture.html` and
`app-capture.json` in the same path as the pcap file.

## Usage

```
$ extract-sni.go -h
Extracts SNIs from a pcap and generates output usable in etc/hosts file and a Burp config that can be used for proxying thick clients.
Version 0.2.0
Usage: extract-sni.exe [--dns address/ip:port] [--output report] [--redirectip 127.0.0.1] traffic.pcap

Positional arguments:
  traffic.pcap           pcap file to parse

Options:
  --dns address/ip:port, -d address/ip:port
                         DNS server as Address/IP:Port
  --output report, -o report
                         output report filename
  --redirectip 127.0.0.1, -r 127.0.0.1
                         IP address to redirect the hosts to [default: 127.0.0.1]
  --help, -h             display this help and exit
  --version              display version and exit
```

## Questions

1. Why doesn't it capture pcaps, too?
    1. It's a small tool that does one thing. I do not like feature creep.
    2. I might actually add this later but right now I am OK with this.

## Troubleshooting

### My Output File is Noisy
Your pcap is noisy. Try to filter as much unrelated traffic as you can. I use
the techniques described in `Network Traffic Attribution on Windows`:

* https://parsiya.net/blog/2015-08-01-network-traffic-attribution-on-windows/

I usually use [Microsoft Network Monitor][netmon] or Netmon. With Netmon you can
filter traffic by process. However, this adds an extra step. Netmon's cap file
must be converted to pcap using Wireshark (or other tools). Keep in mind that
sometimes Wireshark cannot [convert cap files to pcap][cap-to-pcap].

[netmon]: https://www.microsoft.com/en-ca/download/details.aspx?id=4865
[cap-to-pcap]: https://parsiya.net/cheatsheet/#open-a-network-monitor-cap-file-in-wireshark-and-save-is-disabled

### Error `Couldn't load wpcap.dll`
`npcap` is not installed. See the [npcap](#npcap) section above for more info.

## License
Opensourced under the MIT license. See the [LICENSE](LICENSE) file for details.
