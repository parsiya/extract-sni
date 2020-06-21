# Extracted SNIs for {.pcapFileName}
Follow the instructions at [Thick Client Proxying - Part 10 - The hosts File][proxy-hosts].

[proxy-hosts]: https://parsiya.net/blog/2020-05-09-thick-client-proxying-part-10-the-hosts-file/#how-do-we-proxy-with-this

## Step 1: Hosts
Add the following text to your `etc/hosts` file. You will need local admin
access to edit it. Changes are applied as soon as you save the file.
	
```
# hosts file for {.pcapFileName}
{.Hosts}
```

## Step 2: Burp Config
Load the created project config in Burp. If you want to use your own config,
load this after Burp has loaded with your config via
`Project (menu) > Project options > Load project options`. This only overwrites
the listeners and the `hostname_resolution` sections.

```json
{.Config}
```

Note 1: The listeners are bound to the IP address supplied to the `redirectip`
parameter. If you want to listen on a different interface, open the config file
in an editor and search/replace.

Note 2: After loading the config, check `Dashboard (tab) > Event Log` to see if
all proxy listeners have been enabled properly. Proxy listeners will not work if
there is already something listening on that port.

## Step 3: Monitor, Rinse, and Repeat
You are now good to go. Keep monitoring the application for new endpoints. If
new endpoints are discovered you know what to do.

## Troubleshooting
See the blog post:

* [Thick Client Proxying - Part 10 - The hosts File][blog]

[blog]: https://parsiya.net/blog/2020-05-09-thick-client-proxying-part-10-the-hosts-file/
