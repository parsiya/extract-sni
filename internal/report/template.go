package report

import (
	"html/template"
	"strings"
)

// Info contains the information that go into the report HTML template.
type Info struct {
	PcapFileName   string
	Hosts          string
	ConfigFileName string
}

// Generate creates the html report.
func (i Info) Generate() (string, error) {
	var rpt strings.Builder
	// Parse the template.
	tmpl, err := template.New("report").Parse(reportTemplate)
	if err != nil {
		return "", err
	}
	// Execute the template.
	if err := tmpl.Execute(&rpt, i); err != nil {
		return "", err
	}
	// Return the results.
	return rpt.String(), nil
}

// template.html bundled in the app.
var reportTemplate = `
<!DOCTYPE html>
<html>
	<head>
		<meta charset="UTF-8">
			<title>Extracted SNIs for {{.PcapFileName}}</title>
			<style>
           /*  Copyright (c) Microsoft Corporation. All rights reserved.
            *  Licensed under the MIT License. See License.txt in the project root for license information.
            */
            /* Modified vscode/markdown.css */
            html, body {
                font-family: var(--markdown-font-family, -apple-system, BlinkMacSystemFont, "Segoe WPC", "Segoe UI", system-ui, "Ubuntu", "Droid Sans", sans-serif);
                font-size: var(--markdown-font-size, 14px);
                padding: 0 26px;
                line-height: var(--markdown-line-height, 22px);
                word-wrap: break-word;
            }
            body.scrollBeyondLastLine {
                margin-bottom: calc(100vh - 22px);
            }
            a {
                text-decoration: none;
            }
            a:hover {
                text-decoration: underline;
            }
            a:focus,
            input:focus,
            select:focus,
            textarea:focus {
                outline: 1px solid -webkit-focus-ring-color;
                outline-offset: -1px;
            }
            h1 {
                padding-bottom: 0.3em;
                line-height: 1.2;
                border-bottom-width: 1px;
                border-bottom-style: solid;
            }
            h1, h2, h3 {
                font-weight: normal;
            }
            code {
                font-family: var(--vscode-editor-font-family, "SF Mono", Monaco, Menlo, Consolas, "Ubuntu Mono", "Liberation Mono", "DejaVu Sans Mono", "Courier New", monospace);
                font-size: 1em;
                line-height: 1.357em;
                font-weight: bold;
            }
            body.wordWrap pre {
                white-space: pre-wrap;
            }
            pre:not(.hljs),
            pre.hljs code > div {
                padding: 16px;
                border-radius: 3px;
                overflow: auto;
            }
            pre code {
                color: var(--vscode-editor-foreground);
                tab-size: 4;
            }
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe WPC', 'Segoe UI', system-ui, 'Ubuntu', 'Droid Sans', sans-serif;
                font-size: 16px;
                line-height: 1.6;
            }

            .vscode-dark pre {
                background-color: rgba(82, 79, 79, 0.4);
            }
            .vscode-dark h1,
            .vscode-dark hr,
            .vscode-dark table > tbody > tr + tr > td {
                border-color: rgba(255, 255, 255, 0.18);
            }
        </style>
    </head>
    <body class="vscode-dark">
        <h1>Extracted SNIs for {{.PcapFileName}}</h1>
        <p>Follow the instructions at 
            <a
            href="https://parsiya.net/blog/2020-05-09-thick-client-proxying-part-10-the-hosts-file/#how-do-we-proxy-with-this"
            target="_blank">Thick Client Proxying - Part 10 - The hosts
            File</a>.
        </p>
        <h2>Step 1: Hosts</h2>
        <p>Add the following text to your 
            <code>etc/hosts</code> file. You will need local admin access to
            edit it. Changes are applied as soon as you save the file.
        </p>
        <pre># hosts file for {{.PcapFileName}}
{{.Hosts}}</pre>
        <h2>Step 2: Burp Config</h2>
        <p>Load the created project config in Burp. If you want to use your own
        config, load this after Burp has loaded with your config via
            <code>Project (menu) &gt; Project options &gt; Load project options</code>. This only overwrites
the listeners and the 
            <code>hostname_resolution</code> sections.
        </p>
        <ul>
            <li>
                <a href="{{.ConfigFileName}}" target="_blank">{{.ConfigFileName}}</a>
            </li>
        </ul>
        
        <p>Note 1: The listeners are bound to the IP address supplied to the 
            <code>redirectip</code> parameter. If you want to listen on a
            different interface, open the config file in an editor and
            search/replace.
        </p>
        <p>Note 2: After loading the config, check <code>Dashboard (tab) &gt;
        Event Log</code> to see if all proxy listeners have been enabled
        properly. Proxy listeners will not work if there is already something
        listening on that port.
        </p>
        <h2>Step 3: Monitor, Rinse, and Repeat</h2>
        <p>You are now good to go. Keep monitoring the application for new
        endpoints. If new endpoints are discovered you know what to do.</p>
        <h2>Troubleshooting</h2>
        <p>See the blog post:</p>
        <ul>
            <li>
                <a
                href="https://parsiya.net/blog/2020-05-09-thick-client-proxying-part-10-the-hosts-file/"
                target="_blank">Thick Client Proxying - Part 10 - The hosts
                File</a>
            </li>
        </ul>
    </body>
</html>
`
