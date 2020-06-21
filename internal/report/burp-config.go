package report

import "github.com/parsiya/go-helpers/jsonhelper"

// Created with https://mholt.github.io/json-to-go/.

// Host is a single hostname resolution item.
type Host struct {
	Enabled   bool   `json:"enabled"`
	Hostname  string `json:"hostname"`
	IPAddress string `json:"ip_address"`
}

// NewHost returns a populated Hostname.
func NewHost(sni, ip string) Host {
	return Host{
		Enabled:   true,
		Hostname:  sni,
		IPAddress: ip,
	}
}

// Listener is a Burp proxy listener.
type Listener struct {
	CertificateMode          string `json:"certificate_mode"`
	ListenMode               string `json:"listen_mode"`
	ListenSpecificAddress    string `json:"listen_specific_address"`
	ListenerPort             int    `json:"listener_port"`
	Running                  bool   `json:"running"`
	SupportInvisibleProxying bool   `json:"support_invisible_proxying"`
}

// NewListener returns a populated listener.
func NewListener(listenerIP string, listenerPort int) Listener {

	lsn := Listener{
		CertificateMode:          "per_host",
		ListenerPort:             listenerPort,
		Running:                  true,
		SupportInvisibleProxying: true,
	}

	if listenerIP == "127.0.0.1" {
		lsn.ListenMode = "loopback_only"
		lsn.ListenSpecificAddress = ""
	} else {
		lsn.ListenMode = "specific_address"
		lsn.ListenSpecificAddress = listenerIP
	}

	return lsn
}

// BurpConfig is a subset of a Burp project config file.
type BurpConfig struct {
	ProjectOptions struct {
		Connections struct {
			HostnameResolution []Host `json:"hostname_resolution"`
		} `json:"connections"`
	} `json:"project_options"`
	Proxy struct {
		RequestListeners []Listener `json:"request_listeners"`
	} `json:"proxy"`
}

// JSON converts a BurpConfig struct to JSON. The output can be loaded in Burp.
func (c BurpConfig) JSON() (string, error) {

	js, err := jsonhelper.StructToJSONString(c, true, false)
	// js, err := json.MarshalIndent(&c, "", "    ")
	if err != nil {
		return "", err
	}
	return string(js), nil
}
