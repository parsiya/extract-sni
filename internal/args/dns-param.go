package args

import (
	"fmt"
	"strings"
)

// See https://github.com/alexflint/go-arg#custom-parsing.

type DNSParam struct {
	Host string
	Port string
}

// String is the stringer for DNSParam. Returns "host:port".
func (d DNSParam) String() string {
	return fmt.Sprintf("%s:%s", d.Host, d.Port)
}

// UnmarshalText parses and validates the incoming DNSParam.
func (d *DNSParam) UnmarshalText(b []byte) error {

	// Convert it to string.
	s := string(b)

	// Check if it has a ":".
	pos := strings.Index(s, ":")
	if pos == -1 {
		// All of it is Host.
		d.Host = s
	} else {
		// Everything before : is host.
		d.Host = s[:pos]
		// Everything after : is port.
		d.Port = s[pos+1:]
	}

	// Now check if d.Port is empty. If it's empty then it means the input did
	// not have a port. E.g., "localhost" or "localhost:". If so, use the
	// default port 53.
	d.Port = "53"

	return nil
}

// MarshalText returns the default value for the usage text.
func (d *DNSParam) MarshalText() ([]byte, error) {
	return []byte(fmt.Sprintf("%s:%s", d.Host, d.Port)), nil
}
