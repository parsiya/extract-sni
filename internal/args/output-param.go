package args

import (
	"fmt"
	"strings"
)

// Valid output format values.
var validFormats = map[string]struct{}{
	"hosts": struct{}{},
	"burp":  struct{}{},
	"both":  struct{}{},
}

// isValid checks whether a value is a key in validFormats.
func isValid(val string) bool {
	_, exists := validFormats[val]
	return exists
}

// outputFormats returns a comma-separated list of valid output formats.
func outputFormats() string {
	keys := make([]string, 0)
	for k := range validFormats {
		keys = append(keys, k)
	}
	return strings.Join(keys, ", ")
}

// ----------

// OutputParam represents the --output or -o parameter.
type OutputParam struct {
	Format string
}

// String is the stringer for OutputParam. Returns Format.
func (o OutputParam) String() string {
	return o.Format
}

// UnmarshalText checks whether the incoming OutputParam is one of the valid
// options.
func (o *OutputParam) UnmarshalText(b []byte) error {

	s := string(b)
	// Check whether we got a valid output format.
	if exists := isValid(s); exists {
		o.Format = s
		return nil
	}

	return fmt.Errorf("%s is not one of the valid output format values. Valid values are %s", s, outputFormats())
}
