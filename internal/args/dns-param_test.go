package args

import "testing"

func TestDNSParam_UnmarshalText(t *testing.T) {
	type args struct {
		b []byte
	}
	tests := []struct {
		name string
		d    *DNSParam
		args args
		res  DNSParam
	}{
		{"ip-port", &DNSParam{}, args{b: []byte("127.0.0.1:1234")}, DNSParam{Host: "127.0.0.1", Port: "1234"}},
		{"ip-port-noport-nocolon", &DNSParam{}, args{b: []byte("127.0.0.1")}, DNSParam{Host: "127.0.0.1", Port: "53"}},
		{"ip-port-noport", &DNSParam{}, args{b: []byte("127.0.0.1:")}, DNSParam{Host: "127.0.0.1", Port: "53"}},
		{"server-port", &DNSParam{}, args{b: []byte("example.net:1234")}, DNSParam{Host: "example.net", Port: "1234"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			if err := tt.d.UnmarshalText(tt.args.b); err != nil {
				t.Errorf("DNSParam.UnmarshalText() error = %v", err)
				return
			}
			if tt.d.Host != tt.res.Host {
				t.Errorf("DNSParam.UnmarshalText() bad Host, got %v, want %v", tt.d.Host, tt.res.Host)
			}
		})
	}
}
