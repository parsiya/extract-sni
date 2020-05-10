package args

import (
	"testing"
)

func Test_isValid(t *testing.T) {
	type args struct {
		val string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"valid-burp", args{val: "burp"}, true},
		{"valid-hosts", args{val: "hosts"}, true},
		{"valid-both", args{val: "both"}, true},
		{"invalid-all", args{val: "all"}, false},
		{"invalid-empty", args{val: ""}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValid(tt.args.val); got != tt.want {
				t.Errorf("isValid() = %v, want %v", got, tt.want)
			}
		})
	}
}
