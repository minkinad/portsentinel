package security

import (
	"context"
	"testing"
)

func TestPolicyBlocksPrivateAndPorts(t *testing.T) {
	cases := []struct {
		url     string
		policy  Policy
		blocked bool
	}{{"http://127.0.0.1", Policy{AllowedPorts: []int{80}}, true}, {"http://127.0.0.1:8080", Policy{AllowedPorts: []int{80}}, true}, {"http://127.0.0.1", Policy{AllowPrivate: true, AllowedPorts: []int{80}}, false}, {"http://user:pass@example.com", Policy{AllowedPorts: []int{80}}, true}}
	for _, tc := range cases {
		t.Run(tc.url, func(t *testing.T) {
			_, err := tc.policy.Resolve(context.Background(), tc.url)
			if (err != nil) != tc.blocked {
				t.Fatalf("error=%v blocked=%v", err, tc.blocked)
			}
		})
	}
}
