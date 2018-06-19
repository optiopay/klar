package main

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/optiopay/klar/clair"
)

func TestFilterWhitelist(t *testing.T) {
	image := "fluent/fluent-bit"
	whitelist := &vulnerabilitiesWhitelist{
		map[string]bool{"CVE-3": true},
		map[string]map[string]bool{image: {"CVE-4": true}},
	}

	vs := make([]*clair.Vulnerability, 5)
	for i := range vs {
		vs[i] = mockVulnerability(fmt.Sprintf("CVE-%d", i))
	}

	expected := make([]*clair.Vulnerability, 3)
	for i := range expected {
		expected[i] = mockVulnerability(fmt.Sprintf("CVE-%d", i))
	}

	filtered := filterWhitelist(whitelist, vs, image)
	if !reflect.DeepEqual(filtered, expected) {
		t.Fatalf("Actual filtered vulnerabilities %s did not match expected ones %s.", filtered, expected)
	}

}
func mockVulnerability(name string) *clair.Vulnerability {
	return &clair.Vulnerability{name, "", "", "", "", nil, "", nil, "", ""}
}
