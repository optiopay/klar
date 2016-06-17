package docker

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewImage(t *testing.T) {
	image, err := NewImage("docker-registry.optiopay.com/nginx:1b29e1531c")
	if err != nil {
		t.Fatalf("Can't parse qname: %s", err)
	}
	if image.Registry != "https://docker-registry.optiopay.com/v2" {
		t.Fatalf("Incorrect registry name %s", image.Registry)
	}
	if image.Name != "nginx" {
		t.Fatalf("Incorrect image name %s", image.Name)
	}
	if image.Tag != "1b29e1531c" {
		t.Fatalf("Incorrect image tag %s", image.Tag)
	}
}

func TestPull(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp, err := ioutil.ReadFile("testdata/registry-response.json")
		if err != nil {
			t.Fatalf("Can't load registry test response %s", err.Error())
		}
		fmt.Fprintln(w, string(resp))
	}))
	defer ts.Close()

	image, err := NewImage("docker-registry.optiopay.com/nginx:1b29e1531c")
	image.Registry = ts.URL
	err = image.Pull()
	if err != nil {
		t.Fatalf("Can't pull image: %s", err)
	}
	if len(image.FsLayers) == 0 {
		t.Fatal("Can't pull fsLayers")
	}
}
