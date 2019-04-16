package docker

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewImage(t *testing.T) {
	tcs := map[string]struct {
		image    string
		registry string
		name     string
		tag      string
	}{
		"full": {
			image:    "docker-registry.domain.com:8080/nginx:1b29e1531c",
			registry: "https://docker-registry.domain.com:8080/v2",
			name:     "nginx",
			tag:      "1b29e1531c",
		},
		"regular": {
			image:    "docker-registry.domain.com/nginx:1b29e1531c",
			registry: "https://docker-registry.domain.com/v2",
			name:     "nginx",
			tag:      "1b29e1531c",
		},
		"regular_extended": {
			image:    "docker-registry.domain.com/skynetservices/skydns:2.3",
			registry: "https://docker-registry.domain.com/v2",
			name:     "skynetservices/skydns",
			tag:      "2.3",
		},
		"no_tag": {
			image:    "docker-registry.domain.com/nginx",
			registry: "https://docker-registry.domain.com/v2",
			name:     "nginx",
			tag:      "latest",
		},
		"no_tag_with_port": {
			image:    "docker-registry.domain.com:8080/nginx",
			registry: "https://docker-registry.domain.com:8080/v2",
			name:     "nginx",
			tag:      "latest",
		},

		"no_registry": {
			image:    "skynetservices/skydns:2.3",
			registry: "https://registry-1.docker.io/v2",
			name:     "skynetservices/skydns",
			tag:      "2.3",
		},
		"no_registry_root": {
			image:    "postgres:9.5.1",
			registry: "https://registry-1.docker.io/v2",
			name:     "library/postgres",
			tag:      "9.5.1",
		},
		"digest": {
			image:    "postgres@sha256:f6a2b81d981ace74aeafb2ed2982d52984d82958bfe836b82cbe4bf1ba440999",
			registry: "https://registry-1.docker.io/v2",
			name:     "library/postgres",
			tag:      "sha256:f6a2b81d981ace74aeafb2ed2982d52984d82958bfe836b82cbe4bf1ba440999",
		},
		"localhost_no_tag": {
			image:    "localhost/nginx",
			registry: "https://localhost/v2",
			name:     "nginx",
			tag:      "latest",
		},
		"localhost_tag_with_port": {
			image:    "localhost:8080/nginx:xxx",
			registry: "https://localhost:8080/v2",
			name:     "nginx",
			tag:      "xxx",
		},
	}
	for name, tc := range tcs {

		image, err := NewImage(&Config{ImageName: tc.image})
		if err != nil {
			t.Fatalf("%s: Can't parse image name: %s", name, err)
		}
		if image.Registry != tc.registry {
			t.Fatalf("%s: Expected registry name %s, got %s", name, tc.registry, image.Registry)
		}
		if image.Name != tc.name {
			t.Fatalf("%s: Expected image name %s, got %s", name, tc.name, image.Name)
		}
		if image.Tag != tc.tag {
			t.Fatalf("%s: Expected image tag %s, got %s", name, tc.tag, image.Tag)
		}
	}

}

func TestPullManifestSchemaV1(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "application/vnd.docker.distribution.manifest.v1+prettyjws")
		resp, err := ioutil.ReadFile("testdata/registry-response.json")
		if err != nil {
			t.Fatalf("Can't load registry test response %s", err.Error())
		}
		fmt.Fprintln(w, string(resp))
	}))
	defer ts.Close()

	image, err := NewImage(&Config{ImageName: "docker-registry.domain.com/nginx:1b29e1531ci"})
	image.Registry = ts.URL
	err = image.Pull()
	if err != nil {
		t.Fatalf("Can't pull image: %s", err)
	}
	if len(image.FsLayers) == 0 {
		t.Fatal("Can't pull fsLayers")
	}
}

func TestPullManifestSchemaV2(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp, err := ioutil.ReadFile("testdata/registry-response-schemav2.json")
		w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
		if err != nil {
			t.Fatalf("Can't load registry test response %s", err.Error())
		}
		fmt.Fprintln(w, string(resp))
	}))
	defer ts.Close()

	image, err := NewImage(&Config{ImageName: "docker-registry.domain.com/nginx:1b29e1531c"})
	image.Registry = ts.URL
	err = image.Pull()
	if err != nil {
		t.Fatalf("Can't pull image: %s", err)
	}
	if len(image.FsLayers) == 0 {
		t.Fatal("Can't pull fsLayers")
	}
}
