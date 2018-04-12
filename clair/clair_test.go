package clair

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/coreos/clair/api/v3/clairpb"
	"github.com/optiopay/klar/docker"
	"google.golang.org/grpc"
)

const (
	imageName      = "test-image"
	imageTag       = "image-tag"
	imageRegistry  = "https://image-registry"
	layerHash      = "blob1"
	emptyLayerHash = "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
	imageToken     = "token"
)

func clairServerhandler(t *testing.T) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		responseFile := "testdata/clair-get"

		if r.Method == "POST" {
			var envelope layerEnvelope
			if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
				http.Error(w, `{"message": "json decode"}`, http.StatusBadRequest)
				return
			}
			layer := envelope.Layer
			if layer.Name != layerHash {
				http.Error(w, `{"message": "layer name"}`, http.StatusBadRequest)
				return
			}
			if layer.Headers.Authorization != imageToken {
				http.Error(w, `{"message": "image token"}`, http.StatusBadRequest)
				return
			}

			if layer.Path != fmt.Sprintf("%s/%s/blobs/%s", imageRegistry, imageName, layerHash) {
				http.Error(w, `{"message": "layer path"}`, http.StatusBadRequest)
				return
			}

			if layer.ParentName != "" && layer.ParentName != layerHash {
				http.Error(w, `{"message": "layer parent name"}`, http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusCreated)
			responseFile = "testdata/clair-post"
		} else {
			if r.URL.Path != fmt.Sprintf("/v1/layers/%s", layerHash) {
				http.Error(w, `{"message": "get path"}`, http.StatusBadRequest)
				return
			}
		}

		resp, err := ioutil.ReadFile(responseFile)
		if err != nil {
			t.Fatalf("Can't load clair test response %s", err.Error())
		}
		fmt.Fprintln(w, string(resp))
	})
}

var dockerImage = &docker.Image{
	Registry: imageRegistry,
	Name:     imageName,
	Tag:      imageTag,
	FsLayers: []docker.FsLayer{
		{layerHash},
		{emptyLayerHash},
		{layerHash},
	},
	Token: imageToken,
}

func TestAnalyseV1(t *testing.T) {
	ts := httptest.NewServer(clairServerhandler(t))
	defer ts.Close()

	c := NewClair(ts.URL, 1, time.Minute)
	vs, err := c.Analyse(dockerImage)
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 1 {
		t.Fatalf("Expected 1 vulnerability, got %d", len(vs))
	}
}

const gAddr = "localhost:60801"

type gServer struct{}

func startGServer() {
	lis, err := net.Listen("tcp", gAddr)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	clairpb.RegisterAncestryServiceServer(s, &gServer{})

	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

func TestMain(m *testing.M) {
	go startGServer()
	os.Exit(m.Run())
}

func (s *gServer) PostAncestry(ctx context.Context, in *clairpb.PostAncestryRequest) (*clairpb.PostAncestryResponse, error) {
	return &clairpb.PostAncestryResponse{}, nil
}

func (s *gServer) GetAncestry(ctx context.Context, in *clairpb.GetAncestryRequest) (*clairpb.GetAncestryResponse, error) {
	return &clairpb.GetAncestryResponse{
		Ancestry: &clairpb.Ancestry{
			Name: in.GetAncestryName(),
			Features: []*clairpb.Feature{
				{
					Name:          "coreutils",
					NamespaceName: "debian:8",
					Version:       "8.23-4",
					Vulnerabilities: []*clairpb.Vulnerability{
						{

							Name:          "CVE-2014-9471",
							NamespaceName: "debian:8",
							Description:   "The parse_datetime function in GNU coreutils ...",
							Link:          "https://security-tracker.debian.org/tracker/CVE-2014-9471",
							Severity:      "Low",
							FixedBy:       "9.23-5",
						},
					},
				},
			},
		},
	}, nil
}

func TestAnalyseV3(t *testing.T) {
	c := NewClair(gAddr, 3, time.Minute)
	vs, err := c.Analyse(dockerImage)
	if err != nil {
		t.Fatal(err)
	}

	if len(vs) != 1 {
		t.Fatalf("Expected 1 vulnerability, got %d", len(vs))
	}
	if vs[0].Name != "CVE-2014-9471" {
		t.Errorf("unexpected vulnerability name: %s", vs[0].Name)
	}
}
