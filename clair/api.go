package clair

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/clair/api/v3/clairpb"
	"github.com/optiopay/klar/docker"
	"github.com/optiopay/klar/utils"
	"google.golang.org/grpc"
)

type apiV1 struct {
	url    string
	client http.Client
}

type apiV3 struct {
	url    string
	client clairpb.AncestryServiceClient
}

func newAPI(url string, version int, timeout time.Duration) (API, error) {
	if version < 3 {
		return newAPIV1(url, timeout), nil
	}
	return newAPIV3(url)
}

func newAPIV1(url string, timeout time.Duration) *apiV1 {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = fmt.Sprintf("http://%s", url)
	}
	if strings.LastIndex(url, ":") < 6 {
		url = fmt.Sprintf("%s:6060", url)
	}
	return &apiV1{
		url: url,
		client: http.Client{
			Timeout: timeout,
		},
	}
}

func newAPIV3(url string) (*apiV3, error) {
	if i := strings.Index(url, "://"); i != -1 {
		runes := []rune(url)
		url = string(runes[i+3:])
	}
	if strings.Index(url, ":") == -1 {
		url = fmt.Sprintf("%s:6060", url)
	}
	conn, err := grpc.Dial(url, grpc.WithInsecure())
	if err != nil {
		return nil, fmt.Errorf("did not connect to %s: %v", url, err)
	}
	return &apiV3{
		url:    url,
		client: clairpb.NewAncestryServiceClient(conn)}, nil
}

func (a *apiV1) Push(image *docker.Image) error {
	for i := 0; i < len(image.FsLayers); i++ {
		layer := newLayer(image, i)
		if err := a.pushLayer(layer); err != nil {
			return err
		}
	}
	return nil
}

func (a *apiV1) pushLayer(layer *layer) error {
	envelope := layerEnvelope{Layer: layer}
	reqBody, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("can't serialze push request: %s", err)
	}
	url := fmt.Sprintf("%s/v1/layers", a.url)
	request, err := http.NewRequest("POST", url, bytes.NewBuffer(reqBody))
	if err != nil {
		return fmt.Errorf("can't create a push request: %s", err)
	}
	request.Header.Set("Content-Type", "application/json")
	utils.DumpRequest(request)
	response, err := a.client.Do(request)
	if err != nil {
		return fmt.Errorf("can't push layer to Clair: %s", err)
	}
	utils.DumpResponse(response)
	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("can't read clair response : %s", err)
	}
	if response.StatusCode != http.StatusCreated {
		var lerr layerError
		err = json.Unmarshal(body, &lerr)
		if err != nil {
			return fmt.Errorf("can't even read an error message: %s", err)
		}
		return fmt.Errorf("push error %d: %s", response.StatusCode, string(body))
	}
	return nil
}

func (a *apiV1) Analyze(image *docker.Image) ([]*Vulnerability, error) {
	url := fmt.Sprintf("%s/v1/layers/%s?vulnerabilities", a.url, image.AnalyzedLayerName())
	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("can't create an analyze request: %s", err)
	}
	utils.DumpRequest(request)
	response, err := a.client.Do(request)
	if err != nil {
		return nil, err
	}
	utils.DumpResponse(response)
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(response.Body)
		return nil, fmt.Errorf("analyze error %d: %s", response.StatusCode, string(body))
	}
	var envelope layerEnvelope
	if err = json.NewDecoder(response.Body).Decode(&envelope); err != nil {
		return nil, err
	}
	var vs []*Vulnerability
	for _, f := range envelope.Layer.Features {
		for _, v := range f.Vulnerabilities {
			v.FeatureName = f.Name
			v.FeatureVersion = f.Version
			//the for loop uses the same variable for "v", reloading with new values
			//since we are appending a pointer to the variable to the slice, we need to create a copy of the struct
			//otherwise the slice winds up with multiple pointers to the same struct
			vulnerability := v
			vs = append(vs, &vulnerability)
		}
	}
	return vs, nil
}

func (a *apiV3) Push(image *docker.Image) error {
	req := &clairpb.PostAncestryRequest{
		Format:       "Docker",
		AncestryName: image.Name,
	}

	ls := make([]*clairpb.PostAncestryRequest_PostLayer, len(image.FsLayers))
	for i := 0; i < len(image.FsLayers); i++ {
		ls[i] = newLayerV3(image, i)
	}
	req.Layers = ls
	_, err := a.client.PostAncestry(context.Background(), req)
	return err
}

func newLayerV3(image *docker.Image, index int) *clairpb.PostAncestryRequest_PostLayer {
	return &clairpb.PostAncestryRequest_PostLayer{
		Hash:    image.LayerName(index),
		Path:    strings.Join([]string{image.Registry, image.Name, "blobs", image.FsLayers[index].BlobSum}, "/"),
		Headers: map[string]string{"Authorization": image.Token},
	}
}

func (a *apiV3) Analyze(image *docker.Image) ([]*Vulnerability, error) {
	req := &clairpb.GetAncestryRequest{
		AncestryName:        image.Name,
		WithFeatures:        true,
		WithVulnerabilities: true,
	}

	resp, err := a.client.GetAncestry(context.Background(), req)
	if err != nil {
		return nil, err
	}
	var vs []*Vulnerability
	for _, f := range resp.Ancestry.Features {
		for _, v := range f.Vulnerabilities {
			cv := convertVulnerability(v)
			cv.FeatureName = f.Name
			cv.FeatureVersion = f.Version
			//the for loop uses the same variable for "cv", reloading with new values
			//since we are appending a pointer to the variable to the slice, we need to create a copy of the struct
			//otherwise the slice winds up with multiple pointers to the same struct
			vulnerability := cv
			vs = append(vs, vulnerability)
		}
	}
	return vs, nil
}

func convertVulnerability(cv *clairpb.Vulnerability) *Vulnerability {
	return &Vulnerability{
		Name:          cv.Name,
		NamespaceName: cv.NamespaceName,
		Description:   cv.Description,
		Severity:      cv.Severity,
		Link:          cv.Link,
		FixedBy:       cv.FixedBy,
	}
}
