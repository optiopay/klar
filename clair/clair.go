package clair

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/optiopay/klar/docker"
)

type Clair struct {
	url string
}

type layer struct {
	Name       string
	Path       string
	ParentName string
	Format     string
	Features   []feature `json:"Features"`
}

type feature struct {
	Name            string          `json:"Name,omitempty"`
	NamespaceName   string          `json:"NamespaceName,omitempty"`
	Version         string          `json:"Version,omitempty"`
	Vulnerabilities []Vulnerability `json:"Vulnerabilities"`
	AddedBy         string          `json:"AddedBy,omitempty"`
}

type Vulnerability struct {
	Name          string                 `json:"Name,omitempty"`
	NamespaceName string                 `json:"NamespaceName,omitempty"`
	Description   string                 `json:"Description,omitempty"`
	Link          string                 `json:"Link,omitempty"`
	Severity      string                 `json:"Severity,omitempty"`
	Metadata      map[string]interface{} `json:"Metadata,omitempty"`
	FixedBy       string                 `json:"FixedBy,omitempty"`
	FixedIn       []feature              `json:"FixedIn,omitempty"`
}

type layerError struct {
	Message string
}

type clairError struct {
	Message string `json:"Layer"`
}

type layerEnvelope struct {
	Layer *layer      `json:"Layer,omitempty"`
	Error *clairError `json:"Error,omitempty"`
}

func NewClair(url string) Clair {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = fmt.Sprintf("http://%s", url)
	}
	if strings.LastIndex(url, ":") < 5 {
		url = fmt.Sprintf("%s:6060", url)
	}
	return Clair{url}
}

func newLayer(image *docker.Image, index int) *layer {
	var parentName string
	if index > 0 {
		parentName = image.FsLayers[index-1].BlobSum
	}
	return &layer{
		Name:       image.FsLayers[index].BlobSum,
		Path:       strings.Join([]string{image.Registry, image.Name, "blobs", image.FsLayers[index].BlobSum}, "/"),
		ParentName: parentName,
		Format:     "Docker",
	}
}

func (c *Clair) Analyse(image *docker.Image) (*[]Vulnerability, error) {
	vs := make([]Vulnerability, 0)
	for i := range image.FsLayers {
		layer := newLayer(image, i)
		err := c.pushLayer(layer)
		if err != nil {
			fmt.Printf("Push layer %d failed: %s", i, err.Error())
			continue
		}
		lvs, err := c.analyzeLayer(layer)
		if err != nil {
			fmt.Printf("Analyze layer %d failed: %s", i, err.Error())
		} else {
			vs = append(vs, *lvs...)
		}
	}
	return &vs, nil
}

func (c *Clair) analyzeLayer(layer *layer) (*[]Vulnerability, error) {
	url := fmt.Sprintf("%s/v1/layers/%s?vulnerabilities", c.url, layer.Name)
	response, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(response.Body)
		return nil, fmt.Errorf("Analyze error %d: %s", response.StatusCode, string(body))
	}
	var envelope layerEnvelope
	if err = json.NewDecoder(response.Body).Decode(&envelope); err != nil {
		return nil, err
	}
	vs := make([]Vulnerability, 0)
	for _, f := range envelope.Layer.Features {
		for _, v := range f.Vulnerabilities {
			vs = append(vs, v)
		}
	}
	return &vs, nil
}

func (c *Clair) pushLayer(layer *layer) error {
	envelope := layerEnvelope{Layer: layer}
	reqBody, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("can't serialze push request: %s", err)
	}
	url := fmt.Sprintf("%s/v1/layers", c.url)
	request, err := http.NewRequest("POST", url, bytes.NewBuffer(reqBody))
	if err != nil {
		return fmt.Errorf("Can't create a push request: %s", err)
	}
	request.Header.Set("Content-Type", "application/json")
	//fmt.Printf("Pushing layer %v", layer)
	response, err := (&http.Client{Timeout: time.Minute}).Do(request)
	if err != nil {
		return fmt.Errorf("Can't push layer to Clair: %s", err)
	}
	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("Can't read clair response : %s", err)
	}
	if response.StatusCode != http.StatusCreated {
		var lerr layerError
		err = json.Unmarshal(body, &lerr)
		if err != nil {
			return fmt.Errorf("Can't even read an error message: %s", err)
		}
		return fmt.Errorf("Push error %d: %s", response.StatusCode, string(body))
	}
	return nil

}
