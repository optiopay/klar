package docker

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
)

type Image struct {
	Registry string
	Name     string
	Tag      string
	FsLayers []FsLayer
}

type FsLayer struct {
	BlobSum string
}

var imageRe = regexp.MustCompile("(.*?[^/])/(.*?):(.*)")

func NewImage(qname string) (*Image, error) {
	parts := imageRe.FindStringSubmatch(qname)
	if parts == nil {
		return nil, fmt.Errorf("Can't parse image qname %q", qname)
	}
	registry, name, tag := parts[1], parts[2], parts[3]
	if tag == "" {
		tag = "latest"
	}
	registry = fmt.Sprintf("https://%s/v2", registry)
	return &Image{
		Registry: registry,
		Name:     name,
		Tag:      tag,
	}, nil
}

func (i *Image) Pull() error {
	url := fmt.Sprintf("%s/%s/manifests/%s", i.Registry, i.Name, i.Tag)
	fmt.Println(url)
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("Get error")
		return err
	}
	defer resp.Body.Close()
	if err = json.NewDecoder(resp.Body).Decode(i); err != nil {
		fmt.Println("Decode error")

		return err
	}
	return nil
}
