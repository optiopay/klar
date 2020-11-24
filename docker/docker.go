package docker

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/optiopay/klar/utils"
)

const (
	stateInitial = iota
	stateName
	statePort
	stateTag
)

// Image represents Docker image
type Image struct {
	Registry      string
	Name          string
	Tag           string
	FsLayers      []FsLayer
	Token         string
	user          string
	password      string
	client        http.Client
	digest        string
	schemaVersion int
	os            string
	arch          string
}

func (i *Image) LayerName(index int) string {
	s := fmt.Sprintf("%s%s", trimDigest(i.digest),
		trimDigest(i.FsLayers[index].BlobSum))
	return s
}

func (i *Image) AnalyzedLayerName() string {
	index := len(i.FsLayers) - 1
	if i.schemaVersion == 1 {
		index = 0
	}
	return i.LayerName(index)
}

func trimDigest(d string) string {
	return strings.Replace(d, "sha256:", "", 1)
}

// FsLayer represents a layer in docker image
type FsLayer struct {
	BlobSum string
}

// ImageV1 represents a Manifest V 2, Schema 1 Docker Image
type imageV1 struct {
	SchemaVersion int
	FsLayers      []fsLayer
}

// FsLayer represents a layer in a Manifest V 2, Schema 1 Docker Image
type fsLayer struct {
	BlobSum string
}

type config struct {
	MediaType string
	Digest    string
}

// imageV2 represents Manifest V 2, Schema 2 Docker Image
type imageV2 struct {
	SchemaVersion int
	Config        config
	Layers        []layer
}

// Layer represents a layer in a Manifest V 2, Schema 2 Docker Image
type layer struct {
	Digest string
}

// ManifestList represents a ManifestList V 2
type manifestList struct {
	SchemaVersion int
	MediaType     string
	Manifests     []manifest
}

// Manifest represents a manifest item in a ManifestList V 2
type manifest struct {
	MediaType string
	Size      int
	Digest    string
	Platform  platform
}

type platform struct {
	Architecture string
	OS           string
	Variant      string
}

type Config struct {
	ImageName        string
	User             string
	Password         string
	Token            string
	InsecureTLS      bool
	InsecureRegistry bool
	Timeout          time.Duration
	PlatformOS       string
	PlatformArch     string
}

const dockerHub = "registry-1.docker.io"

var tokenRe = regexp.MustCompile(`Bearer realm="(.*?)",service="(.*?)",scope="(.*?)"`)

// NewImage parses image name which could be the ful name registry:port/name:tag
// or in any other shorter forms and creates docker image entity without
// information about layers
func NewImage(conf *Config) (*Image, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: conf.InsecureTLS},
		Proxy:           http.ProxyFromEnvironment,
	}
	client := http.Client{
		Transport: tr,
		Timeout:   conf.Timeout,
	}
	registry := dockerHub
	tag := "latest"
	token := ""
	os := "linux"
	arch := "amd64"
	var nameParts, tagParts []string
	var name, port string
	state := stateInitial
	start := 0
	for i, c := range conf.ImageName {
		if c == ':' || c == '/' || c == '@' || i == len(conf.ImageName)-1 {
			if i == len(conf.ImageName)-1 {
				// ignore a separator, include the last symbol
				i += 1
			}
			part := conf.ImageName[start:i]
			start = i + 1
			switch state {
			case stateInitial:
				if part == "localhost" || strings.Contains(part, ".") {
					// it's registry, let's check what's next =port of image name
					registry = part
					if c == ':' {
						state = statePort
					} else {
						state = stateName
					}
				} else {
					// it's an image name, if separator is /
					// next part is also part of the name
					// othrewise it's an offcial image
					if c == '/' {
						// we got just a part of name, till next time
						start = 0
						state = stateName
					} else {
						state = stateTag
						name = fmt.Sprintf("library/%s", part)
					}
				}
			case stateTag:
				tag = ""
				tagParts = append(tagParts, part)
			case statePort:
				state = stateName
				port = part
			case stateName:
				if c == ':' || c == '@' {
					state = stateTag
				}
				nameParts = append(nameParts, part)
			}
		}
	}

	if port != "" {
		registry = fmt.Sprintf("%s:%s", registry, port)
	}
	if name == "" {
		name = strings.Join(nameParts, "/")
	}
	if tag == "" {
		tag = strings.Join(tagParts, ":")
	}
	if conf.InsecureRegistry {
		registry = fmt.Sprintf("http://%s/v2", registry)
	} else {
		registry = fmt.Sprintf("https://%s/v2", registry)
	}
	if conf.Token != "" {
		token = "Basic " + conf.Token
	}
	if conf.PlatformOS != "" {
		os = conf.PlatformOS
	}
	if conf.PlatformArch != "" {
		arch = conf.PlatformArch
	}

	return &Image{
		Registry: registry,
		Name:     name,
		Tag:      tag,
		user:     conf.User,
		password: conf.Password,
		Token:    token,
		client:   client,
		os:       os,
		arch:     arch,
	}, nil
}

// Pull retrieves information about layers from docker registry.
// It gets docker registry token if needed.
func (i *Image) Pull() error {
	resp, err := i.pullReq()
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		i.Token, err = i.requestToken(resp)
		io.Copy(ioutil.Discard, resp.Body)
		if err != nil {
			return err
		}
		// try again
		resp, err = i.pullReq()
		if err != nil {
			return err
		}
		defer resp.Body.Close()
	}
	if contentType := resp.Header.Get("Content-Type"); contentType == "application/vnd.docker.distribution.manifest.list.v2+json" {
		err = parseManifestResponse(resp, i)
		if err != nil {
			return err
		}
		// pull actual manifest instead of manifestlist
		resp, err = i.pullReq()
		if err != nil {
			return err
		}
		defer resp.Body.Close()
	}
	return parseImageResponse(resp, i)
}

func parseImageResponse(resp *http.Response, image *Image) error {
	switch contentType := resp.Header.Get("Content-Type"); contentType {
	case "application/vnd.docker.distribution.manifest.v2+json":
		var imageV2 imageV2
		if err := json.NewDecoder(resp.Body).Decode(&imageV2); err != nil {
			fmt.Fprintln(os.Stderr, "Image V2 decode error")
			return err
		}
		image.FsLayers = make([]FsLayer, len(imageV2.Layers))
		for i := range imageV2.Layers {
			image.FsLayers[i].BlobSum = imageV2.Layers[i].Digest
		}
		image.digest = imageV2.Config.Digest
		image.schemaVersion = imageV2.SchemaVersion
	case "application/vnd.docker.distribution.manifest.v1+prettyjws":
		var imageV1 imageV1
		if err := json.NewDecoder(resp.Body).Decode(&imageV1); err != nil {
			fmt.Fprintln(os.Stderr, "ImageV1 decode error")
			return err
		}
		image.FsLayers = make([]FsLayer, len(imageV1.FsLayers))
		// in schemaVersion 1 layers are in reverse order, so we save them in the same order as v2
		// base layer is the first
		for i := range imageV1.FsLayers {
			image.FsLayers[len(imageV1.FsLayers)-1-i].BlobSum = imageV1.FsLayers[i].BlobSum
		}
		image.schemaVersion = imageV1.SchemaVersion
	default:
		return fmt.Errorf("Docker Registry responded with unsupported Content-Type: %s", contentType)
	}
	return nil
}

func parseManifestResponse(resp *http.Response, image *Image) error {
	var manifestlist manifestList
	if err := json.NewDecoder(resp.Body).Decode(&manifestlist); err != nil {
		fmt.Fprintln(os.Stderr, "ManifestList decode error")
		return err
	}
	for _, m := range manifestlist.Manifests {
		if m.Platform.OS == image.os && m.Platform.Architecture == image.arch {
			image.Tag = m.Digest
			return nil
		}
	}
	return fmt.Errorf("Did not find the specified platform (os: %s, arch: %s) in the manifest list.", image.os, image.arch)
}

func (i *Image) requestToken(resp *http.Response) (string, error) {
	authHeader := resp.Header.Get("Www-Authenticate")
	if authHeader == "" {
		return "", fmt.Errorf("Empty Www-Authenticate")
	}
	parts := tokenRe.FindStringSubmatch(authHeader)
	if parts == nil {
		return "", fmt.Errorf("Can't parse Www-Authenticate: %s", authHeader)
	}
	realm, service, scope := parts[1], parts[2], parts[3]
	var url string
	if i.user != "" {
		url = fmt.Sprintf("%s?service=%s&scope=%s&account=%s", realm, service, scope, i.user)
	} else {
		url = fmt.Sprintf("%s?service=%s&scope=%s", realm, service, scope)
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Can't create a request")
		return "", err
	}
	if i.user != "" {
		req.SetBasicAuth(i.user, i.password)
	}
	tResp, err := i.client.Do(req)
	if err != nil {
		if tResp != nil {
			io.Copy(ioutil.Discard, tResp.Body)
		}
		return "", err
	}

	defer tResp.Body.Close()
	if tResp.StatusCode != http.StatusOK {
		io.Copy(ioutil.Discard, tResp.Body)
		return "", fmt.Errorf("Token request returned %d", tResp.StatusCode)
	}

	var tokenEnv map[string]interface{}
	if err = json.NewDecoder(tResp.Body).Decode(&tokenEnv); err != nil {
		fmt.Fprintln(os.Stderr, "Token response decode error")
		return "", err
	}
	if token, ok := tokenEnv["token"]; ok {
		return fmt.Sprintf("Bearer %s", token), nil
	}
	if token, ok := tokenEnv["access_token"]; ok {
		return fmt.Sprintf("Bearer %s", token), nil
	}
	fmt.Fprintln(os.Stderr, "Token response decode error, no token or access_token found")
	return "", err
}

func (i *Image) pullReq() (*http.Response, error) {
	url := fmt.Sprintf("%s/%s/manifests/%s", i.Registry, i.Name, i.Tag)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Can't create a request")
		return nil, err
	}
	if i.Token == "" && i.user != "" {
		req.SetBasicAuth(i.user, i.password)
		i.Token = req.Header.Get("Authorization")
	} else {
		req.Header.Set("Authorization", i.Token)
	}

	// Prefer manifest schema v2
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.v1+prettyjws, application/vnd.docker.distribution.manifest.list.v2+json")
	utils.DumpRequest(req)
	resp, err := i.client.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Get error")
		return nil, err
	}
	utils.DumpResponse(resp)
	return resp, nil
}
