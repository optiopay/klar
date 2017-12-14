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

const dockerHub = "registry-1.docker.io"

var tokenRe = regexp.MustCompile(`Bearer realm="(.*?)",service="(.*?)",scope="(.*?)"`)

// NewImage parses image name which could be the ful name registry:port/name:tag
// or in any other shorter forms and creates docker image entity without
// information about layers
func NewImage(qname, user, password string, insecureTLS, insecureRegistry bool) (*Image, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureTLS},
	}
	client := http.Client{
		Transport: tr,
		Timeout:   time.Minute,
	}
	registry := dockerHub
	tag := "latest"
	var name string

	if !utils.ImageOnlyRegexp.MatchString(string(qname)) || strings.HasPrefix(qname, "localhost/") {
		registry = utils.DomainRegexp.FindString(string(qname))
		imageAndTag := utils.ImageRegexp.FindStringSubmatch(string(qname))
		result := make(map[string]string)
		for i, name := range utils.ImageRegexp.SubexpNames() {
			if i != 0 {
				result[name] = imageAndTag[i]
			}
		}
		name = result["name"]
		if len(result["tag"]) > 0 {
			tag = result["tag"]
		}
	} else {
		imageAndTag := utils.ImageNoRegistryRegexp.FindStringSubmatch(string(qname))
		result := make(map[string]string)
		for i, name := range utils.ImageRegexp.SubexpNames() {
			if i != 0 {
				result[name] = imageAndTag[i]
			}
		}
		name = result["name"]
		if !strings.Contains(name, "/") {
			name = "library/" + name
		}
		if len(result["tag"]) > 0 {
			tag = result["tag"]
		}
	}

	if insecureRegistry {
		registry = fmt.Sprintf("http://%s/v2", registry)
	} else {
		registry = fmt.Sprintf("https://%s/v2", registry)
	}

	return &Image{
		Registry: registry,
		Name:     name,
		Tag:      tag,
		user:     user,
		password: password,
		client:   client,
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
	if resp.StatusCode == http.StatusNotFound {
		fmt.Fprintln(os.Stderr, "Image not found")
		os.Exit(1)
	}

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
	}
	defer resp.Body.Close()
	return parseImageResponse(resp, i)
}

func parseImageResponse(resp *http.Response, image *Image) error {
	contentType := resp.Header.Get("Content-Type")
	if contentType == "application/vnd.docker.distribution.manifest.v2+json" {
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
	} else {
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
	}
	return nil
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
		io.Copy(ioutil.Discard, tResp.Body)
		return "", err
	}

	defer tResp.Body.Close()
	if tResp.StatusCode != http.StatusOK {
		io.Copy(ioutil.Discard, tResp.Body)
		return "", fmt.Errorf("Token request returned %d", tResp.StatusCode)
	}
	var tokenEnv struct {
		Token string
	}

	if err = json.NewDecoder(tResp.Body).Decode(&tokenEnv); err != nil {
		fmt.Fprintln(os.Stderr, "Token response decode error")
		return "", err
	}
	return fmt.Sprintf("Bearer %s", tokenEnv.Token), nil
}

func (i *Image) pullReq() (*http.Response, error) {
	url := fmt.Sprintf("%s/%s/manifests/%s", i.Registry, i.Name, i.Tag)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Can't create a request")
		return nil, err
	}
	if i.Token == "" {
		if i.user != "" {
			req.SetBasicAuth(i.user, i.password)
			i.Token = req.Header.Get("Authorization")
		}
	} else {
		req.Header.Set("Authorization", i.Token)
	}

	// Prefer manifest schema v2
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json")
	utils.DumpRequest(req)
	resp, err := i.client.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Get error")
		return nil, err
	}
	utils.DumpResponse(resp)
	return resp, nil
}
