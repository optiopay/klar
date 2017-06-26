package docker

import (
	"os"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"regexp"
	"strings"
)

const (
	stateInitial = iota
	stateName
	statePort
	stateTag
)

// Image represents Docker image
type Image struct {
	Registry string
	Name     string
	Tag      string
	FsLayers []FsLayer
	Token    string
	user     string
	password string
	client   http.Client
}

// FsLayer represents a layer in docker image
type FsLayer struct {
	BlobSum string
}

// ImageV1 represents a Manifest V 2, Schema 1 Docker Image
type imageV1 struct {
	FsLayers []fsLayer
}

// FsLayer represents a layer in a Manifest V 2, Schema 1 Docker Image
type fsLayer struct {
	BlobSum string
}

// imageV2 represents Manifest V 2, Schema 2 Docker Image
type imageV2 struct {
	Layers []layer
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
	client := http.Client{Transport: tr}
	registry := dockerHub
	tag := "latest"
	var nameParts, tagParts []string
	var name, port string
	state := stateInitial
	start := 0
	for i, c := range qname {
		if c == ':' || c == '/' || c == '@' || i == len(qname)-1 {
			if i == len(qname)-1 {
				// ignore a separator, include the last symbol
				i += 1
			}
			part := qname[start:i]
			start = i + 1
			switch state {
			case stateInitial:
				addrs, err := net.LookupHost(part)
				// not a hostname?
				if err != nil || len(addrs) == 0 {
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
				} else {
					// it's registry, let's check what's next =port of image name
					registry = part
					if c == ':' {
						state = statePort
					} else {
						state = stateName
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
	contentType := resp.Header.Get("Content-Type")
	if contentType == "application/vnd.docker.distribution.manifest.v2+json" {
		var imageV2 imageV2
		if err = json.NewDecoder(resp.Body).Decode(&imageV2); err != nil {
			fmt.Fprintln(os.Stderr, "Image V2 decode error")
			return err
		}
		i.FsLayers = make([]FsLayer, len(imageV2.Layers))
		for idx := range imageV2.Layers {
			i.FsLayers[idx].BlobSum = imageV2.Layers[idx].Digest
		}
	} else {
		var imageV1 imageV1
		if err = json.NewDecoder(resp.Body).Decode(&imageV1); err != nil {
			fmt.Fprintln(os.Stderr, "ImageV1 decode error")
			return err
		}
		i.FsLayers = make([]FsLayer, len(imageV1.FsLayers))
		for idx := range imageV1.FsLayers {
			i.FsLayers[idx].BlobSum = imageV1.FsLayers[idx].BlobSum
		}
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
	url := fmt.Sprintf("%s?service=%s&scope=%s&account=%s", realm, service, scope, i.user)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Can't create a request")
		return "", err
	}
	req.SetBasicAuth(i.user, i.password)
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
		req.SetBasicAuth(i.user, i.password)
		i.Token = req.Header.Get("Authorization")
	} else {
		req.Header.Set("Authorization", i.Token)
	}

	// Prefer v2 manifests
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json")

	resp, err := i.client.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Get error")
		return nil, err
	}
	return resp, nil
}

func dumpRequest(r *http.Request) {
	dump, err := httputil.DumpRequest(r, true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Can't dump HTTP request %s\n", err.Error())
	} else {
		fmt.Fprintf(os.Stderr, "request_dump: %s\n", string(dump[:]))
	}
}

func dumpResponse(r *http.Response) {
	dump, err := httputil.DumpResponse(r, true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Can't dump HTTP reqsponse %s\n", err.Error())
	} else {
		fmt.Fprintf(os.Stderr, "response_dump: %s\n", string(dump[:]))
	}
}
