package main

import (
	"fmt"
	"os"

	"github.com/optiopay/klar/clair"
	"github.com/optiopay/klar/docker"
)

var store = make(map[string][]*clair.Vulnerability)

func main() {
	fail := func(format string, a ...interface{}) {
		fmt.Fprintf(os.Stderr, fmt.Sprintf("%s\n", format), a...)
		os.Exit(2)
	}

	if len(os.Args) != 2 {
		fail("Image name must be provided")
	}

	conf, err := newConfig(os.Args)
	if err != nil {
		fail("Invalid options: %s", err)
	}

	if !conf.JSONOutput {
		fmt.Fprintf(os.Stderr, "clair timeout %s\n", conf.ClairTimeout)
		fmt.Fprintf(os.Stderr, "docker timeout: %s\n", conf.DockerConfig.Timeout)
	}
	whitelist := &vulnerabilitiesWhitelist{}
	if conf.WhiteListFile != "" {
		if !conf.JSONOutput {
			fmt.Fprintf(os.Stderr, "whitelist file: %s\n", conf.WhiteListFile)
		}
		whitelist, err = parseWhitelistFile(conf.WhiteListFile)
		if err != nil {
			fail("Could not parse whitelist file: %s", err)
		}
	} else {
		if !conf.JSONOutput {
			fmt.Fprintf(os.Stderr, "no whitelist file\n")
		}
	}

	image, err := docker.NewImage(&conf.DockerConfig)
	if err != nil {
		fail("Can't parse qname: %s", err)
	}

	err = image.Pull()
	if err != nil {
		fail("Can't pull image: %s", err)
	}

	output := jsonOutput{
		Vulnerabilities: make(map[string][]*clair.Vulnerability),
	}

	if len(image.FsLayers) == 0 {
		fail("Can't pull fsLayers")
	} else {
		if conf.JSONOutput {
			output.LayerCount = len(image.FsLayers)
		} else {
			fmt.Printf("Analysing %d layers\n", len(image.FsLayers))
		}
	}

	var vs []*clair.Vulnerability
	for _, ver := range []int{1, 3} {
		c := clair.NewClair(conf.ClairAddr, ver, conf.ClairTimeout)
		vs, err = c.Analyse(image)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to analyze using API v%d: %s\n", ver, err)
		} else {
			if !conf.JSONOutput {
				fmt.Printf("Got results from Clair API v%d\n", ver)
			}
			break
		}
	}
	if err != nil {
		fail("Failed to analyze, exiting")
	}

	vsNumber := 0

	numVulnerabilites := len(vs)
	vs = filterWhitelist(whitelist, vs, image.Name)
	numVulnerabilitiesAfterWhitelist := len(vs)
	groupBySeverity(vs)

	if conf.JSONOutput {
		vsNumber = jsonFormat(conf, output)
	} else {
		if numVulnerabilitiesAfterWhitelist < numVulnerabilites {
			//display how many vulnerabilities were whitelisted
			fmt.Printf("Whitelisted %d vulnerabilities\n", numVulnerabilites-numVulnerabilitiesAfterWhitelist)
		}
		fmt.Printf("Found %d vulnerabilities\n", len(vs))
		switch style := conf.FormatStyle; style {
		case "table":
			vsNumber = tableFormat(conf, vs)
		default:
			vsNumber = standardFormat(conf, vs)
		}
	}

	if vsNumber > conf.Threshold {
		os.Exit(1)
	}
}

func groupBySeverity(vs []*clair.Vulnerability) {
	for _, v := range vs {
		sevRow := vulnsBy(v.Severity, store)
		store[v.Severity] = append(sevRow, v)
	}
}

func vulnsBy(sev string, store map[string][]*clair.Vulnerability) []*clair.Vulnerability {
	items, found := store[sev]
	if !found {
		items = make([]*clair.Vulnerability, 0)
		store[sev] = items
	}
	return items
}

//Filter out whitelisted vulnerabilites
func filterWhitelist(whitelist *vulnerabilitiesWhitelist, vs []*clair.Vulnerability, imageName string) []*clair.Vulnerability {
	generalWhitelist := whitelist.General
	imageWhitelist := whitelist.Images

	filteredVs := make([]*clair.Vulnerability, 0, len(vs))

	for _, v := range vs {
		if _, exists := generalWhitelist[v.Name]; !exists {
			if _, exists := imageWhitelist[imageName][v.Name]; !exists {
				//vulnerability is not in the image whitelist, so add it to the list to return
				filteredVs = append(filteredVs, v)
			}
		}
	}

	return filteredVs
}
