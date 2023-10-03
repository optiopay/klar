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
	allowlist := &vulnerabilitiesAllowlist{}
	if conf.AllowListFile != "" {
		if !conf.JSONOutput {
			fmt.Fprintf(os.Stderr, "allowlist file: %s\n", conf.AllowListFile)
		}
		allowlist, err = parseAllowlistFile(conf.AllowListFile)
		if err != nil {
			fail("Could not parse allowlist file: %s", err)
		}
	} else {
		if !conf.JSONOutput {
			fmt.Fprintf(os.Stderr, "no allowlist file\n")
		}
	}

	image, err := docker.NewImage(&conf.DockerConfig)
	if err != nil {
		fail("Can't parse name: %s", err)
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
	vs = filterAllowlist(allowlist, vs, image.Name)
	numVulnerabilitiesAfterAllowlist := len(vs)
	groupBySeverity(vs)

	if conf.JSONOutput {
		vsNumber = jsonFormat(conf, output)
	} else {
		if numVulnerabilitiesAfterAllowlist < numVulnerabilites {
			//display how many vulnerabilities were allowlisted
			fmt.Printf("Allowlisted %d vulnerabilities\n", numVulnerabilites-numVulnerabilitiesAfterAllowlist)
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

//Filter out allowlisted vulnerabilites
func filterAllowlist(allowlist *vulnerabilitiesAllowlist, vs []*clair.Vulnerability, imageName string) []*clair.Vulnerability {
	generalAllowlist := allowlist.General
	imageAllowlist := allowlist.Images

	filteredVs := make([]*clair.Vulnerability, 0, len(vs))

	for _, v := range vs {
		if _, exists := generalAllowlist[v.Name]; !exists {
			if _, exists := imageAllowlist[imageName][v.Name]; !exists {
				//vulnerability is not in the image allowlist, so add it to the list to return
				filteredVs = append(filteredVs, v)
			}
		}
	}

	return filteredVs
}
