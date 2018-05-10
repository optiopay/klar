package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/optiopay/klar/clair"
	"github.com/optiopay/klar/docker"
)

var store = make(map[string][]*clair.Vulnerability)

func main() {
	fail := func(format string, a ...interface{}) {
		fmt.Fprintf(os.Stderr, fmt.Sprintf("%s\n", format), a...)
		os.Exit(1)
	}

	if len(os.Args) != 2 {
		fail("Image name must be provided")
	}

	conf, err := newConfig(os.Args)
	if err != nil {
		fail("Invalid options: %s", err)
	}

	fmt.Fprintf(os.Stderr, "clair timeout %s\n", conf.ClairTimeout)
	fmt.Fprintf(os.Stderr, "docker timeout: %s\n", conf.DockerConfig.Timeout)
	
	whitelist := &vulnerabilitiesWhitelist{}
	if (conf.WhiteListFile != "") {
		fmt.Fprintf(os.Stderr, "whitelist file: %s\n", conf.WhiteListFile)
		whitelist, err = parseWhitelistFile(conf.WhiteListFile)
		if err != nil {
			fail("Could not parse whitelist file: %s", err)
		}
	} else {
		fmt.Fprintf(os.Stderr, "no whitelist file\n")
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

	//remove duplicates
	vs = deDupe(vs);

	//apply whitelist
    numVulnerabilites := len(vs)
	vs = filterWhitelist(whitelist,vs)
	numVulnerabilitiesAfterWhitelist := len(vs)
	
	groupBySeverity(vs)
	vsNumber := 0

	if conf.JSONOutput {
		iteratePriorities(conf.ClairOutput, func(sev string) {
			vsNumber += len(store[sev])
			output.Vulnerabilities[sev] = store[sev]
		})
		enc := json.NewEncoder(os.Stdout)
		enc.Encode(output)
	} else {
		if numVulnerabilitiesAfterWhitelist < numVulnerabilites {
			//display how many vulnerabilities were whitelisted
			fmt.Printf("Whitelisted %d vulnerabilities\n", numVulnerabilites - numVulnerabilitiesAfterWhitelist)
		}
		fmt.Printf("Found %d vulnerabilities\n", len(vs))
		iteratePriorities(priorities[0], func(sev string) { fmt.Printf("%s: %d\n", sev, len(store[sev])) })
		fmt.Printf("\n")
		
		iteratePriorities(conf.ClairOutput, func(sev string) {
			vsNumber += len(store[sev])
			for _, v := range store[sev] {
				fmt.Printf("%s: [%s] \nFound in: %s [%s]\nFixed By: %s\n%s\n%s\n", v.Name, v.Severity, v.FeatureName, v.FeatureVersion, v.FixedBy, v.Description, v.Link)
				fmt.Println("-----------------------------------------")
			}
		})
		
	}

	if vsNumber > conf.Threshold {
		os.Exit(1)
	}
}

func iteratePriorities(output string, f func(sev string)) {
	filtered := true
	for _, sev := range priorities {
		if filtered {
			if sev != output {
				continue
			} else {
				filtered = false
			}
		}

		if len(store[sev]) != 0 {
			f(sev)
		}
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
func filterWhitelist(whitelist *vulnerabilitiesWhitelist, vs []*clair.Vulnerability) []*clair.Vulnerability {
	generalWhitelist := (*whitelist).General
	imageWhitelist := (*whitelist).Images
	
	filteredVs := make([]*clair.Vulnerability, 0, len(vs))
	
	for _, v := range vs {
		if _, exists := generalWhitelist[v.Name]; !exists {
			//vulnerability is not in the general whitelist, so get the image name by removing ":version" from the value returned via the Clair API
			imageName := strings.Split(v.NamespaceName, ":")[0]
			if _, exists := imageWhitelist[imageName][v.Name]; !exists {
				//vulnerability is not in the image whitelist, so add it to the list to return
				filteredVs = append(filteredVs, v)
			}
		}
	}
	
	return filteredVs
}

//Remove duplicates
func deDupe(vs []*clair.Vulnerability) []*clair.Vulnerability {
	deDupedVs := make([]*clair.Vulnerability, 0, len(vs))
	
	//Use a map to store found vulnerabilities
	foundVulnerabilites := make(map[string]bool)
	
	for _, v := range vs {
		//use a combination of vulnerability name, feature name, and feature version to uniquely identify a vulnerability for deduping
		if _, exists := foundVulnerabilites[ strings.Join([]string{v.Name,v.FeatureName,v.FeatureVersion},"") ]; !exists {
			//vulnerability has not been encountered yet, so add it to the list and mark it as found in the map
			deDupedVs = append(deDupedVs, v)
			foundVulnerabilites[ strings.Join([]string{v.Name,v.FeatureName,v.FeatureVersion},"") ] = true
		}
	}
	
	return deDupedVs
}
	
	