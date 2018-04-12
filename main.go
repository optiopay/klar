package main

import (
	"encoding/json"
	"fmt"
	"os"

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
		fmt.Printf("Found %d vulnerabilities\n", len(vs))
		iteratePriorities(conf.ClairOutput, func(sev string) {
			vsNumber += len(store[sev])
			for _, v := range store[sev] {
				fmt.Printf("%s: [%s] \nFound in: %s\n%s\n%s\n", v.Name, v.Severity, v.FeatureName, v.Description, v.Link)
				fmt.Println("-----------------------------------------")
			}
		})
		iteratePriorities(priorities[0], func(sev string) { fmt.Printf("%s: %d\n", sev, len(store[sev])) })
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
