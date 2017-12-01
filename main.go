package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/optiopay/klar/clair"
	"github.com/optiopay/klar/docker"
	"github.com/optiopay/klar/utils"
)

type jsonOutput struct {
	LayerCount      int
	Vulnerabilities map[string][]*clair.Vulnerability
}

var priorities = []string{"Unknown", "Negligible", "Low", "Medium", "High", "Critical", "Defcon1"}
var store = make(map[string][]*clair.Vulnerability)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Image name must be provided\n")
		os.Exit(1)
	}

	if os.Getenv("KLAR_TRACE") != "" {
		utils.Trace = true
		os.Setenv("GRPC_TRACE", "all")
		os.Setenv("GRPC_VERBOSITY", "DEBUG")
		os.Setenv("GODEBUG", "http2debug=2")
	}

	clairAddr := os.Getenv("CLAIR_ADDR")
	if clairAddr == "" {
		fmt.Fprintf(os.Stderr, "Clair address must be provided\n")
		os.Exit(1)
	}

	clairOutput := priorities[0]
	outputEnv := os.Getenv("CLAIR_OUTPUT")
	if outputEnv != "" {
		output := strings.Title(strings.ToLower(outputEnv))
		correct := false
		for _, sev := range priorities {
			if sev == output {
				clairOutput = sev
				correct = true
				break
			}
		}

		if !correct {
			fmt.Fprintf(os.Stderr, "Clair output level %s is not supported, only support %v\n", outputEnv, priorities)
			os.Exit(1)
		}
	}

	threshold := 0
	thresholdStr := os.Getenv("CLAIR_THRESHOLD")
	if thresholdStr != "" {
		threshold, _ = strconv.Atoi(thresholdStr)
	}

	dockerUser := os.Getenv("DOCKER_USER")
	dockerPassword := os.Getenv("DOCKER_PASSWORD")

	insecureTLS := false
	if envInsecure, err := strconv.ParseBool(os.Getenv("DOCKER_INSECURE")); err == nil {
		insecureTLS = envInsecure
	}

	insecureRegistry := false
	if envInsecureReg, err := strconv.ParseBool(os.Getenv("REGISTRY_INSECURE")); err == nil {
		insecureRegistry = envInsecureReg
	}

	useJSONOutput := false
	if envJSONOutput, err := strconv.ParseBool(os.Getenv("JSON_OUTPUT")); err == nil {
		useJSONOutput = envJSONOutput
	}

	image, err := docker.NewImage(os.Args[1], dockerUser, dockerPassword, insecureTLS, insecureRegistry)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Can't parse qname: %s\n", err)
		os.Exit(1)
	}

	err = image.Pull()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Can't pull image: %s\n", err)
		os.Exit(1)
	}

	output := jsonOutput{
		Vulnerabilities: make(map[string][]*clair.Vulnerability),
	}

	if len(image.FsLayers) == 0 {
		fmt.Fprintf(os.Stderr, "Can't pull fsLayers\n")
		os.Exit(1)
	} else {
		if useJSONOutput {
			output.LayerCount = len(image.FsLayers)
		} else {
			fmt.Printf("Analysing %d layers\n", len(image.FsLayers))
		}
	}

	var vs []*clair.Vulnerability
	for _, ver := range []int{1, 3} {
		c := clair.NewClair(clairAddr, ver)
		vs, err = c.Analyse(image)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to analyze using API V%d: %s", ver, err)
		} else {
			break
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to analyze, exiting")
		os.Exit(2)
	}

	groupBySeverity(vs)
	vsNumber := 0

	if useJSONOutput {
		iteratePriorities(clairOutput, func(sev string) {
			vsNumber += len(store[sev])
			output.Vulnerabilities[sev] = store[sev]
		})
		enc := json.NewEncoder(os.Stdout)
		enc.Encode(output)
	} else {
		fmt.Printf("Found %d vulnerabilities\n", len(vs))
		iteratePriorities(clairOutput, func(sev string) {
			vsNumber += len(store[sev])
			for _, v := range store[sev] {
				fmt.Printf("%s: [%s] \nFound in: %s\n%s\n%s\n", v.Name, v.Severity, v.FeatureName, v.Description, v.Link)
				fmt.Println("-----------------------------------------")
			}
		})
		iteratePriorities(priorities[0], func(sev string) { fmt.Printf("%s: %d\n", sev, len(store[sev])) })
	}

	if vsNumber > threshold {
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
