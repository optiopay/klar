package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/optiopay/klar/clair"
	"github.com/optiopay/klar/docker"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Image name must be provided")
		os.Exit(1)
	}

	clairAddr := os.Getenv("CLAIR_ADDR")
	if clairAddr == "" {
		clairAddr = "https://clair-staging.optiopay.com"
	}

	threshold := 0
	thresholdStr := os.Getenv("CLAIR_THRESHOLD")
	if thresholdStr != "" {
		threshold, _ = strconv.Atoi(thresholdStr)
	}

	image, err := docker.NewImage(os.Args[1])
	if err != nil {
		fmt.Printf("Can't parse qname: %s", err)
		os.Exit(1)
	}

	err = image.Pull()
	if err != nil {
		fmt.Printf("Can't pull image: %s", err)
		os.Exit(1)
	}
	if len(image.FsLayers) == 0 {
		fmt.Printf("Can't pull fsLayers")
		os.Exit(1)
	} else {
		fmt.Printf("Analysing %d layers\n", len(image.FsLayers))
	}

	c := clair.NewClair(clairAddr)
	vs, err := c.Analyse(image)
	highSevs := make([]clair.Vulnerability, 0)
	for _, v := range *vs {
		if v.Severity == "High" {
			highSevs = append(highSevs, v)
		}
	}
	fmt.Printf("Found %d vulnerabilities \n", len(*vs))
	fmt.Printf("High severity: %d\n", len(highSevs))
	if len(highSevs) > threshold {
		os.Exit(1)
	}
}
