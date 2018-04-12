package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/optiopay/klar/clair"
	"github.com/optiopay/klar/docker"
	"github.com/optiopay/klar/utils"
)

const (
	optionClairOutput      = "CLAIR_OUTPUT"
	optionClairAddress     = "CLAIR_ADDR"
	optionKlarTrace        = "KLAR_TRACE"
	optionClairThreshold   = "CLAIR_THRESHOLD"
	optionClairTimeout     = "CLAIR_TIMEOUT"
	optionDockerTimeout    = "DOCKER_TIMEOUT"
	optionJSONOutput       = "JSON_OUTPUT"
	optionDockerUser       = "DOCKER_USER"
	optionDockerPassword   = "DOCKER_PASSWORD"
	optionDockerToken      = "DOCKER_TOKEN"
	optionDockerInsecure   = "DOCKER_INSECURE"
	optionRegistryInsecure = "REGISTRY_INSECURE"
)

var priorities = []string{"Unknown", "Negligible", "Low", "Medium", "High", "Critical", "Defcon1"}

func parseOutputPriority() (string, error) {
	clairOutput := priorities[0]
	outputEnv := os.Getenv(optionClairOutput)
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
			return "", fmt.Errorf("Clair output level %s is not supported, only support %v\n", outputEnv, priorities)
		}
	}
	return clairOutput, nil
}

func parseIntOption(key string) int {
	val := 0
	valStr := os.Getenv(key)
	if valStr != "" {
		val, _ = strconv.Atoi(valStr)
	}
	return val
}

func parseBoolOption(key string) bool {
	val := false
	if envVal, err := strconv.ParseBool(os.Getenv(key)); err == nil {
		val = envVal
	}
	return val
}

type jsonOutput struct {
	LayerCount      int
	Vulnerabilities map[string][]*clair.Vulnerability
}

type config struct {
	ClairAddr    string
	ClairOutput  string
	Threshold    int
	JSONOutput   bool
	ClairTimeout time.Duration
	DockerConfig docker.Config
}

func newConfig(args []string) (*config, error) {
	clairAddr := os.Getenv(optionClairAddress)
	if clairAddr == "" {
		return nil, fmt.Errorf("Clair address must be provided\n")
	}

	if os.Getenv(optionKlarTrace) != "" {
		utils.Trace = true
	}

	clairOutput, err := parseOutputPriority()
	if err != nil {
		return nil, err
	}

	clairTimeout := parseIntOption(optionClairTimeout)
	if clairTimeout == 0 {
		clairTimeout = 1
	}

	dockerTimeout := parseIntOption(optionDockerTimeout)
	if dockerTimeout == 0 {
		dockerTimeout = 1
	}

	return &config{
		ClairAddr:    clairAddr,
		ClairOutput:  clairOutput,
		Threshold:    parseIntOption(optionClairThreshold),
		JSONOutput:   parseBoolOption(optionJSONOutput),
		ClairTimeout: time.Duration(clairTimeout) * time.Minute,
		DockerConfig: docker.Config{
			ImageName:        args[1],
			User:             os.Getenv(optionDockerUser),
			Password:         os.Getenv(optionDockerPassword),
			Token:            os.Getenv(optionDockerToken),
			InsecureTLS:      parseBoolOption(optionDockerInsecure),
			InsecureRegistry: parseBoolOption(optionRegistryInsecure),
			Timeout:          time.Duration(dockerTimeout) * time.Minute,
		},
	}, nil
}
