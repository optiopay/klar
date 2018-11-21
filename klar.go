package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/optiopay/klar/clair"
	"github.com/optiopay/klar/docker"
	"github.com/optiopay/klar/utils"

	"gopkg.in/yaml.v2"
)

//Used to represent the structure of the whitelist YAML file
type vulnerabilitiesWhitelistYAML struct {
	General []string
	Images  map[string][]string
}

//Map structure used for ease of searching for whitelisted vulnerabilites
type vulnerabilitiesWhitelist struct {
	General map[string]bool            //key: CVE and value: true
	Images  map[string]map[string]bool //key: image name and value: [key: CVE and value: true]
}

const (
	optionClairOutput      = "CLAIR_OUTPUT"
	optionClairAddress     = "CLAIR_ADDR"
	optionKlarTrace        = "KLAR_TRACE"
	optionClairThreshold   = "CLAIR_THRESHOLD"
	optionClairTimeout     = "CLAIR_TIMEOUT"
	optionDockerTimeout    = "DOCKER_TIMEOUT"
	optionJSONOutput       = "JSON_OUTPUT" // deprecate?
	optionFormatOutput     = "FORMAT_OUTPUT"
	optionDockerUser       = "DOCKER_USER"
	optionDockerPassword   = "DOCKER_PASSWORD"
	optionDockerToken      = "DOCKER_TOKEN"
	optionDockerInsecure   = "DOCKER_INSECURE"
	optionRegistryInsecure = "REGISTRY_INSECURE"
	optionWhiteListFile    = "WHITELIST_FILE"
	optionIgnoreUnfixed    = "IGNORE_UNFIXED"
)

var priorities = []string{"Unknown", "Negligible", "Low", "Medium", "High", "Critical", "Defcon1"}
var formatTypes = []string{"standard", "json", "table"}

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

func parseFormatTypes() (string, error) {
	// until JSON_OUTPUT is actually removed, it should override FORMAT_OUTPUT
	if parseBoolOption(optionJSONOutput) {
		return "json", nil
	}
	formatStyle := formatTypes[0]
	formatOutputEnv := os.Getenv(optionFormatOutput)
	if formatOutputEnv != "" {
		output := strings.ToLower(formatOutputEnv)
		correct := false
		for _, stlye := range formatTypes {
			if stlye == output {
				formatStyle = stlye
				correct = true
				break
			}
		}

		if !correct {
			return "", fmt.Errorf("Format type %s is not supported, only support %v\n", formatOutputEnv, formatTypes)
		}
	}
	return formatStyle, nil
}

type jsonOutput struct {
	LayerCount      int
	Vulnerabilities map[string][]*clair.Vulnerability
}

type config struct {
	ClairAddr     string
	ClairOutput   string
	Threshold     int
	JSONOutput    bool
	FormatStyle   string
	ClairTimeout  time.Duration
	DockerConfig  docker.Config
	WhiteListFile string
	IgnoreUnfixed bool
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

	formatStyle, err := parseFormatTypes()
	if err != nil {
		return nil, err
	}

	return &config{
		ClairAddr:     clairAddr,
		ClairOutput:   clairOutput,
		Threshold:     parseIntOption(optionClairThreshold),
		JSONOutput:    formatStyle == "json",
		FormatStyle:   formatStyle,
		IgnoreUnfixed: parseBoolOption(optionIgnoreUnfixed),
		ClairTimeout:  time.Duration(clairTimeout) * time.Minute,
		WhiteListFile: os.Getenv(optionWhiteListFile),
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

//Parse the whitelist file
func parseWhitelistFile(whitelistFile string) (*vulnerabilitiesWhitelist, error) {
	whitelistYAML := vulnerabilitiesWhitelistYAML{}
	whitelist := vulnerabilitiesWhitelist{}

	//read the whitelist file
	whitelistBytes, err := ioutil.ReadFile(whitelistFile)
	if err != nil {
		return nil, fmt.Errorf("could not read file %v", err)
	}
	if err = yaml.Unmarshal(whitelistBytes, &whitelistYAML); err != nil {
		return nil, fmt.Errorf("could not unmarshal %v", err)
	}

	//Initialize the whitelist maps
	whitelist.General = make(map[string]bool)
	whitelist.Images = make(map[string]map[string]bool)

	//Populate the maps
	for _, cve := range whitelistYAML.General {
		whitelist.General[cve] = true
	}

	for image, cveList := range whitelistYAML.Images {
		whitelist.Images[image] = make(map[string]bool)
		for _, cve := range cveList {
			whitelist.Images[image][cve] = true
		}
	}

	return &whitelist, nil
}
