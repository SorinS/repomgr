package main

import (
	"gopkg.in/yaml.v3"
)

type Configuration struct {
	Repositories []Repositories `yaml:"repositories"`
	Rules        []Rules        `yaml:"rules"`
	Constraints  []Constraints  `yaml:"constraints"`
	Schedules    []Schedules    `yaml:"schedules"`
	Credentials  []Credentials  `yaml:"credentials"`
}

type Repository struct {
	Name       string      `yaml:"name,omitempty"`
	URL        interface{} `yaml:"url,omitempty"`
	Credential string      `yaml:"credential,omitempty"`
	Rules      string      `yaml:"rules,omitempty"`
	Schedule   string      `yaml:"schedule,omitempty"`
}

type Rule struct {
	Name        string   `yaml:"name,omitempty"`
	Constraints []string `yaml:"constraints,omitempty"`
}

type Constraint struct {
	Name       string `yaml:"name,omitempty"`
	Expression string `yaml:"expression,omitempty"`
	Action     string `yaml:"action,omitempty"`
}

type Schedule struct {
	Name      string `yaml:"name,omitempty"`
	Interval  string `yaml:"interval,omitempty"`
	Frequency int    `yaml:"frequency,omitempty"`
}

type Value map[string]string

type Credential struct {
	Name  string `yaml:"name,omitempty"`
	Type  string `yaml:"type,omitempty"`
	Value Value  `yaml:"value,omitempty"`
}

type Repositories struct {
	Repository []Repository `yaml:"repository"`
}

type Constraints struct {
	Constraint []Constraint `yaml:"constraint"`
}

type Rules struct {
	Rule []Rule `yaml:"rule"`
}

type Schedules struct {
	Schedule []Schedule `yaml:"schedule"`
}

type Credentials struct {
	Credential []Credential `yaml:"credential"`
}

func parseConfig(cfgFilePath string) (*Configuration, error) {
	var config Configuration
	yamlData, err := ReadFileContent(cfgFilePath)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal([]byte(yamlData), &config)
	if err != nil {
		return nil, err
	}
	return &config, nil
}
