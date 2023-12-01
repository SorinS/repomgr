package main

import (
	"gopkg.in/yaml.v3"
)

type Configuration struct {
	Repositories []Repository   `yaml:"repositories"`
	Schedules    []Schedule     `yaml:"schedules"`
	Credentials  []Credential   `yaml:"credentials"`
	ReportSource []ReportSource `yaml:"reportsources"`
}

type Value map[string]string
type Headers map[string]string

type Repository struct {
	Name       string      `yaml:"name,omitempty"`
	URL        interface{} `yaml:"url,omitempty"`
	Credential string      `yaml:"credential,omitempty"`
	Schedule   string      `yaml:"schedule,omitempty"`
}

type Schedule struct {
	Name      string `yaml:"name,omitempty"`
	Interval  string `yaml:"interval,omitempty"`
	Frequency int    `yaml:"frequency,omitempty"`
}

type Credential struct {
	Name  string `yaml:"name,omitempty"`
	Type  string `yaml:"type,omitempty"`
	Value Value  `yaml:"value,omitempty"`
}

type ReportSource struct {
	Name       string  `yaml:"name,omitempty"`
	URL        string  `yaml:"url,omitempty"`
	Credential string  `yaml:"credential,omitempty"`
	Parameters string  `yaml:"parameters,omitempty"`
	Path       string  `yaml:"path,omitempty"`
	Payload    string  `yaml:"payload,omitempty"`
	Headers    Headers `yaml:"headers,omitempty"`
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
