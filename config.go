package main

import (
	"gopkg.in/yaml.v3"
)

type Data map[string]string
type Repositories []Repository
type Reportsources []Source
type Credentials []Credential

type Configuration struct {
	Repositories  Repositories  `yaml:"repositories"`
	Reportsources Reportsources `yaml:"reportsources"`
	Credentials   Credentials   `yaml:"credentials"`
}

type Repository struct {
	Name               string `yaml:"name,omitempty"`
	URL                string `yaml:"url,omitempty"`
	Credential         string `yaml:"credential,omitempty"`
	TLSVerify          bool   `yaml:"tlsverify,omitempty"`
	PolicyPath         string `yaml:"policyPath,omitempty"`
	RegistriesDirPath  string `yaml:"registriesDirPath,omitempty"`
	RegistriesConfPath string `yaml:"registriesConfPath,omitempty"`
	TmpDir             string `yaml:"tmpDir,omitempty"`
	CfgFile            string `yaml:"cfgFile,omitempty"`
	CommandTimeout     int64  `yaml:"commandTimeout,omitempty"`
}

type Source struct {
	Name       string `yaml:"name,omitempty"`
	URL        string `yaml:"url,omitempty"`
	Credential string `yaml:"credential,omitempty"`
	Parameters string `yaml:"parameters,omitempty"`
	Path       string `yaml:"path,omitempty"`
	Payload    string `yaml:"payload,omitempty"`
	Headers    Data   `yaml:"headers,omitempty"`
}

type Credential struct {
	Name string `yaml:"name,omitempty"`
	Type string `yaml:"type,omitempty"`
	Data Data   `yaml:"data,omitempty"`
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
