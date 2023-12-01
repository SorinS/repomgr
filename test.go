package main

import (
	"errors"
	"fmt"
	"io"
)

type testOptions struct {
	global *globalOptions
}

func (test *testOptions) run(args []string, stdout io.Writer) error {
	fmt.Fprintf(stdout, "test invoked\n")
	cfgFile := test.global.cfgFile
	if cfgFile == "" {
		return errors.New("no configuration file passed")
	}
	cfg, err := parseConfig(cfgFile)
	if err != nil {
		fmt.Fprintf(stdout, "parsing the config file: %s, resulted in error: %v\n", cfgFile, err)
		return err
	}
	fmt.Fprintf(stdout, "Found: %d credentials\n", len(cfg.Credentials))
	fmt.Fprintf(stdout, "Found: %d repositories\n", len(cfg.Repositories))
	fmt.Fprintf(stdout, "Found: %d report sources\n", len(cfg.Reportsources))

	for _, cred := range cfg.Credentials {
		fmt.Printf("Cred Name: %s\n", cred.Name)
		fmt.Printf("Credential value: %s\n", getCredential(&cred))
	}

	for _, repo := range cfg.Repositories {
		fmt.Fprintf(stdout, "Repo: %s\n", repo.Name)
	}

	return nil
}
