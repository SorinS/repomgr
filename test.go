package main

import (
	"bytes"
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
	printConfig(cfg, stdout)

	buf := new(bytes.Buffer)
	err = repoLogin(cfg, buf)
	if err != nil {
		fmt.Printf("error logging in: %v, stdout: %s", err, buf.String())
	} else {
		fmt.Printf("success: %s", buf.String())
	}

	return nil
}

func repoLogin(cfg *Configuration, stdout io.Writer) error {
	return Login(cfg, "nexus1", []string{}, stdout)
}

func printConfig(cfg *Configuration, stdout io.Writer) {
	fmt.Fprintf(stdout, "Found: %d credentials\n", len(cfg.Credentials))
	fmt.Fprintf(stdout, "Found: %d repositories\n", len(cfg.Repositories))
	fmt.Fprintf(stdout, "Found: %d report sources\n", len(cfg.Reportsources))
	fmt.Fprintf(stdout, "---------\n\n")
	fmt.Fprintf(stdout, "==== Credentials ====\n\n")
	for _, cred := range cfg.Credentials {
		fmt.Printf("Cred Name: %s\n", cred.Name)
		fmt.Printf("Credential value: %s\n", GetCredential(&cred))
	}
	fmt.Fprintf(stdout, "---------\n\n")
	fmt.Fprintf(stdout, "==== Repositories ====\n\n")
	for _, repo := range cfg.Repositories {
		fmt.Fprintf(stdout, "name=%s\n", repo.Name)
		fmt.Fprintf(stdout, "url=%s\n", repo.URL)
		fmt.Fprintf(stdout, "tlsverify=%t\n", repo.TLSVerify)
		fmt.Fprintf(stdout, "policyPath=%s\n", repo.PolicyPath)
		fmt.Fprintf(stdout, "registriesDirPath=%s\n", repo.RegistriesDirPath)
		fmt.Fprintf(stdout, "registriesConfPath=%s\n", repo.RegistriesConfPath)
		fmt.Fprintf(stdout, "tmpDir=%s\n", repo.TmpDir)
		fmt.Fprintf(stdout, "cfgFile=%s\n", repo.CfgFile)
		fmt.Fprintf(stdout, "commandTimeout=%d\n", repo.CommandTimeout)
		fmt.Fprintf(stdout, "------\n\n")
	}

}
