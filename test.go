package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"time"
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
	return repoLoging("nexus1", cfg)

}

func repoLoging(repoName string, cfg *Configuration) error {
	repo := GetRepoByName(repoName, cfg)
	if repo == nil {
		return errors.New("non-existing repository configuration")
	}
	buf := new(bytes.Buffer)
	if err := Login(cfg, repo, []string{repo.URL}, buf); err != nil {
		fmt.Printf("failure: error: %v, stdout: %s\n\n", err, buf.String())
		return err
	}
	fmt.Printf("login success: %s\n\n", buf.String())
	time.Sleep(1 * time.Second)
	fmt.Printf("logging out of: %s\n", repoName)
	if err := Logout(cfg, repo, []string{repo.URL}, buf); err != nil {
		fmt.Printf("failure: error: %v, stdout: %s\n\n", err, buf.String())
		return err
	}
	fmt.Printf("logout success: %s\n\n", buf.String())
	return nil
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
