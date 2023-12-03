package main

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/containers/common/pkg/auth"
	commonFlag "github.com/containers/common/pkg/flag"
	"reflect"
)

func Login(cfg *Configuration, repoName string, args []string, buf *bytes.Buffer) error {
	repo := GetRepoByName(repoName, cfg)

	if repo == nil {
		return errors.New(fmt.Sprintf("repository named: %s is not configured", repoName))
	}

	optsGlobal := &globalOptions{
		debug:              false,
		tlsVerify:          commonFlag.OptionalBool{},
		policyPath:         "",
		insecurePolicy:     true,
		registriesDirPath:  "",
		commandTimeout:     0,
		registriesConfPath: "",
		tmpDir:             "",
		cfgFile:            "",
	}

	optsAuthLogin := auth.LoginOptions{
		AuthFile:                  "",
		DockerCompatAuthFile:      "",
		CertDir:                   "",
		Password:                  "",
		Username:                  "",
		StdinPassword:             false,
		GetLoginSet:               false,
		Verbose:                   false,
		AcceptRepositories:        false,
		AcceptUnspecifiedRegistry: true,
		NoWriteBack:               false,
	}

	opts := &loginOptions{
		global:    optsGlobal,
		loginOpts: optsAuthLogin,
		tlsVerify: NewOptionalBool(repo.TLSVerify),
	}

	return opts.run(args, buf)

}

func Logout(cfg *Configuration, repoName string, args []string, buf *bytes.Buffer) error {
	return errors.New("not implemented")
}

func GetRepoByName(repoName string, cfg *Configuration) *Repository {
	for _, repo := range cfg.Repositories {
		if repo.Name == repoName {
			return &repo
		}
	}
	return nil
}

func NewOptionalBool(val bool) commonFlag.OptionalBool {
	ob := commonFlag.OptionalBool{} // Initially, both present and value are false
	if val {
		reflect.ValueOf(&ob).Elem().FieldByName("present").SetBool(true)
		reflect.ValueOf(&ob).Elem().FieldByName("value").SetBool(true)
	}
	return ob
}
