package main

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/containers/common/pkg/auth"
	commonFlag "github.com/containers/common/pkg/flag"
	"io"
	"reflect"
	"time"
)

func Login(cfg *Configuration, repoName string, args []string, stdout io.Writer) error {
	repo := GetRepoByName(repoName, cfg)

	if repo == nil {
		return errors.New(fmt.Sprintf("repository named: %s is not configured", repoName))
	}

	user, pwd, err := GetRepoCreds(repo, cfg)
	if err != nil {
		return errors.New(fmt.Sprintf("unable to get credentials from: %s", repo.Credential))
	}

	optsGlobal := &globalOptions{
		debug:              false,
		tlsVerify:          commonFlag.OptionalBool{},
		policyPath:         repo.PolicyPath,
		insecurePolicy:     true,
		registriesDirPath:  repo.RegistriesDirPath,
		commandTimeout:     time.Duration(repo.CommandTimeout) * time.Second,
		registriesConfPath: repo.RegistriesConfPath,
		tmpDir:             repo.TmpDir,
		cfgFile:            repo.CfgFile,
	}

	optsAuthLogin := auth.LoginOptions{
		AuthFile:                  "",
		DockerCompatAuthFile:      "",
		CertDir:                   "",
		Password:                  pwd,
		Username:                  user,
		StdinPassword:             false,
		GetLoginSet:               false,
		Verbose:                   true,
		AcceptRepositories:        true,
		AcceptUnspecifiedRegistry: true,
		NoWriteBack:               false,
	}

	opts := &loginOptions{
		global:    optsGlobal,
		loginOpts: optsAuthLogin,
		tlsVerify: NewOptionalBool(repo.TLSVerify),
	}

	return opts.run(args, stdout)

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

func GetRepoCreds(repo *Repository, cfg *Configuration) (string, string, error) {
	cred := GetCredByName(repo.Credential, cfg)
	if cred == nil {
		return "", "", errors.New("unable to find the repo credentials")
	}
	return GetBasicCreds(GetCredential(cred))
}
