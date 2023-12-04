package main

import (
	"errors"
	"fmt"
	"github.com/containers/common/pkg/auth"
	commonFlag "github.com/containers/common/pkg/flag"
	"io"
	"reflect"
	"time"
)

func GetGlobalOptions(repo *Repository) *globalOptions {
	return &globalOptions{
		debug:              false,
		tlsVerify:          commonFlag.OptionalBool{},
		policyPath:         repo.PolicyPath,
		insecurePolicy:     true, //FIXME: parametrize this
		registriesDirPath:  repo.RegistriesDirPath,
		commandTimeout:     time.Duration(repo.CommandTimeout) * time.Second,
		registriesConfPath: repo.RegistriesConfPath,
		tmpDir:             repo.TmpDir,
		cfgFile:            repo.CfgFile,
	}
}

func Login(cfg *Configuration, repo *Repository, args []string, stdout io.Writer) error {
	user, pwd, err := GetRepoCreds(repo, cfg)
	if err != nil {
		return errors.New(fmt.Sprintf("unable to get credentials from: %s", repo.Credential))
	}

	optsGlobal := GetGlobalOptions(repo)

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
		AcceptUnspecifiedRegistry: false,
		NoWriteBack:               false,
	}

	opts := &loginOptions{
		global:    optsGlobal,
		loginOpts: optsAuthLogin,
		tlsVerify: commonFlag.OptionalBool{},
	}

	return opts.run(args, stdout)

}

func Logout(cfg *Configuration, repo *Repository, args []string, stdout io.Writer) error {
	optsGlobal := GetGlobalOptions(repo)
	optsLogout := auth.LogoutOptions{
		AuthFile:                  "",
		DockerCompatAuthFile:      "",
		All:                       false,
		AcceptRepositories:        false,
		Stdout:                    nil,
		AcceptUnspecifiedRegistry: true,
	}
	opts := logoutOptions{
		global:     optsGlobal,
		logoutOpts: optsLogout,
		tlsVerify:  commonFlag.OptionalBool{},
	}
	return opts.run(args, stdout)

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
