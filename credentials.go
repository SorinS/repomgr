package main

import (
	"errors"
	"fmt"
	"strings"
)

func GetCredential(cred *Credential) string {
	switch strings.ToLower(cred.Type) {
	case "vault":
		//FIXME: Just returning the content of the secret access config here
		return MapToString(cred.Data, IdentStr, IdentStr)
	case "basic":
		var user, password string
		for key, value := range cred.Data {
			if strings.ToLower(key) == "user" {
				user = value
			}
			if strings.ToLower(key) == "password" {
				password = value
			}
		}
		return fmt.Sprintf("%s:%s", user, password)
	default:
		return ":"
	}

}

func GetVaultCreds(secretData string, secretType string) (string, string, error) {
	switch secretType {
	case "KV":
		return "", "", errors.New("not implemented")
	case "AD":
		return "", "", errors.New("not implemented")
	default:
		return "", "", errors.New("not implemented")
	}

}

func GetBasicCreds(basic string) (string, string, error) {
	s := strings.Split(basic, ":")
	if len(s) > 1 {
		return s[0], s[1], nil
	}
	return "", "", errors.New("invalid basic secret")
}

func GetCredByName(credName string, cfg *Configuration) *Credential {
	for _, cred := range cfg.Credentials {
		if cred.Name == credName {
			return &cred
		}
	}
	return nil
}
