package main

import (
	"fmt"
	"strings"
)

func getCredential(cred *Credential) string {
	switch strings.ToLower(cred.Type) {
	case "vault":
		return "vault"
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
		return ""
	}

}
