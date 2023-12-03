package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"net/http"
	"net/url"
	"repomgr/hashicorp"
	"strings"
)

const AWSRegionMetaDataUrl = "http://169.254.169.254/latest/meta-data/placement/reqion"

type JWTAuth struct {
	Role string `json:"role"`
	Jwt  string `json:"jwt"`
}

func GetMidJWT(port int, appName, bamEnv string) (int, []byte, error) {
	SetIfEmpty(&appName, "CSM_PROD")
	SetIfEmpty(&bamEnv, "PROD")
	SetIfEmpty(&port, 3002)
	midUrl, err := url.Parse(fmt.Sprintf("%s:%d", "http://127.0.0.1", port))
	if err != nil {
		return 500, []byte{}, err
	}
	return SendHTTPRequest(
		true,
		"",
		"GET",
		*midUrl,
		[]byte{},
		make(http.Header))
}

func AWSLoginPayload(env, awsRegion string) (map[string]interface{}, error) {
	awsEndpoint := fmt.Sprintf("%s.%s.%s", "https://sts.", awsRegion, ".amazonaws.com")
	SetIfEmpty(&awsRegion, "us-east-1")
	SetIfEmpty(&env, "CSM_PROD")
	sess, err := session.NewSession(&aws.Config{
		Region:   aws.String(awsRegion),
		Endpoint: aws.String(awsEndpoint),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create AWS session")
	}

	svc := sts.New(sess)
	req, _ := svc.GetCallerIdentityRequest(&sts.GetCallerIdentityInput{})
	req.HTTPRequest.Header.Add("X-Vault-AWS-IAM-Server-ID", strings.ToUpper(env))

	err = req.Sign()
	if err != nil {
		return nil, fmt.Errorf("failed to sign the AWS requestn")
	}

	headers, _ := json.Marshal(req.HTTPRequest.Header)
	body, _ := json.Marshal(req.HTTPRequest.Body)

	stsData := make(map[string]interface{})
	stsData["iam_http_request_method"] = req.HTTPRequest.Method
	stsData["iam_request_url"] = base64.StdEncoding.EncodeToString([]byte(req.HTTPRequest.URL.String()))
	stsData["iam_request_headers"] = base64.StdEncoding.EncodeToString(headers)
	stsData["iam_request_body"] = base64.StdEncoding.EncodeToString(body)

	return stsData, nil
}

func GetBVPAuthMaterial(port int) (string, error) {
	SetIfEmpty(&port, 3002)
	status, jwt, err := GetMidJWT(port, "", "")
	if err == nil && status/100 == 2 {
		return string(jwt), err
	}
	status, jwt, err = GetMidJWT(port+1, "", "")
	if err != nil || status/100 != 2 {
		return "", err
	}
	return string(jwt), err
}

func GetAWSRegion(regionUrl, truststoreDir string, skipSSLVerify bool) (string, error) {
	awsRegionURL, err := url.Parse(regionUrl)
	if err != nil {
		return "", err
	}
	status, response, err := SendHTTPRequest(skipSSLVerify, truststoreDir, "GET", *awsRegionURL, []byte{}, make(http.Header))
	if err != nil {
		return "", errors.New("the current binary might not be in AWS")
	}

	if status/100 != 2 {
		return "", errors.New("non 2xx status received, body: " + string(response))
	}

	return string(response), nil
}

func GetAWSInstanceId(instanceURL, truststoreDir string, skipSSLVerify bool) (string, error) {
	awsInstanceURL, err := url.Parse(instanceURL)
	if err != nil {
		return "", err
	}

	status, response, err := SendHTTPRequest(skipSSLVerify, truststoreDir, "GET", *awsInstanceURL, []byte{}, make(http.Header))
	if err != nil {
		return "", err
	}

	if status/100 != 2 {
		return "", errors.New("non 2xx status received, body: " + string(response))
	}

	return string(response), nil
}

func GetAWSAuthMaterial(env, region, role string) (string, error) {
	awsPayload, err := AWSLoginPayload(env, region)
	if err != nil {
		return "", err
	}
	var buffer bytes.Buffer
	buffer.WriteString("\n")
	for k, v := range awsPayload {
		buffer.WriteString(fmt.Sprintf("\"%s\": \"%s\",\n", k, v))
	}
	buffer.WriteString(fmt.Sprintf("\"role\": \"%s\"\n", role))
	return buffer.String(), nil
}

func GetSecretRoleType(secretConfig map[string]string) string {
	return secretConfig["ROLE_TYPE"]
}

func BVPLogin(port int, config map[string]string) ([]byte, string, error) {
	jwt, err := GetBVPAuthMaterial(port)
	if err != nil {
		return []byte{}, "bvp", errors.New("unable to get a MID JWT token")
	}
	jwtAuth := JWTAuth{
		Role: config["ROLE_NAME"],
		Jwt:  string(jwt),
	}
	payload, _ := json.Marshal(jwtAuth)
	authURL, _ := url.Parse(config["AUTH_URL"])
	status, response, err := SendHTTPRequest(true, "", "POST", *authURL, payload, make(http.Header))
	if err != nil {
		return []byte{}, "bvp", err
	}
	if status/100 != 2 {
		return []byte{}, "bvp", errors.New(fmt.Sprintf("non-2xx status returned, error: %v, body: %s", err, string(response)))
	}
	return response, "bvp", nil
}

func AWSLogin(config map[string]string) ([]byte, string, error) {
	authMaterial, err := GetAWSAuthMaterial("", "", config["ROLE_NAME"])
	if err != nil {
		return []byte{}, "aws", err
	}
	authUrl, err := url.Parse(config["AUTH_URL"])
	if err != nil {
		return []byte{}, "aws", err
	}
	headers := make(map[string][]string)
	headers["Content-Type"] = []string{"application/json"}

	status, respBody, err := SendHTTPRequest(true, "", "POST", *authUrl, []byte(authMaterial), headers)
	if err != nil {
		return []byte{}, "aws", err
	}
	if status/100 != 2 {
		return []byte{}, "aws", errors.New(fmt.Sprintf("non-2xx response received, error: %v, body: %s\n", err, string(respBody)))
	}
	return respBody, "aws", nil
}

func GetToken(loginData []byte) (string, error) {
	loginResponse := hashicorp.Secret{}
	err := json.Unmarshal(loginData, &loginResponse)
	if err != nil {
		return "", err
	}
	return loginResponse.Auth.ClientToken, nil
}

func BVPSecret(port int, config map[string]string) (string, string, error) {
	err := CheckNotEmpty(config["AUTH_URL"], config["ROLE_TYPE"], config["SECRET_URL"], config["ROLE_NAME"])
	if err != nil {
		return "", "bvp", errors.New("invalid secret access config")
	}
	loginData, secretType, err := BVPLogin(port, config)
	if err != nil {
		return "", secretType, err
	}
	token, err := GetToken(loginData)
	if err != nil {
		return "", secretType, err
	}
	secretHeaders := make(http.Header)
	secretHeaders.Add("X-Vault-Token", token)

	secretURL, err := url.Parse(config["SECRET_URL"])
	if err != nil {
		return "", secretType, err
	}
	status, resp, err := SendHTTPRequest(true, "", "GET", *secretURL, []byte{}, secretHeaders)
	if err != nil {
		return "", secretType, err
	}
	if status/100 != 2 {
		return "", secretType, errors.New("non-2xx status received")
	}
	return string(resp), secretType, nil
}

func AWSSecret(config map[string]string) (string, string, error) {
	err := CheckNotEmpty(config["AUTH_URL"], config["ROLE_TYPE"], config["SECRET_URL"], config["ROLE_NAME"])
	if err != nil {
		return "", "aws", errors.New("invalid secret access config")
	}
	loginData, secretType, err := AWSLogin(config)
	if err != nil {
		return "", secretType, err
	}
	token, err := GetToken(loginData)
	if err != nil {
		return "", secretType, err
	}
	secretHeaders := make(http.Header)
	secretHeaders.Add("X-Vault-Token", token)

	secretURL, err := url.Parse(config["SECRET_URL"])
	if err != nil {
		return "", secretType, err
	}
	status, resp, err := SendHTTPRequest(true, "", "GET", *secretURL, []byte{}, secretHeaders)
	if err != nil {
		return "", secretType, err
	}
	if status/100 != 2 {
		return "", secretType, errors.New("non-2xx status received")
	}
	return string(resp), secretType, nil

}

func DecodeSecret(content []byte) (*hashicorp.Secret, error) {
	var secret hashicorp.Secret
	err := json.Unmarshal(content, &secret)
	if err != nil {
		return nil, err
	}
	return &secret, nil
}

func GetSecret(secretConfig map[string]string, roleId string) (string, string, error) {
	switch GetSecretRoleType(secretConfig) {
	case "bvp":
		if roleId != "" {
			return "", "bvp", errors.New("step-up not implemented yet")
		}
		return BVPSecret(0, secretConfig)
	case "bcp":
		return "", "bcp", errors.New("not implemented yet")
	case "shared":
		return "", "shared", errors.New("not implemented yet")
	case "aws":
		return AWSSecret(secretConfig)
	default:
		return "", "", errors.New("invalid secret type")
	}
}
