package lib

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/spf13/viper"
)

// HTTPClient - interface to provide members a way of injecting requirements for testing
type HTTPClient interface {
	Get(string) (*http.Response, error)
	Post(url string, contentType string, body io.Reader) (*http.Response, error)
	Do(*http.Request) (*http.Response, error)
}

func extractClientToken(input []byte) (string, error) {
	var temp map[string]interface{}
	err := json.Unmarshal(input, &temp)
	if err != nil {
		return "", err
	}

	auth := temp["auth"].(map[string]interface{})
	return auth["client_token"].(string), nil
}

func extractJwt(input []byte) (string, error) {
	var temp map[string]interface{}
	err := json.Unmarshal(input, &temp)
	if err != nil {
		return "", err
	}

	data := temp["data"].(map[string]interface{})
	return data["ClientToken"].(string), nil
}

func extractIsValid(input []byte) (string, error) {
	var temp map[string]interface{}
	err := json.Unmarshal(input, &temp)
	if err != nil {
		return "", err
	}

	data := temp["data"].(map[string]interface{})
	return fmt.Sprintf("%v", data["is_valid"]), nil
}

// AWSLogin - call vault with AWS data to log in and gain the client token
func AWSLogin(client HTTPClient, iamData IamData) (string, error) {
	// basic configuration options - read from viper
	vaultURL := viper.Get("vault-url")
	iamString, _ := json.Marshal(iamData)
	buf := bytes.NewBuffer(iamString)
	resp, err := client.Post(fmt.Sprintf("%s/v1/auth/aws/login", vaultURL), "application/json", buf)
	if err != nil {
		return "", err
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("Unable to retrieve IAM Login from vault: %s", body)
	}

	return extractClientToken(body)
}

// GetJWT - call vault get jwt with the role and option claim
func GetJWT(client HTTPClient, clientToken string, roleName string, claimName string) (string, error) {
	// construct the JSON to send to vault
	data := map[string]interface{}{
		"role_name": roleName,
	}

	if claimName != "" {
		data["claim_name"] = claimName
	}

	b, _ := json.Marshal(data)
	buf := bytes.NewReader(b)

	// construct the request to send
	vaultURL := viper.Get("vault-url")
	req, _ := http.NewRequest("PUT", fmt.Sprintf("%s/v1/auth/jwtplugin/token/issue", vaultURL), buf)
	req.Header.Add("X-Vault-Token", clientToken)
	req.Header.Add("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}

	// extract the jwt from the response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("Unable to retrieve JWT : %s", body)
	}

	return extractJwt(body)
}

// ValidateJWT -  check if the provided JWT is valid or not
func ValidateJWT(client HTTPClient, jwt string) (string, error) {
	vaultURL := viper.Get("vault-url")

	buf := bytes.NewReader([]byte(fmt.Sprintf("{ \"token\": \"%s\" }", jwt)))

	req, _ := http.NewRequest("PUT", fmt.Sprintf("%s/v1/auth/jwtplugin/token/validate", vaultURL), buf)
	req.Header.Add("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}

	// extract if the jwt is valid or not from the response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("Error occured during validation : %s", body)
	}

	return extractIsValid(body)
}

// IssueJwt - issue the jwt based on your current IAM role
func IssueJwt(client HTTPClient, role string, claim string) (string, error) {
	iamData, err := GenerateLoginData()
	if err != nil {
		return "", fmt.Errorf("Error getting iam login data: %v", err)
	}

	token, err := AWSLogin(client, *iamData)

	if err != nil {
		return "", fmt.Errorf("Error signing into Vault: %v", err)
	}

	return GetJWT(client, token, role, claim)
}
