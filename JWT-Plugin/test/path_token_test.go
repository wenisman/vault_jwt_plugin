package josejwt_test

import (
	"fmt"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/logical"
)

func TestCreateBadAuthToken(t *testing.T) {
	b, storage := getTestBackend(t)
	roleName := "test_role"
	resp, _ := createSampleRole(b, storage, roleName, "")

	req := &logical.Request{
		Storage: storage,
	}

	resp, err := createToken(req, b, t, roleName, "")
	if err != nil && resp.IsError() != false {
		t.Fatalf("this should not have thrown an error")
	}
}

func TestIssueValidateToken(t *testing.T) {
	b, storage := getTestBackend(t)
	roleName := "test_role"
	resp, _ := createSampleRole(b, storage, roleName, "")

	req := &logical.Request{
		Storage:     storage,
		DisplayName: fmt.Sprintf("test-%s", roleName),
	}

	resp, err := createToken(req, b, t, roleName, "")
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	if resp.Data["ClientToken"] == "" {
		t.Fatal("no token returned\n")
	}

	clientToken := resp.Data["ClientToken"].(string)
	log.Println(clientToken)

	// with a 1 second timeout this should still return a valid token
	time.Sleep(time.Duration(1) * time.Second)
	validateToken(req, b, t, clientToken, roleName, true)
	validateToken(req, b, t, clientToken, roleName, true)

	// with a two second timeout this should fail vaildation
	time.Sleep(time.Duration(2) * time.Second)
	validateToken(req, b, t, clientToken, roleName, false)

	// now to recreate a token and test its valid once again
	resp, err = createToken(req, b, t, roleName, "")
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	if resp.Data["ClientToken"] == "" {
		t.Fatal("no token returned\n")
	}

	clientToken = resp.Data["ClientToken"].(string)
	validateToken(req, b, t, clientToken, roleName, true)
}

// test the claims
func TestFailClaimsOnToken(t *testing.T) {
	b, storage := getTestBackend(t)

	claims := map[string]string{
		"sample-one": "allow sample",
	}

	resp, err := createClaim(b, storage, "test-claim", claims)
	resp, err = createClaim(b, storage, "test-claim-fail", claims)

	if err != nil {
		t.Fatal(fmt.Sprintf("Unable to save the claims to storage\n%#v ", err))
	}

	if resp.Data["saved"] != true {
		t.Fatal("Unable to save the claims to storage\n")
	}

	roleName := "test_claim_role"
	resp, _ = createSampleRole(b, storage, roleName, "")

	req := &logical.Request{
		Storage:     storage,
		DisplayName: fmt.Sprintf("testclaim-%s", roleName),
	}

	resp, err = createToken(req, b, t, roleName, "test-claim")
	if resp != nil && strings.Index(resp.Data["error"].(string), "Permission denied") < 0 {
		t.Fatalf("Disallowed claims should be denied, resp:%#v\n", resp)
	}
}

// test the claims work with named claims
func TestIssueClaimsOnToken(t *testing.T) {
	b, storage := getTestBackend(t)

	claims := map[string]string{
		"sample-one": "allow sample",
	}

	resp, err := createClaim(b, storage, "test-claim", claims)

	if err != nil {
		t.Fatal(fmt.Sprintf("Unable to save the claims to storage\n%#v ", err))
	}

	if resp.Data["saved"] != true {
		t.Fatal("Unable to save the claims to storage\n")
	}

	roleName := "test_claim_role"
	resp, _ = createSampleRole(b, storage, roleName, "test-claim")

	req := &logical.Request{
		Storage:     storage,
		DisplayName: fmt.Sprintf("testclaim-%s", roleName),
	}

	resp, err = createToken(req, b, t, roleName, "test-claim")
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	if resp.Data["ClientToken"] == "" {
		t.Fatal("no token returned\n")
	}

	clientToken := resp.Data["ClientToken"].(string)
	log.Println(clientToken)
}

// create the token given the parameters
func createToken(req *logical.Request, b logical.Backend, t *testing.T, roleName string, claimName string) (*logical.Response, error) {
	data := map[string]interface{}{
		"role_name":  roleName,
		"token_type": "jwt",
	}

	// set the claim to use if specified
	if claimName != "" {
		data["claim_name"] = claimName
	}

	req.Operation = logical.UpdateOperation
	req.Path = "token/issue"
	req.Data = data

	start := time.Now()
	resp, err := b.HandleRequest(req)
	fmt.Printf("Issue Token took %s\n", time.Since(start))

	return resp, err
}

// validate the returned token
func validateToken(req *logical.Request, b logical.Backend, t *testing.T, clientToken string, roleName string, result bool) {
	data := map[string]interface{}{
		"token":     clientToken,
		"role_name": roleName,
	}

	req.Path = "token/validate"
	req.Data = data

	start := time.Now()

	resp, err := b.HandleRequest(req)
	fmt.Printf("Validate Token took %s\n", time.Since(start))
	if err != nil || (resp != nil && resp.IsError()) {
		if err.Error() != "token is expired" {
			t.Fatalf("err:%s resp:%#v\n", err, resp)
		} else {
			return
		}
	}

	if resp.Data["is_valid"] != result {
		t.Fatalf("incorrect validation result")
	}
}

// create the role with the specified name
func createSampleRole(b logical.Backend, storage logical.Storage, roleName string, claim string) (*logical.Response, error) {
	data := map[string]interface{}{
		"token_type":   "jwt",
		"token_ttl":    2,
		"named_claims": []string{claim},
	}

	req := &logical.Request{
		Operation:   logical.CreateOperation,
		Path:        fmt.Sprintf("role/%s", roleName),
		Storage:     storage,
		Data:        data,
		DisplayName: fmt.Sprintf("test-%s", roleName),
	}

	return b.HandleRequest(req)
}

func createClaim(b logical.Backend, storage logical.Storage, name string, claims map[string]string) (*logical.Response, error) {

	data := map[string]interface{}{
		"claims": claims,
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      fmt.Sprintf("claims/%s", name),
		Storage:   storage,
		Data:      data,
	}

	return b.HandleRequest(req)
}
