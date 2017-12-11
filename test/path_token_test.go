package josejwt_test

import (
	"fmt"
	"log"
	"testing"
	"time"

	"github.com/hashicorp/vault/logical"
)

func TestCreateBadAuthToken(t *testing.T) {
	b, storage := getTestBackend(t)
	roleName := "test_role"
	resp, _ := createSampleRole(b, storage, roleName)

	req := &logical.Request{
		Storage: storage,
	}

	resp, err := createToken(req, b, t, roleName)
	if err != nil && resp.IsError() != false {
		t.Fatalf("this should not have thrown an error")
	}
}

func TestIssueValidateToken(t *testing.T) {
	b, storage := getTestBackend(t)
	roleName := "test_role"
	resp, _ := createSampleRole(b, storage, roleName)

	req := &logical.Request{
		Storage:     storage,
		DisplayName: fmt.Sprintf("test-%s", roleName),
	}

	resp, err := createToken(req, b, t, roleName)
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
	validateToken(req, b, t, clientToken, roleName, true)
	validateToken(req, b, t, clientToken, roleName, true)
	validateToken(req, b, t, clientToken, roleName, true)
	validateToken(req, b, t, clientToken, roleName, true)

	// with a two second timeout this should fail vaildation
	time.Sleep(time.Duration(2) * time.Second)
	validateToken(req, b, t, clientToken, roleName, false)

	// now to recreate a token and test its valid once again
	resp, err = createToken(req, b, t, roleName)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	if resp.Data["ClientToken"] == "" {
		t.Fatal("no token returned\n")
	}

	clientToken = resp.Data["ClientToken"].(string)
	validateToken(req, b, t, clientToken, roleName, true)
}

// create the token given the parameters
func createToken(req *logical.Request, b logical.Backend, t *testing.T, roleName string) (*logical.Response, error) {
	data := map[string]interface{}{
		"role_name":  roleName,
		"token_type": "jwt",
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
func createSampleRole(b logical.Backend, storage logical.Storage, roleName string) (*logical.Response, error) {
	data := map[string]interface{}{
		"token_type": "jwt",
		"token_ttl":  2,
	}

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      fmt.Sprintf("role/%s", roleName),
		Storage:   storage,
		Data:      data,
	}

	return b.HandleRequest(req)
}
