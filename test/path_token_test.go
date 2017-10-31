package josejwt_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/vault/logical"
)

func TestAuthenticateValidateToken(t *testing.T) {
	b, storage := getTestBackend(t)
	createSampleRole(b, storage, "test_role")
	createSampleRole(b, storage, "test_role_two")

	start := time.Now()
	data := map[string]interface{}{
		"role_name": "test_role",
	}

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "token/issue",
		Data:      data,
		Storage:   storage,
	}

	resp, err := b.HandleRequest(req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	fmt.Printf("Authenticate Token took %s\n", time.Since(start))

	if resp.Data["ClientToken"] == "" {
		t.Fatal("no token returned\n")
	}

	data = map[string]interface{}{
		"token":     resp.Data["ClientToken"],
		"role_name": "test_role",
	}

	req.Path = "token/validate"
	req.Data = data

	// with a 1 second timeout this should still return a valid token
	time.Sleep(time.Duration(1) * time.Second)
	validateToken(req, b, t, true)
	validateToken(req, b, t, true)
	validateToken(req, b, t, true)
	validateToken(req, b, t, true)
	validateToken(req, b, t, true)
	validateToken(req, b, t, true)

	// with a two second timeout this should fail vaildation
	time.Sleep(time.Duration(2) * time.Second)
	validateToken(req, b, t, false)
	validateToken(req, b, t, false)
}

func validateToken(req *logical.Request, b logical.Backend, t *testing.T, result bool) error {
	start := time.Now()

	resp, err := b.HandleRequest(req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	if resp.Data["is_valid"] != result {
		t.Fatalf("incorrect validation result")
	}

	fmt.Printf("Validate Token took %s\n", time.Since(start))

	return nil
}

func createSampleRole(b logical.Backend, storage logical.Storage, roleName string) (*logical.Response, error) {
	data := map[string]interface{}{
		"token_type": "jwt",
		"secret_ttl": 2,
	}

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      fmt.Sprintf("role/%s", roleName),
		Storage:   storage,
		Data:      data,
	}

	return b.HandleRequest(req)
}
