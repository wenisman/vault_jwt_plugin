package josejwt_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/mitchellh/mapstructure"

	"github.com/hashicorp/vault/logical"
	jwt "github.com/wenisman/vault_jwt_plugin/plugin"
)

func TestCRUDRole(t *testing.T) {
	b, storage := getTestBackend(t)

	/***  TEST Create Role OPERATION ***/
	startTime := time.Now()
	data := map[string]interface{}{
		"token_type": "jwt",
	}

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "role/test_role",
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}
	fmt.Printf("'Test create role' took %s\n", time.Since(startTime))

	/***  TEST GET OPERATION ***/
	startTime = time.Now()

	req.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	var returnedRole jwt.RoleStorageEntry
	err = mapstructure.Decode(resp.Data, &returnedRole)

	if returnedRole.Name != "test_role" {
		t.Fatalf("incorrect role name %s returned, not the same as saved value \n", returnedRole.Name)
	} else if returnedRole.TokenType != "jwt" {
		t.Fatalf("incorrect token type returned, not the same as saved value \n")
	}
	fmt.Printf("'Test get role' took %s\n", time.Since(startTime))

	/***  TEST Delete OPERATION ***/
	startTime = time.Now()
	req.Operation = logical.DeleteOperation

	resp, err = b.HandleRequest(req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}
	fmt.Printf("'Test delete role' took %s\n", time.Since(startTime))
}
