package josejwt_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/mitchellh/mapstructure"

	"github.com/hashicorp/vault/logical"
	jwt "github.com/wenisman/vault_jwt_plugin/plugin"
)

func TestCRUDKey(t *testing.T) {
	b, storage := getTestBackend(t)

	/***  TEST SET OPERATION ***/
	startTime := time.Now()
	data := map[string]interface{}{
		"alg": "HS256",
	}

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "keys/test_key",
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}
	fmt.Printf("'Test create key' took %s\n", time.Since(startTime))

	/***  TEST GET OPERATION ***/
	startTime = time.Now()

	req.Operation = logical.ReadOperation
	resp, err = b.HandleRequest(req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	var returnedKey jwt.KeyStorageEntry
	err = mapstructure.Decode(resp.Data, &returnedKey)

	if returnedKey.Name != "test_key" {
		t.Fatalf("incorrect key name returned, not the same as saved value")
	} else if returnedKey.Algorithm != "HS256" {
		t.Fatalf("incorrect algorith returned, not the same as saved value")
	}
	fmt.Printf("'Test get key' took %s\n", time.Since(startTime))
}
