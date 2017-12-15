# Vault JWT Plugin 

## Purpose
The purpose of this plugin is to allow apps to authenticate through the use of JWT tokens
This was previously proposed within the vault Git repo... https://github.com/hashicorp/vault/issues/1986
I will be following the guidelines of the proposal as much as I can whilst trying to make this feasible for applications

## Workflow
There will have to be several steps in getting up the apps for authentication, however these can all be done through basic curl requests and so will be fully scriptable through any CICD pipeline

### Creating a token
1. create the application role
    - an application role ID and secret ID will be returned to you
2. create the JWT
    - the JWT will check your application role ID plus secret ID and append any claims to the JWT before constructing a new token

Then your application is able to append the JWT into the **Authorization** header with the _bearer_ prefix

The token will be generated using the DisplayName from your authenticated client-token. The display name will provide the role that the token will be created off, each token will then be signed and returned to the client. 

```
curl -H "X-Vault-Token: [CLIENT-TOKEN]" -H "Content-Type: application/json" --request PUT http://127.0.0.1:8200/v1/auth/[PLUGIN-NAME]/token/issue
```

### Validating a token
1. The JWT is then able to be authenticated and validated by the vault end point, returning either an 200 (OK) or throwing the appropriate error.

```
curl -H "X-Vault-Token: [CLIENT-TOKEN]" -H "Content-Type: application/json" -d '{ "token":"[JWT-TOKEN]" }' --request PUT http://127.0.0.1:8200/v1/auth/[PLUGIN-NAME]/token/validate
```


## Building
you can build using the provided `build.sh` 
to set up the build.sh
```
chmod a+x build.sh
```

## Installing
To use a plugin in vault you must set it up correctly, a little light reading
https://www.vaultproject.io/docs/plugin/index.html


### Setup
There is a provided script that can setup your JWT plugin for you, however it requires that you are on the instance running your vault.

```
./redeploy.sh [PLUGIN-NAME]
```

You can substitute the plugin name for what ever name takes your fancy, for instance `jwt`. Please note that this will also mount your plugin on that path so you will need to take note of this.

## Setup vault

### AWS Auth
https://www.vaultproject.io/docs/auth/aws.html

You will need to enable the AWS Auth plugin and set your credentials
```
vault auth-enable aws

vault write auth/aws/config/client secret_key=[AWS_SECRET_ACCESS_KEY] access_key=[AWS_ACCESS_KEY_ID]
```

### Policies
Vault works by allowing certain actions once a login has occured, the client token will be given a set of policies to determine what you can and cant do. To amend these policies you can provide a policy document 
https://www.vaultproject.io/docs/concepts/policies.html

but a sample would look like:
```
path "auth/[PLUGIN-NAME]/token/*" {
  capabilities = ["read", "update", "create"]
}
```

this would allow a client to issue and validate tokens, however they would not be allowewd to perform other actions like create or amend roles. 

you can then apply the policy with, the POLICY-NAME is what will be used in the logins to find that policy 
```
vault policy-write [POLICY-NAME] [POLICY-FILE].hcl
```


## Roles
### AWS Roles
You can refer to the documentation, however to set up a role for the AWS Auth to use you will need to get the IAM ARN, know which policy you want to attach and then have the role name. 
```
vault write auth/aws/role/[ROLE_NAME] auth_type=iam policies=[default, OTHER POLICIES] bound_iam_principal_arn=“[IAM_ARN]”
```

### Claims
You can create a `named` claim, this is a predefined set of claims that will be attached to a JWT. You can assign any named claim to a Role and when you create the token you can give it this claim as long as the role has this specified during its creations. This is to stop apps from mis-assuming roles.

```

curl -X POST  -H "X-Vault-Token: [VAULT_TOKEN]" -H "Content-Type: application/json" -d '{ "claims": { [ENTER YOUR CLAIMS] }  }' http://127.0.0.1:8200/v1/auth/jwtplugin/claims/[CLAIM_NAME]
```

### JWT Roles
You will also need to set up the roles in the JWT plugin as well, this is so that you can set the claims that are to be provided on the token. 

*NOTE:* There is no overriding the claims when requesting a token, it is not the security concern of a client to assert what it is allowed to access. 

To set up the role you will need higher level permissions, you can set up your own tokens which is the most preferred method or you could go full cowboy and use the Root token to do this. 
```
curl -H "X-Vault-Token: [VAULT-TOKEN]" -H "Content-Type: application/json" --request POST -d '{ "claims": { [ENTER YOUR CLAIMS] }, "token_type": "jwt", "name": "[AWS-ROLE-NAME]" }' http://127.0.0.1:8200/v1/auth/[PLUGIN-NAME]/role/[AWS-ROLE-NAME]
```  
**OR** use a named claim
```
curl -H "X-Vault-Token: [VAULT-TOKEN]" -H "Content-Type: application/json" --request POST -d '{ "claim-name": "[CLAIM_NAME]", "token_type": "jwt", "name": "[AWS-ROLE-NAME]" }' http://127.0.0.1:8200/v1/auth/[PLUGIN-NAME]/role/[AWS-ROLE-NAME]
```

