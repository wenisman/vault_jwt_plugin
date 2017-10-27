# Vault JWT Plugin 

## Purpose
The purpose of this plugin is to allow apps to authenticate through the use of JWT tokens

## Workflow
There will have to be several steps in getting up the apps for authentication, however these can all be done through basic curl requests and so will be fully scriptable through any CICD pipeline

### Creating a token
1. create the application role
    - an application role ID and secret ID will be returned to you
2. create the JWT
    - the JWT will check your application role ID plus secret ID and append any claims to the JWT before constructing a new token

Then your application is able to append the JWT into the **Authorization** header with the _bearer_ prefix

### Validating a token
1. The JWT is then able to be authenticated and validated by the vault end point, returning either an 200 (OK) or throwing the appropriate error.
