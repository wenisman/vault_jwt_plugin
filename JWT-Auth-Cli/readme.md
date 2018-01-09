# Vault IAM Auth
This is a simple command line tool that will send a request to AWS and get you the login credentials for authentication via the iam role. 

## Why IAM 
Well this lets AWS become the trusted advisor, so we can assume that anyone with a verified signed request from AWS is genuinely who they say thay are as Amazon has provided a signed request. 

## How it Works
The CLI uses the built in AWS credentials on the instance, to run 
```
./vault-iam-auth
```

Thats it, you will get back the full request you can send to Vault if you have the [AWS Auth](https://www.vaultproject.io/docs/auth/aws.html) backend enabled and configured. Please see the documentation for more details on this. 

### Options
You can set the `vault-header`, this is a unique header that vault can use as a protection against replay attacks. In the Vault AWS Auth documentation look up `X-Vault-AWS-IAM-Server-ID`, and you `vault-header` must equal this in order for your request to be processed. 

```
./vault-iam-auth -v [some-header]
```


## Thanks
Couldnt have been built without these awesome libraries
[cobra](https://github.com/spf13/cobra)

[viper](https://github.com/spf13/viper)

[AWS Golang SDK](https://aws.amazon.com/sdk-for-go/)
