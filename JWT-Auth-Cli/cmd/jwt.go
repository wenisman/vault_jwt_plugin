package cmd

import (
	"fmt"
	"net/http"

	"github.com/siteminder-au/vault-iam-auth/lib"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var jwtCmd = &cobra.Command{
	Use:   "jwt",
	Short: "Commands that will issue and validate JWTs",
	Long: `There are two commands that will 'issue' and 'validate' the JWT
using the IAM profile from AWS.`,
	Run: func(cmd *cobra.Command, args []string) {
		// this is intentionally empty, there is nothing to do in this command
	},
}

// issueCmd represents the auth command
var issueCmd = &cobra.Command{
	Use:   "issue",
	Short: "Authenticate with Vault and get an JWT",
	Long: `Authenticate with the specified vault server, this will include 
getting the signed IAM request from AWS and then requesting the auth token
from the vault server. The JWT will also be returned as he output.`,
	Run: func(cmd *cobra.Command, args []string) {
		client := &http.Client{}

		jwt, err := lib.IssueJwt(client, viper.GetString("role-name"), viper.GetString("claim-name"))

		if err != nil {
			fmt.Println("Error getting Token", err)
			return
		}

		fmt.Println(jwt)
	},
}

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate a provided JWT",
	Long:  `Validate the JWT with the Vault server.`,
	Run: func(cmd *cobra.Command, args []string) {
		client := &http.Client{}

		isValid, err := lib.ValidateJWT(client, viper.GetString("jwt"))
		if err != nil {
			fmt.Println("Error validating the JWT", err)
			return
		}

		fmt.Println(isValid)
	},
}

func init() {
	RootCmd.AddCommand(jwtCmd)

	// addition of the subcommand for issuing tokens
	jwtCmd.AddCommand(issueCmd)
	jwtCmd.AddCommand(validateCmd)

	issueCmd.Flags().StringP("vault-header", "v", "", "Additional header with which to sign the IAM request")
	issueCmd.Flags().StringP("vault-url", "u", "http://127.0.0.1:8200", "The url of the vault server")
	issueCmd.Flags().StringP("role-name", "r", "", "The role name to use")
	issueCmd.Flags().StringP("claim-name", "c", "", "The name of the predefined claim set to append to the token")
	viper.BindPFlags(issueCmd.Flags())

	validateCmd.Flags().StringP("vault-url", "u", "http://127.0.0.1:8200", "The url of the vault server")
	validateCmd.Flags().StringP("jwt", "j", "", "The JWT to validate")
	viper.BindPFlags(validateCmd.Flags())
}
