package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/siteminder-au/vault-iam-auth/lib"
)

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "vault-iam-auth",
	Short: "This will create the JSON object to send to vault for login via IAM authentication",
	Long: `Using the AWS credentials on the instance this will send a request to the AWS SDk that will
	generate the CallerIdentity Documents that vaults needs to be able to verify this instance.`,

	// Uncomment the following line if your bare application
	// has an action associated with it:
	Run: func(cmd *cobra.Command, args []string) {
		data, err := lib.GenerateLoginData()
		if err != nil {
			fmt.Println("Error getting iam login data", err)
		} else {
			output, _ := json.Marshal(data)
			fmt.Println(string(output))
		}
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	RootCmd.Flags().StringP("vault-header", "v", "", "Additional header with which to sign the IAM request")

	viper.BindPFlags(RootCmd.Flags())
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	viper.AutomaticEnv() // read in environment variables that match
}
