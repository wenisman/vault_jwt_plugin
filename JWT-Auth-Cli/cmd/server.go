package cmd

import (
	"github.com/siteminder-au/vault-iam-auth/lib"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start the REST server for the Vault Auth",
	Long:  `Start the localhost server for REST-ful calls to get and validate JWT's`,
	Run: func(cmd *cobra.Command, args []string) {
		server := lib.Server{}

		server.Run()
	},
}

func init() {
	RootCmd.AddCommand(serverCmd)

	serverCmd.Flags().StringP("vault-header", "v", "", "Additional header with which to sign the IAM request")
	serverCmd.Flags().StringP("vault-url", "u", "http://127.0.0.1:8200", "The url of the vault server")
	viper.BindPFlags(serverCmd.Flags())
}
