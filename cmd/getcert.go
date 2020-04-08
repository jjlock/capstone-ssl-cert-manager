/*
Copyright © 2020 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"
	"github.com/ssl-cert-manager/sslcm/certdb"
)

// getcertCmd represents the getcert command
var getcertCmd = &cobra.Command{
	Use:   "getcert [domain]",
	Short: "Gets the certificate for a domain",
	Long: `getcert retrieves the most recent certificate for a given user ID and
	subdomain/domain combo from the database.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		certificates, err := certdb.GetCertFromDb(args[0])
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("CLIENT CERTIFICATE")
		fmt.Println(certificates.ClientCert)
		fmt.Println()
		fmt.Println("ISSUER CERTIFICATE")
		fmt.Println(certificates.IssuerCert)
	},
}

func init() {
	rootCmd.AddCommand(getcertCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// getcertCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// getcertCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
