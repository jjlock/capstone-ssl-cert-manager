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
	certdb "github.com/ssl-cert-manager/sslcm/certdb"
)

// reqcertCmd represents the reqcert command
var reqcertCmd = &cobra.Command{
	Use:   "reqcert [domain] [email]",
	Short: "Starts the certificate request process",
	Long: `reqcert starts the certificate request process for a given user ID
	and subdomain/domain combo. A free SSL certificate will be requested and then
	stored in the database.`,
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		certificates := certdb.GenerateFreeSSLCerts(args[0], args[1])
		err := certdb.AddCertsToDb(certificates, args[0], args[1])
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Certificates for domain", args[0], "successfully generated")
	},
}

func init() {
	rootCmd.AddCommand(reqcertCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// reqcertCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// reqcertCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
