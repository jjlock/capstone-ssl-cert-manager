package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/ssl-cert-manager/sslcm/certdb"
)

func main() {
	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/cert/{domain}", GetCert).Methods("GET")
	router.HandleFunc("/cert/{domain}", DeleteCert).Methods("DELETE")
	router.HandleFunc("/cert/{domain}", RequestCert)
	log.Fatal(http.ListenAndServe(":8080", router))
}

// GetCert is function called when /get-cert/{domain} is hit
func GetCert(w http.ResponseWriter, r *http.Request) {
	domain := mux.Vars(r)["domain"]

	var cert = certdb.GetCertFromDb(domain)

	json.NewEncoder(w).Encode(cert)
}

// RequestCert is function called when /get-cert/{domain} is hit
func RequestCert(w http.ResponseWriter, r *http.Request) {
	domain := mux.Vars(r)["domain"]
	email := mux.Vars(r)["email"]

	certificates := certdb.GenerateFreeSSLCerts(domain, email)
	err := certdb.AddCertsToDb(certificates, domain, email)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Fprintf(w, "Certs for domain \""+domain+"\" successfully generated")
}

// DeleteCert is called when /delete-cert/{domain} is hit
func DeleteCert(w http.ResponseWriter, r *http.Request) {
	domain := mux.Vars(r)["domain"]

	// TODO not sure how to respond...
	certdb.RemoveCertFromDb(domain)
}
