package certdb

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/go-acme/lego/certcrypto"
	"github.com/go-acme/lego/certificate"
	"github.com/go-acme/lego/challenge/dns01"
	"github.com/go-acme/lego/registration"
	"github.com/go-sql-driver/mysql"
	"github.com/ssl-cert-manager/sslcm/certs"
	"github.com/xenolf/lego/lego"
	"github.com/xenolf/lego/providers/dns/digitalocean"
)

type MyUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

type Certificate struct {
	ClientCert string `json:"clientCert"`
	IssuerCert string `json:"issuerCert"`
}

func (u *MyUser) GetEmail() string {
	return u.Email
}
func (u MyUser) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *MyUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

// GenerateFreeSSLCerts requests/generates certificates to be stored
func GenerateFreeSSLCerts(domain string, email string) *certificate.Resource {
	// Create a user. New accounts need an email and private key to start.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	myUser := MyUser{
		Email: email,
		key:   privateKey,
	}

	config := lego.NewConfig(&myUser)

	// This is the ACME URL for ACME v2 staging environment
	config.CADirURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
	// config.CADirURL = "https://acme-v02.api.letsencrypt.org/directory"
	config.Certificate.KeyType = certcrypto.RSA2048

	// A client facilitates communication with the CA server.
	client, err := lego.NewClient(config)
	if err != nil {
		log.Fatal(err)
	}

	providerConfig := digitalocean.NewDefaultConfig()
	providerConfig.PropagationTimeout = time.Minute * 2
	providerConfig.TTL = 60
	providerConfig.PollingInterval = time.Second * 1

	providerConfig.AuthToken = os.Getenv("DIGITALOCEAN_AUTH_TOKEN")
	provider, err := digitalocean.NewDNSProviderConfig(providerConfig)
	if err != nil {
		log.Fatal(err)
	}
	err = client.Challenge.SetDNS01Provider(provider, dns01.DisableCompletePropagationRequirement())
	if err != nil {
		log.Fatal(err)
	}
	// New users will need to register
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		log.Fatal(err)
	}
	myUser.Registration = reg
	fmt.Printf("%+v\n", reg)

	request := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}

	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		log.Fatal(err)
	}

	return certificates
}

// OpenDb return open DB
func OpenDb() *sql.DB {
	config := mysql.Config{
		User:                    os.Getenv("AWS_DB_USER"),
		Passwd:                  os.Getenv("AWS_DB_PASSWORD"),
		Net:                     "tcp",
		Addr:                    os.Getenv("AWS_DB_ENDPOINT"),
		DBName:                  os.Getenv("AWS_DB_NAME"),
		AllowCleartextPasswords: true,
		AllowNativePasswords:    true,
	}

	connectStr := config.FormatDSN()

	db, err := sql.Open("mysql", connectStr)
	if err != nil {
		log.Fatal(err)
	}
	return db
}

// AddCertsToDb uploads certs as strings to local MySql db
func AddCertsToDb(certificates *certificate.Resource, domain string, email string) error {
	db := OpenDb()

	insert, err := db.Query(fmt.Sprintf("INSERT INTO domain_cert_table(domain, private_key, issuer_cert, cert, created_at, email) VALUES ('%s','%s','%s','%s', '%s', '%s')",
		domain, string(certificates.PrivateKey[:]),
		string(certificates.IssuerCertificate[:]), string(certificates.Certificate[:]), time.Now(), email))
	if err != nil {
		return err
	}

	defer insert.Close()
	return nil
}

// RemoveCertFromDb deletes row from db table based of primary key domain
func RemoveCertFromDb(domain string) error {
	db := OpenDb()

	var cert string
	err := db.QueryRow(`SELECT cert FROM domain_cert_table WHERE domain =?`, domain).Scan(&cert)
	if err != nil {
		return fmt.Errorf("Domain %s does not exist", domain)
	}

	insert, err := db.Query(fmt.Sprintf("DELETE FROM domain_cert_table WHERE domain = '%s'", domain))
	if err != nil {
		return err
	}

	defer insert.Close()
	return nil
}

// GetCertFromDb gets cert from db from domain primary key
func GetCertFromDb(domain string) (Certificate, error) {
	db := OpenDb()

	var cert string
	err := db.QueryRow(`SELECT cert FROM domain_cert_table WHERE domain =?`, domain).Scan(&cert)
	if err != nil {
		return Certificate{}, fmt.Errorf("Domain %s does not exist", domain)
	}

	certsArray := strings.Split(cert, "\n\n")

	return Certificate{ClientCert: certsArray[0], IssuerCert: certsArray[1]}, nil
}

// UpdateCertsInDb updates the a domains certs in the db (bc the original cert is expired)
func UpdateCertsInDb(certificates *certificate.Resource, domain string) error {
	db := OpenDb()

	update, err := db.Query(fmt.Sprintf("UPDATE domain_cert_table SET private_key = '%s', issuer_cert = '%s', cert = '%s' WHERE domain = '%s'",
		string(certificates.PrivateKey[:]),
		string(certificates.IssuerCertificate[:]), string(certificates.Certificate[:]), domain))
	if err != nil {
		return err
	}

	defer update.Close()
	return nil
}

// UpdateExpiringCerts gets all rows in DB where cert is almost expiring, and calls UpdateCertsInDb to replace expiring certs with freshly generated ones
func UpdateExpiringCerts() {
	var (
		domain string
		email  string
	)
	db := OpenDb()
	today := time.Now()
	// subtract 83 days from current time and parse it to be SQL friendly (i.e. 20200112)
	almostExpiredDate := strings.ReplaceAll(strings.Split(today.AddDate(0, 0, -83).String(), " ")[0], "-", "")
	rows, err := db.Query(fmt.Sprintf("SELECT domain, created_at from domain_cert_table WHERE created_at <= '%s'", almostExpiredDate))
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		err := rows.Scan(&domain, &email)
		if err != nil {
			log.Fatal(err)
		}

		certificates := GenerateFreeSSLCerts(domain, email)
		UpdateCertsInDb(certificates, domain)
	}

	err = rows.Err()
	if err != nil {
		log.Fatal(err)
	}
}

// RemoveExpiredCerts removes expired certs from the db
func RemoveExpiredCerts() {
	db := OpenDb()

	today := time.Now()
	// subtract 90 days from current time and parse it to be SQL friendly (i.e. 20200112)
	expirationDate := strings.ReplaceAll(strings.Split(today.AddDate(0, 0, -90).String(), " ")[0], "-", "")

	query, err := db.Query(fmt.Sprintf("DELETE FROM domain_cert_table WHERE created_at <= '%s'", expirationDate))
	if err != nil {
		log.Fatal(err)
	}

	defer query.Close()

}

// RemoveRevokedCerts removes certs that were revoked by the CA
func RemoveRevokedCerts() {
	var (
		domain        string
		pemClientCert string
		pemIssuerCert string
		clientCert    *x509.Certificate
		issuerCert    *x509.Certificate
	)

	db := OpenDb()

	rows, err := db.Query(fmt.Sprintf("SELECT domain, cert, issuer_cert FROM domain_cert_table"))
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		err := rows.Scan(&domain, &pemClientCert, &pemIssuerCert)
		if err != nil {
			log.Fatal(err)
		}
		clientCert = certs.ParsePEMCert(pemClientCert)
		issuerCert = certs.ParsePEMCert(pemIssuerCert)
		if certs.IsCertRevokedByCA(clientCert, issuerCert, clientCert.OCSPServer[0]) {
			RemoveCertFromDb(domain)
		}
	}
}
