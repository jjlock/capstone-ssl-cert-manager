package main

import (
	"context"
	"fmt"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/ssl-cert-manager/sslcm/aws-lambda/certdb"
)

// Event is the event to request, get, or delete a certificate. Assume an Event will only have one of Request, Get, or Delete be true and the others false
type Event struct {
	Domain  string `json:"domain"`
	Email   string `json:"email"`
	Request bool   `json:"request"`
	Get     bool   `json:"get"`
	Delete  bool   `json:"delete"`
}

// Response is the response to the event
type Response struct {
	Result string `json:"result"`
}

// HandleLambdaEvent handles the Event to either request, get, or delete a SSL certificate in the database
func HandleLambdaEvent(ctx context.Context, event Event) (Response, error) {
	switch {
	case event.Request:
		certificates := certdb.GenerateFreeSSLCerts(event.Domain, event.Email)
		err := certdb.AddCertsToDb(certificates, event.Domain, event.Email)
		if err != nil {
			return Response{Result: fmt.Sprint(err)}, err
		}
		return Response{Result: fmt.Sprintf("Certificates for domain %s successfully generated", event.Domain)}, nil
	case event.Get:
		certificates, err := certdb.GetCertFromDb(event.Domain)
		if err != nil {
			return Response{Result: fmt.Sprint(err)}, err
		}
		return Response{Result: fmt.Sprintf("CLIENT CERTIFICATE\n%s\n\nISSUER CERTIFICATE\n%s\n", certificates.ClientCert, certificates.IssuerCert)}, nil
	case event.Delete:
		err := certdb.RemoveCertFromDb(event.Domain)
		if err != nil {
			return Response{Result: fmt.Sprint(err)}, err
		}
		return Response{Result: fmt.Sprintf("Certificate for %s deleted", event.Domain)}, nil
	default:
		return Response{Result: "Unknown request"}, nil
	}
}

func main() {
	lambda.Start(HandleLambdaEvent)
}
