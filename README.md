# capstone-ssl-cert-manager
UCI Informatics Senior Design Project for [Twilio SendGrid](https://www.twilio.com/sendgrid)

Team:
- Kayla Carrera - Developer
- Justin Lock (Me) - Developer
- Julie Tran - Project Manager
- Xiang Wang - Designer

I was responsible for creating the command line interface and connecting it with the database, setting up configuration, implementing checking if certificates in the database were revoked by the certificate authority, and implementing the AWS lambda function for the SSL certificate manager.

## Project Info
In concept our SSL certificate manager was intended to be used by Twilio SendGrid engineers and their clients to automate the process of requesting and renewing SSL certificates and managing stored SSL certificates.

This project uses the following:
- Digital Ocean
- Let's Encrypt
- AWS Lambda
- AWS RDS for MySQL

Digital Ocean was used for testing our SSL certificate manager with a test domain. Let's Encrypt was used to generate free SSL certificates. AWS Lambda was used to implement request, get, and delete requests so that Twilio SendGrid engineers and clients can interact with our SSL certificate manager. Twilio SendGrid engineers can also use the command line interface of our SSL certificate manager to request, get, and delete certificates. AWS RDS for MySQL was used to store SSL certificates.

### Build
The project can be built using `go build -o sslcm main.go`

### Usage
These commands can be used in the terminal after building the go executable binary:
```
./sslcm reqcert [domain] [email]  # starts the certificate request process and stores the returned certificate in the database
./sslcm getcert [domain]          # gets and prints the certificate from the database for the given domain
./sslcm delcert [domain]          # deletes the certificate from the database for the given domain
```

### AWS Lambda
For use in a AWS Lambda function the project should be built in the aws-lambda directory. For more information on how to build the go executable binary for AWS Lambda see the [AWS Lambda documentation for Go](https://docs.aws.amazon.com/lambda/latest/dg/lambda-golang.html).
