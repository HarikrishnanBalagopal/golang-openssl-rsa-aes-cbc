package main

import (
	"fmt"
	"io/ioutil"

	"foo.com/b/crypto"
	"github.com/sirupsen/logrus"
)

func main() {

	// 1st part

	// generate a random password

	password, err := crypto.GetRandomBytes(32)
	if err != nil {
		logrus.Fatalf("failed to generate a random password. Error: %q", err)
	}

	// read the certificate

	certPath := "crypto/testdata/certificate.crt"
	certBytes, err := ioutil.ReadFile(certPath)
	if err != nil {
		logrus.Fatalf("failed to read the certificate from the file at path %s. Error: %q", certPath, err)
	}

	// parse the certificate

	publicKey, err := crypto.GetRSAPublicKeyFromCertificate(certBytes)
	if err != nil {
		logrus.Fatalf("failed to parse the certificate at path %s. Error: %q", certPath, err)
	}

	// encrypt the password using the public key from the certificate

	encryptedPassword, err := crypto.RsaEncrypt(publicKey, password)
	if err != nil {
		logrus.Fatalf("failed to encrypt the password. Error: %q", err)
	}
	fmt.Println("encryptedPassword", encryptedPassword)

	// 2nd part

	// generate a random salt

	salt, err := crypto.GetRandomBytes(8)
	if err != nil {
		logrus.Fatalf("failed to generate the salt for pbkdf2. Error: %q", err)
	}

	// derive an AES key using the password and the salt

	// read the workload.yaml

	workloadPath := "crypto/testdata/workload.yaml"
	workloadBytes, err := ioutil.ReadFile(workloadPath)
	if err != nil {
		logrus.Fatalf("failed to read the workload from the file at path %s. Error: %q", workloadPath, err)
	}

	// encrypt the workload using the AES key

	encryptedWorkload, err := crypto.AesCbcEncryptWithPbkdf(password, salt, workloadBytes)
	if err != nil {
		logrus.Fatalf("failed to encrypt the workload. Error: %q", err)
	}

	encryptedWorkloadInOpenSSLFormat := crypto.ToOpenSSLFormat(salt, encryptedWorkload)

	fmt.Println("encryptedWorkloadInOpenSSLFormat", encryptedWorkloadInOpenSSLFormat)

	fmt.Println("done")
}
