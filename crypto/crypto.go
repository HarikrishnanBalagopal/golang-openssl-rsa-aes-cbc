package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

// GetRSAPublicKeyFromCertificate gets a RSA public key from a PEM-encoded certificate.crt file.
func GetRSAPublicKeyFromCertificate(certificateInPemFormat []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(certificateInPemFormat)
	if block == nil {
		return nil, fmt.Errorf("invalid certificate. Expected a PEM encoded certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse the x509 certificate. Error: %q", err)
	}
	pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("failed to type cast the public key from the x509 certificate. Actual type: %T and value: %+v", cert.PublicKey, cert.PublicKey)
	}
	return pubKey, nil
}

func GetRSAPrivateKey(privateKeyInPemFormat []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(privateKeyInPemFormat)
	if block == nil {
		return nil, fmt.Errorf("invalid private key. Expected a PEM encoded private key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse the private key. Error: %q", err)
	}
	privKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("failed to type cast the private key. Actual type: %T and value: %+v", key, key)
	}
	return privKey, nil
}

// GetRandomBytes returns n random bytes from a cryptographically secure pseudo random number generator.
func GetRandomBytes(n int) ([]byte, error) {
	bs := make([]byte, n)
	if _, err := rand.Read(bs); err != nil {
		return nil, fmt.Errorf("failed to read 32 bits of randomness. Error: %q", err)
	}
	return bs, nil
}

// RsaEncrypt encrypts the plain text using the RSA public key.
func RsaEncrypt(publicKey *rsa.PublicKey, plainText []byte) ([]byte, error) {
	// cipherText, err := rsa.EncryptOAEP(sha512.New(), rand.Reader, publicKey, plainText, nil)
	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, plainText)
	if err != nil {
		return cipherText, fmt.Errorf("failed to RSA encrypt the plain text. Error: %q", err)
	}
	return cipherText, nil
}

// RsaDecrypt decrypts the cipher text using the RSA private key.
func RsaDecrypt(privateKey *rsa.PrivateKey, cipherText []byte) ([]byte, error) {
	// plainText, err := rsa.DecryptOAEP(sha512.New(), rand.Reader, privateKey, cipherText, nil)
	plainText, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, cipherText)
	if err != nil {
		return cipherText, fmt.Errorf("failed to RSA encrypt the plain text. Error: %q", err)
	}
	return plainText, nil
}

// DeriveAesKeyAndIv returns an AES key and IV derived from the password and salt using PBKDF2 function.
func DeriveAesKeyAndIv(password, salt []byte) ([]byte, []byte) {
	aesKeyAndIv := pbkdf2.Key(password, salt, 10000, 32+16, sha256.New)
	return aesKeyAndIv[:32], aesKeyAndIv[32:]
}

// AesCbcEncryptWithPbkdf derives an AES key and IV using the given password and salt and then encrypts the plain text.
func AesCbcEncryptWithPbkdf(password, salt, plainText []byte) ([]byte, error) {

	// derive an AES key and IV using the password and the salt

	aesKey, iv := DeriveAesKeyAndIv(password, salt)

	// encrypt the workload using the AES key

	aesCipher, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create a new AES cipher using the key. Error: %q", err)
	}

	// pad the plain text as per PKCS#5 https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS#5_and_PKCS#7

	paddingRequired := aes.BlockSize - len(plainText)%aes.BlockSize
	if paddingRequired == 0 {
		paddingRequired = aes.BlockSize
	}
	padding := make([]byte, paddingRequired)
	for i := 0; i < paddingRequired; i++ {
		padding[i] = byte(paddingRequired)
	}

	paddedPlainText := append(plainText, padding...)
	cipherText := make([]byte, len(paddedPlainText))

	aesCbcEncrypter := cipher.NewCBCEncrypter(aesCipher, iv)
	aesCbcEncrypter.CryptBlocks(cipherText, paddedPlainText)
	return cipherText, nil
}

// AesCbcDecryptWithPbkdf derives an AES key and IV using the given password and salt and then decrypts the cipher text.
func AesCbcDecryptWithPbkdf(password, salt, cipherText []byte) ([]byte, error) {

	// derive an AES key and IV using the password and the salt

	aesKey, iv := DeriveAesKeyAndIv(password, salt)

	// encrypt the workload using the AES key

	aesCipher, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create a new AES cipher using the key. Error: %q", err)
	}

	paddedPlainText := make([]byte, len(cipherText))

	aesCbcDecrypter := cipher.NewCBCDecrypter(aesCipher, iv)
	aesCbcDecrypter.CryptBlocks(paddedPlainText, cipherText)

	// remove the PKCS#5 padding from the plain text https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS#5_and_PKCS#7
	paddingRequired := int(paddedPlainText[len(paddedPlainText)-1])
	plainText := paddedPlainText[:len(paddedPlainText)-paddingRequired]

	return plainText, nil
}

// ToOpenSSLFormat converts the cipher text to OpenSSL encrypted with password and salt format.
// http://justsolve.archiveteam.org/wiki/OpenSSL_salted_format
func ToOpenSSLFormat(salt, cipherText []byte) []byte {
	return append(append([]byte("Salted__"), salt...), cipherText...)
}
