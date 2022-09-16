package crypto_test

import (
	// "crypto/sha512"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"io/ioutil"
	"testing"

	"foo.com/b/crypto"
)

const (
	INPUT_PASSWORD_BASE64    = `N1SWZDmnTDOOfwFu7KXfLc7cT3swy64QZNQpI0IWFYw=`
	INPUT_SALT_HEX           = `DE0B635DA1A926AE`
	EXPECTED_KEY_HEX         = `13AE8A12B8C7585DA261FE05FEEDBDC10BAC5F88274B49B42E8F40C26F23E61A`
	EXPECTED_IV_HEX          = `532ECB23E8270D78BA9CE3A94753848A`
	EXPECTED_WORKLOAD_BASE64 = `U2FsdGVkX1/eC2Ndoakmrh+HubIwGpSjJQ90mX+TkH129uBBwnhpcrc2/I7V2DpeCGJRe4mKAX98N+uM1Ub7t10LBGPwJ5fb6ik2Hha7uns6esOqTK0ExmCzFa1hf6loMDULYt7kqOEnaMlSczXIQwcpwyRR1SvZm9tLTw0jh40MQTxT601NPD9whagW1XzHZdd5wcqzPrOFhJ14kznNQdBokhgIk1LuQUBy5+4sofpD5Sc/dOX+nTYsGU5GB6ke5ZDTSWLjZG/HInswoUKG1oIT6gTc485yqeO1HlgVloFmRoZk/PfZNyEe4fXGpDQ5IMQ5NvdKXn7lM0fdgo5IHGfkt6jqEzmwB9q+at05TKQofhKf3ay/Ooq/ztjLKVCEYhsz6mh3pd4t00gckHg2sgUXXcuveI81iuppfY0M1AWik0XsCORQf4hl5E3yRdzxPX4th+yMbKasyNWw5fxPpKS8BO10KRdjteJksbmKhP2VYEPEgMqFOfQpYpSnvN7UHEUBxIrYC4Wy47JK7Y8VysooOzKAOjTXzlt+seCwNr7RQPNDGnoecx9YsqckNWvd76idTkb4/paCOvfW/pLDK51w26tozP+zd8tAzpwSn245bX8TEg6vjEu5AFrZnMAR1cm4Pd0ztJUZnyzDo7NaAmFFV4aN2/ZAew9U3O0WHnYKntiAHXthVkiS0H8LOZxQUWvhxXIIx91iD6wQ4sgSrxc3DLw2Ffbcw8a0OvHD/iYvfsqOV4FOjJxSCT7fwIctm9zrFrLKXYbObKQBZDCIKEFRDb7syrMIXUGan8QHl4cKVZ5/mtPc6nqP+Crh0QXpsJQa65KmLDo+n2/yBmYkXfiP3t+Sk7ROJP8IVWiw9L/dkpfCcVM5A17qckmJ6ak6lRR/DtAfnhPLz5LQsFfxE1v1FdZkT0GkgbeFSnOLtBPg1HhjMLeiKkOk63gjPQm7r5bEHXhdfupniUXuY7bj3yuNuE1gOK0y1Kt4DWP5zfcKp8Li9NMmF5FiwevV2PYndGDA3ahrcYxwplJRwo8Wd5Nu2ZWKCAa1veAfQDMfY0iIkZQXOIWP0zHWq7o9WhIsIbV3rx7NT7lfkh7I6ToDqKIGp2QUKlrNd2ojCVPfzgsT4xJ9Icz8wNUfkCn5WoIiDnfccSAy/40m/lF8Ui9xZc45Qh0Dz9EyRTD0BqH4dsVN6TcFaf0Fk5B6ODzAC4Enws+HC0z9NxdNuxWps0aOXIn76VD3wwdBHt1PdcVWRkq46Fc0szN6Awmpmi8WMP4hhFZCp69ENR9xIYGV/OehlGI7kiEx0QtMiqzn0k6AHnMAuLwJmHskG55p1tGiDfLhBCJLGrFQpi9MVExg5g0YBIedeIL6Mcn9nXXxKsMyg1HX+cgoW9nBbW2ftqj9yJo2vV83MZNtCoQB3I0S+2I/qyab7mq6xaYHIGbtC+xTHPOioI11DnL5S6NyGLK5vN/2Z0ltZtvYw3zYOGbJwf3GmbcAcg+NpogCEmOBr3MK2886uluHke1QslvV423sG/y7WsfKUat3NcoQ/LeoDOBRCth+2+eRE2yQIm17lc9Mm3vSvtJkwXvo8pFIuNn2dBse6qJQmwP17LlWxRLZalj3k+sl6AGXituAvZbnXt829UgcTpRd4A83uelbZL86Wvobgab38Qp8v763p1ViMxfw0FdWJusN1sOPSBPEiFfLbkA+So1PQS/Iti0vcYsVuEvPA5j8iGNjyBYrTGMd3nfdxMErPO5j80HJLJ0Qw3CJALJXS709lsCly3M2T5v6e7wFY85ZBQzclJ2YR8DtOOc09wIxr5P/jiC8nm3veFDphT/Y1dR2/hZbw4jgMiSulhlQI62JByI3AGf1r68GLF+GTBZiUAfecH77Hi+Alg6FncTnRJjkCbt/2GGgWopsFzhgW0oCe1D/aO7dmPUXf1ve7IgjpAufaUvolhaIrNp8F/hMKhhJapAWQQ733ez0U2uP`
	SELF_SIGNED_CERT         = `-----BEGIN CERTIFICATE-----
MIIFkzCCA3ugAwIBAgIUZn+6N9X8vcTBmoWMTRVof/rBDOAwDQYJKoZIhvcNAQEL
BQAwWTELMAkGA1UEBhMCSU4xEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDESMBAGA1UEAwwJbG9jYWxob3N0MB4X
DTIyMDkxNjA0MzUyOVoXDTIzMDkxNjA0MzUyOVowWTELMAkGA1UEBhMCSU4xEzAR
BgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5
IEx0ZDESMBAGA1UEAwwJbG9jYWxob3N0MIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
MIICCgKCAgEAmKV82mv0UdmhOnqKjxHppY7VnpURoHoFf27UpgVobBpxWN1v8dB4
eBpyPck0sRdm/ogGonwhMoxadXViQHiUGwcj0p9wKUh7RU7s21GOzEQ/Pl3kZS1s
RqfICCAJPaXtbeOMqFbyg6F6V0tlo/5aeStBVSX/Ac2aak34Lglql8KPVHWUZrk5
4ekao7sDQVgbgzGeys77ascMtoa5oLB1mHxdjRWVy5OJ0SC2b2fXrvZ8mvCfnkUO
QK/VYXJDwJ1BLoOGMN2eeTJCLBQU/bnKRb11bEfSLDXwnKPSjq9NOwIVNolKLG32
B1fQQlfB5JbLhW5iL0g+rCZsQpx2mYKXyozc0WagIDh1lyWRd7VirBnLv3/STEtB
r87hyPwaF6644fdQZny1UdGwy+VqsXlHBvV3fEZ6hqYe5QcJ0cLP+lfnBiX5utzO
sZ5jf2vMyGzDZLaentQC3OEqLPsWYiiCYJQV/A3IBL6vRNyUm5fvtLIS/q2nK79/
VzCJ1xVbGboPp7TdLNAZINycCCnVmfEI8dE204IOR6IOhKWMOjfSSdibQoLKpYa4
ipCBJ+afEA8Qiu7n45m1uSu1pHCPsnM7Gx96xBk6zLpzmucyJzffR+7G6THIx8uD
Fzed5LMUnxu7uhcKp3qq3bgMmTVK5MWumja7aKH2BhNV1icfrR2c2MMCAwEAAaNT
MFEwHQYDVR0OBBYEFECb1BtmitVWUtfntS/gJ/RSAAAiMB8GA1UdIwQYMBaAFECb
1BtmitVWUtfntS/gJ/RSAAAiMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL
BQADggIBACJox70CCQJnZvY3JaYfO1PkE7CZWG17Nm8tLnrPlxbpyMyl3L83TZlQ
oQCpmpdj2MaNDKYICGhbmW/7ZMJ9cmjA1qnqeDgzl1WXGRa+xV6KjQJftafXjQKI
PQ2rMHrTa2CepXspiXcxdGbo07J0VZJl8ixSEOaF4kDSM0DVJHBRq0rLJvxNnbNA
JWcjfVl9Z9aPTMjd3VwvhXJYLQtjPsEs0HkSFOxId5fuUZAQVopecE/7+q3jO5LK
6PYCUE4FckI5S9hTXQ+RQkhGryE65gsq8EIEd0URKR+TxrLgnLrfPxP6G9HDgLoo
zx9jCgHxexL4x0DvbheNtY0ObeaATZiaFAbOt5ZZHy+H3FGRCJznKJE1cnH9a4xt
Ja0HzAuGDzxg6PNCpeNowHsl3dlSbcP+iFaDERp+6KQHfflOjHJrJxkXmbOTKe6R
AsEHdL7z1rovJGiK4NxD2wpe8yI+ha2uxC6FjSQOzZ2i7jZ28GHu37RJ6kAY94Nr
pXsKatLxoIZfDdQQHCT2PV2zVyUkuGKPU3eoT8OaR4+uH0kO+l1WHI/2Zhm6e86W
JSU89oPKNxGhAX5OPWh175IHJCsEuquUjWdS42A3NStTHukGQAoJvdyKcFxQgNlh
yweFOtmTGKxiy63F2fCtKZ9MALa129R43NHM9pjxBja1kw2uaFmV
-----END CERTIFICATE-----`
	SELF_SIGNED_CERT_KEY = `-----BEGIN PRIVATE KEY-----
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
Jrtusaw9HalZMRj6ErTu4VqP2e3T2g==
-----END PRIVATE KEY-----`
)

var (
	INPUT_CERTIFICATE   = ``
	INPUT_WORKLOAD_YAML = ``
)

func init() {
	certBytes, err := ioutil.ReadFile("testdata/certificate.crt")
	if err != nil {
		panic(err)
	}
	INPUT_CERTIFICATE = string(certBytes)
	workloadBytes, err := ioutil.ReadFile("testdata/workload.yaml")
	if err != nil {
		panic(err)
	}
	INPUT_WORKLOAD_YAML = string(workloadBytes)
}

func TestGetRandomBytes(t *testing.T) {
	t.Run("get some random bytes", func(t *testing.T) {
		bs, err := crypto.GetRandomBytes(16)
		if err != nil {
			t.Fatalf("failed to generate 16 random bytes. Error: %q", err)
		}
		if len(bs) != 16 {
			t.Fatalf("failed to generate 16 random bytes. Actual: %d %+v", len(bs), bs)
		}
	})
}

func TestRsaEncrypt(t *testing.T) {
	t.Run("encrypt with a proper cert", func(t *testing.T) {
		publicKey, err := crypto.GetRSAPublicKeyFromCertificate([]byte(INPUT_CERTIFICATE))
		if err != nil {
			t.Fatalf("failed to parse the certificate and get the RSA public key from it. Error: %q", err)
		}
		password, err := base64.StdEncoding.DecodeString(INPUT_PASSWORD_BASE64)
		if err != nil {
			t.Fatalf("failed to decode the base64 encoded password. Error: %q", err)
		}

		// encrypt the password using the public key from the certificate

		encryptedPassword, err := crypto.RsaEncrypt(publicKey, password)
		if err != nil {
			t.Fatalf("failed to encrypt the password using the RSA public key. Error: %q", err)
		}
		if len(encryptedPassword) != 512 {
			t.Fatalf("length of the cipher text is different. Expected: 512 Actual: %d", len(encryptedPassword))
		}
	})

	t.Run("encrypt and decrypt with self-signed cert and key", func(t *testing.T) {
		publicKey, err := crypto.GetRSAPublicKeyFromCertificate([]byte(SELF_SIGNED_CERT))
		if err != nil {
			t.Fatalf("failed to parse the certificate and get the RSA public key from it. Error: %q", err)
		}
		privateKey, err := crypto.GetRSAPrivateKey([]byte(SELF_SIGNED_CERT_KEY))
		if err != nil {
			t.Fatalf("failed to parse the certificate and get the RSA public key from it. Error: %q", err)
		}

		password, err := base64.StdEncoding.DecodeString(INPUT_PASSWORD_BASE64)
		if err != nil {
			t.Fatalf("failed to decode the base64 encoded password. Error: %q", err)
		}

		// encrypt the password using the public key from the certificate

		encryptedPassword, err := crypto.RsaEncrypt(publicKey, password)
		if err != nil {
			t.Fatalf("failed to encrypt the password using the RSA public key. Error: %q", err)
		}

		decryptedPassword, err := crypto.RsaDecrypt(privateKey, encryptedPassword)
		if err != nil {
			t.Fatalf("failed to decrypt the password using the RSA private key. Error: %q", err)
		}

		// test to see if the encrypted passwords are the same

		if !bytes.Equal(decryptedPassword, password) {
			t.Fatalf("the decrypted password and the original are different. Expected: %+v Actual: %+v", len(password), len(decryptedPassword))
		}
	})
}

func TestDeriveAesKeyAndIv(t *testing.T) {
	t.Run("derive a key and iv", func(t *testing.T) {
		password, err := base64.StdEncoding.DecodeString(INPUT_PASSWORD_BASE64)
		if err != nil {
			t.Fatalf("failed to decode the base64 encoded password. Error: %q", err)
		}

		salt, err := hex.DecodeString(INPUT_SALT_HEX)
		if err != nil {
			t.Fatalf("failed to decode the salt hex string as bytes. Error: %q", err)
		}
		aesKey, iv := crypto.DeriveAesKeyAndIv(password, salt)
		expectedAesKey, err := hex.DecodeString(EXPECTED_KEY_HEX)
		if err != nil {
			t.Fatalf("failed to decode the expected AES key hex string as bytes. Error: %q", err)
		}
		if !bytes.Equal(aesKey, expectedAesKey) {
			t.Fatalf("AES key is different. Expected: %+v Actual: %+v", expectedAesKey, aesKey)
		}
		expectedIv, err := hex.DecodeString(EXPECTED_IV_HEX)
		if err != nil {
			t.Fatalf("failed to decode the expected iv hex string as bytes. Error: %q", err)
		}
		if !bytes.Equal(aesKey, expectedAesKey) {
			t.Fatalf("IV is different. Expected: %+v Actual: %+v", expectedIv, iv)
		}
	})
}

func TestAesCbcEncryptWithPbkdf(t *testing.T) {
	t.Run("encrypt a message and then decrypt", func(t *testing.T) {
		password, err := base64.StdEncoding.DecodeString(INPUT_PASSWORD_BASE64)
		if err != nil {
			t.Fatalf("failed to decode the base64 encoded password. Error: %q", err)
		}

		salt, err := hex.DecodeString(INPUT_SALT_HEX)
		if err != nil {
			t.Fatalf("failed to decode the salt hex string as bytes. Error: %q", err)
		}

		workload := []byte(INPUT_WORKLOAD_YAML)
		encryptedWorkload, err := crypto.AesCbcEncryptWithPbkdf(password, salt, workload)
		if err != nil {
			t.Fatalf("failed to encrypt the workload using AES CBC. Error: %q", err)
		}

		encryptedWorkloadInOpenSSLFormat := crypto.ToOpenSSLFormat(salt, encryptedWorkload)

		// test to see if the encrypted workloads are the same

		expectedEncryptedWorkload, err := base64.StdEncoding.DecodeString(EXPECTED_WORKLOAD_BASE64)
		if err != nil {
			t.Fatalf("failed to decode the base64 encrypted workload. Error: %q", err)
		}

		if !bytes.Equal(encryptedWorkloadInOpenSSLFormat, expectedEncryptedWorkload) {
			for i := 0; i < len(encryptedWorkloadInOpenSSLFormat); i++ {
				if encryptedWorkloadInOpenSSLFormat[i] != expectedEncryptedWorkload[i] {
					t.Errorf("DIFFERENT AT INDEX: %d expected %v actual %v", i, expectedEncryptedWorkload[i], encryptedWorkloadInOpenSSLFormat[i])
				}
			}
			t.Fatalf("the encrypted workload and the expected are different. Expected: %+v Actual: %+v", len(expectedEncryptedWorkload), len(encryptedWorkload))
		}

		decryptedWorkload, err := crypto.AesCbcDecryptWithPbkdf(password, salt, encryptedWorkload)
		if err != nil {
			t.Fatalf("failed to decrypt the workload using AES CBC. Error: %q", err)
		}
		if !bytes.Equal(decryptedWorkload, workload) {
			t.Fatalf("the decrypted workload and the expected are different. Expected: %+v Actual: %+v", len(workload), len(decryptedWorkload))
		}
	})
}
