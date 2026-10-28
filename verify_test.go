package pkcs7

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io/ioutil"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestVerify(t *testing.T) {
	fixture := UnmarshalTestFixture(SignedTestFixture)
	p7, err := Parse(fixture.Input)
	if err != nil {
		t.Errorf("Parse encountered unexpected error: %v", err)
	}

	if err := p7.Verify(); err != nil {
		t.Errorf("Verify failed with error: %v", err)
	}
	expected := []byte("We the People")
	if !bytes.Equal(p7.Content, expected) {
		t.Errorf("Signed content does not match.\n\tExpected:%s\n\tActual:%s", expected, p7.Content)
	}
}

func TestVerifyAppStore(t *testing.T) {
	fixture := UnmarshalTestFixture(AppStoreReceiptFixture)
	p7, err := Parse(fixture.Input)
	if err != nil {
		t.Errorf("Parse encountered unexpected error: %v", err)
	}
	if err := p7.Verify(); err != nil {
		t.Errorf("Verify failed with error: %v", err)
	}
}

func TestVerifyApkEcdsa(t *testing.T) {
	fixture := UnmarshalTestFixture(ApkEcdsaFixture)
	p7, err := Parse(fixture.Input)
	if err != nil {
		t.Errorf("Parse encountered unexpected error: %v", err)
	}
	p7.Content, err = base64.StdEncoding.DecodeString(ApkEcdsaContent)
	if err != nil {
		t.Errorf("Failed to decode base64 signature file: %v", err)
	}
	if err := p7.Verify(); err != nil {
		t.Errorf("Verify failed with error: %v", err)
	}
}

func TestVerifyFirefoxAddon(t *testing.T) {
	fixture := UnmarshalTestFixture(FirefoxAddonFixture)
	p7, err := Parse(fixture.Input)
	if err != nil {
		t.Errorf("Parse encountered unexpected error: %v", err)
	}
	p7.Content = FirefoxAddonContent
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(FirefoxAddonRootCert)
	// verifies at the signingTime authenticated attr
	if err := p7.VerifyWithChain(certPool); err != nil {
		t.Errorf("Verify failed with error: %v", err)
	}

	// The chain has validity:
	//
	// EE:           2016-08-17 20:04:58 +0000 UTC 2021-08-16 20:04:58 +0000 UTC
	// Intermediate: 2015-03-17 23:52:42 +0000 UTC 2025-03-14 23:52:42 +0000 UTC
	// Root:         2015-03-17 22:53:57 +0000 UTC 2025-03-14 22:53:57 +0000 UTC
	validTime := time.Date(2021, 8, 16, 20, 0, 0, 0, time.UTC)
	if err = p7.VerifyWithChainAtTime(certPool, validTime); err != nil {
		t.Errorf("Verify at UTC now failed with error: %v", err)
	}

	expiredTime := time.Date(2030, time.January, 1, 0, 0, 0, 0, time.UTC)
	if err = p7.VerifyWithChainAtTime(certPool, expiredTime); err == nil {
		t.Errorf("Verify at expired time %s did not error", expiredTime)
	}
	notYetValidTime := time.Date(1999, time.July, 5, 0, 13, 0, 0, time.UTC)
	if err = p7.VerifyWithChainAtTime(certPool, notYetValidTime); err == nil {
		t.Errorf("Verify at not yet valid time %s did not error", notYetValidTime)
	}

	// Verify the certificate chain to make sure the identified root
	// is the one we expect
	ee := getCertFromCertsByIssuerAndSerial(p7.Certificates, p7.Signers[0].IssuerAndSerialNumber)
	if ee == nil {
		t.Errorf("No end-entity certificate found for signer")
	}
	signingTime := mustParseTime("2017-02-23T09:06:16-05:00")
	chains, err := verifyCertChain(ee, p7.Certificates, certPool, signingTime)
	if err != nil {
		t.Error(err)
	}
	if len(chains) != 1 {
		t.Errorf("Expected to find one chain, but found %d", len(chains))
	}
	if len(chains[0]) != 3 {
		t.Errorf("Expected to find three certificates in chain, but found %d", len(chains[0]))
	}
	if chains[0][0].Subject.CommonName != "tabscope@xuldev.org" {
		t.Errorf("Expected to find EE certificate with subject 'tabscope@xuldev.org', but found '%s'", chains[0][0].Subject.CommonName)
	}
	if chains[0][1].Subject.CommonName != "production-signing-ca.addons.mozilla.org" {
		t.Errorf("Expected to find intermediate certificate with subject 'production-signing-ca.addons.mozilla.org', but found '%s'", chains[0][1].Subject.CommonName)
	}
	if chains[0][2].Subject.CommonName != "root-ca-production-amo" {
		t.Errorf("Expected to find root certificate with subject 'root-ca-production-amo', but found '%s'", chains[0][2].Subject.CommonName)
	}
}

func mustParseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

// sign a document with openssl and verify the signature with pkcs7.
// this uses a chain of root, intermediate and signer cert, where the
// intermediate is added to the certs but the root isn't.
func TestSignWithOpenSSLAndVerify(t *testing.T) {
	content := []byte(`
A ship in port is safe,
but that's not what ships are built for.
-- Grace Hopper`)
	// write the content to a temp file
	tmpContentFile, err := ioutil.TempFile("", "TestSignWithOpenSSLAndVerify_content")
	if err != nil {
		t.Fatal(err)
	}
	ioutil.WriteFile(tmpContentFile.Name(), content, 0o755)
	sigalgs := []x509.SignatureAlgorithm{
		x509.SHA256WithRSA,
		x509.SHA512WithRSA,
		x509.ECDSAWithSHA256,
		x509.ECDSAWithSHA384,
		x509.ECDSAWithSHA512,
	}
	for _, sigalgroot := range sigalgs {
		rootCert, err := createTestCertificateByIssuer("PKCS7 Test Root CA", nil, sigalgroot, true)
		if err != nil {
			t.Fatalf("test %s: cannot generate root cert: %s", sigalgroot, err)
		}
		truststore := x509.NewCertPool()
		truststore.AddCert(rootCert.Certificate)
		for _, sigalginter := range sigalgs {
			interCert, err := createTestCertificateByIssuer("PKCS7 Test Intermediate Cert", rootCert, sigalginter, true)
			if err != nil {
				t.Fatalf("test %s/%s: cannot generate intermediate cert: %s", sigalgroot, sigalginter, err)
			}
			// write the intermediate cert to a temp file
			tmpInterCertFile, err := ioutil.TempFile("", "TestSignWithOpenSSLAndVerify_intermediate")
			if err != nil {
				t.Fatal(err)
			}
			fd, err := os.OpenFile(tmpInterCertFile.Name(), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
			if err != nil {
				t.Fatal(err)
			}
			pem.Encode(fd, &pem.Block{Type: "CERTIFICATE", Bytes: interCert.Certificate.Raw})
			fd.Close()
			for _, sigalgsigner := range sigalgs {
				signerCert, err := createTestCertificateByIssuer("PKCS7 Test Signer Cert", interCert, sigalgsigner, false)
				if err != nil {
					t.Fatalf("test %s/%s/%s: cannot generate signer cert: %s", sigalgroot, sigalginter, sigalgsigner, err)
				}

				// write the signer cert to a temp file
				tmpSignerCertFile, err := ioutil.TempFile("", "TestSignWithOpenSSLAndVerify_signer")
				if err != nil {
					t.Fatal(err)
				}
				fd, err = os.OpenFile(tmpSignerCertFile.Name(), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
				if err != nil {
					t.Fatal(err)
				}
				pem.Encode(fd, &pem.Block{Type: "CERTIFICATE", Bytes: signerCert.Certificate.Raw})
				fd.Close()

				// write the signer key to a temp file
				tmpSignerKeyFile, err := ioutil.TempFile("", "TestSignWithOpenSSLAndVerify_key")
				if err != nil {
					t.Fatal(err)
				}
				fd, err = os.OpenFile(tmpSignerKeyFile.Name(), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
				if err != nil {
					t.Fatal(err)
				}
				var derKey []byte
				priv := *signerCert.PrivateKey
				switch priv.(type) {
				case *rsa.PrivateKey:
					derKey = x509.MarshalPKCS1PrivateKey(priv.(*rsa.PrivateKey))
					pem.Encode(fd, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: derKey})
				case *ecdsa.PrivateKey:
					derKey, err = x509.MarshalECPrivateKey(priv.(*ecdsa.PrivateKey))
					if err != nil {
						t.Fatal(err)
					}
					pem.Encode(fd, &pem.Block{Type: "EC PRIVATE KEY", Bytes: derKey})
				}
				fd.Close()

				// write the root cert to a temp file
				tmpSignedFile, err := ioutil.TempFile("", "TestSignWithOpenSSLAndVerify_signature")
				if err != nil {
					t.Fatal(err)
				}
				// call openssl to sign the content
				opensslCMD := exec.Command("openssl", "smime", "-sign", "-nodetach",
					"-in", tmpContentFile.Name(), "-out", tmpSignedFile.Name(),
					"-signer", tmpSignerCertFile.Name(), "-inkey", tmpSignerKeyFile.Name(),
					"-certfile", tmpInterCertFile.Name(), "-outform", "PEM")
				out, err := opensslCMD.CombinedOutput()
				if err != nil {
					t.Fatalf("test %s/%s/%s: openssl command failed with %s: %s", sigalgroot, sigalginter, sigalgsigner, err, out)
				}

				// verify the signed content
				pemSignature, err := ioutil.ReadFile(tmpSignedFile.Name())
				if err != nil {
					t.Fatal(err)
				}
				derBlock, _ := pem.Decode(pemSignature)
				if derBlock == nil {
					break
				}
				p7, err := Parse(derBlock.Bytes)
				if err != nil {
					t.Fatalf("Parse encountered unexpected error: %v", err)
				}
				if err := p7.VerifyWithChain(truststore); err != nil {
					t.Fatalf("Verify failed with error: %v", err)
				}
				// Verify the certificate chain to make sure the identified root
				// is the one we expect
				ee := getCertFromCertsByIssuerAndSerial(p7.Certificates, p7.Signers[0].IssuerAndSerialNumber)
				if ee == nil {
					t.Fatalf("No end-entity certificate found for signer")
				}
				chains, err := verifyCertChain(ee, p7.Certificates, truststore, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				if len(chains) != 1 {
					t.Fatalf("Expected to find one chain, but found %d", len(chains))
				}
				if len(chains[0]) != 3 {
					t.Fatalf("Expected to find three certificates in chain, but found %d", len(chains[0]))
				}
				if chains[0][0].Subject.CommonName != "PKCS7 Test Signer Cert" {
					t.Fatalf("Expected to find EE certificate with subject 'PKCS7 Test Signer Cert', but found '%s'", chains[0][0].Subject.CommonName)
				}
				if chains[0][1].Subject.CommonName != "PKCS7 Test Intermediate Cert" {
					t.Fatalf("Expected to find intermediate certificate with subject 'PKCS7 Test Intermediate Cert', but found '%s'", chains[0][1].Subject.CommonName)
				}
				if chains[0][2].Subject.CommonName != "PKCS7 Test Root CA" {
					t.Fatalf("Expected to find root certificate with subject 'PKCS7 Test Root CA', but found '%s'", chains[0][2].Subject.CommonName)
				}
				os.Remove(tmpSignerCertFile.Name()) // clean up
				os.Remove(tmpSignerKeyFile.Name())  // clean up
			}
			os.Remove(tmpInterCertFile.Name()) // clean up
		}
	}
	os.Remove(tmpContentFile.Name()) // clean up
}

func TestVerifyWithEmptySequence(t *testing.T) {
	content, err := base64.StdEncoding.DecodeString(SignedWithEmptySequence)
	if err != nil {
		t.Fatal(err)
	}
	p7, err := Parse(content)
	if err != nil {
		t.Fatalf("Parse encountered unexpected error: %v", err)
	}

	p7.Content, err = base64.StdEncoding.DecodeString(SignedWithEmptySequenceDigiest)
	if err != nil {
		t.Fatal(err)
	}
	if err := p7.Verify(); err != nil {
		t.Fatalf("Verify failed with error: %v", err)
	}
}
