package testtls

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

const expireDays = 1

type certBundle struct {
	cert []byte
	key  []byte
}

func GenerateCerts(
	path string,
	apiCommonName string,
	apiSANs []string,
	dexCommonName string,
	dexSANs []string,
) error {
	var (
		caCommonName     = "observatorium"
		clientCommonName = "up"
		clientSANs       = "up"
		clientGroups     = "test"
	)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return err
	}
	ca := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: caCommonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, expireDays),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return err
	}

	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	caPrivKeyPEM := new(bytes.Buffer)
	key, err := x509.MarshalECPrivateKey(caPrivKey)
	if err != nil {
		return err
	}
	pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: key,
	})
	caBundle := certBundle{
		cert: caPEM.Bytes(),
		key:  caPrivKeyPEM.Bytes(),
	}

	apiBundle, err := generateCert(ca, caPrivKey, false, apiCommonName, apiSANs, nil)
	if err != nil {
		return err
	}
	dexBundle, err := generateCert(ca, caPrivKey, false, dexCommonName, dexSANs, nil)
	if err != nil {
		return err
	}
	clientBundle, err := generateCert(ca, caPrivKey, true, clientCommonName, []string{clientSANs}, []string{clientGroups})
	if err != nil {
		return err
	}

	for file, content := range map[string][]byte{
		"ca.key":     caBundle.key,
		"ca.pem":     caBundle.cert,
		"server.key": apiBundle.key,
		"server.pem": apiBundle.cert,
		"dex.key":    dexBundle.key,
		"dex.pem":    dexBundle.cert,
		"client.key": clientBundle.key,
		"client.pem": clientBundle.cert,
	} {
		// Write certificates
		if err := os.MkdirAll(path, 0750); err != nil {
			return fmt.Errorf("mkdir %s: %v", path, err)
		}

		if err := os.WriteFile(filepath.Join(path, file), content, 0644); err != nil {
			return fmt.Errorf("write file %s: %v", file, err)
		}
	}
	return nil
}

func generateCert(caCert *x509.Certificate, caPrivateKey crypto.Signer, client bool, commonName string, dnsNames []string, ou []string) (*certBundle, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}
	apiCert := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         commonName,
			OrganizationalUnit: ou,
		},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:   time.Now(),

		NotAfter:              time.Now().AddDate(0, 0, expireDays),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		DNSNames:              dnsNames,
		BasicConstraintsValid: true,
		IsCA:                  false,
		AuthorityKeyId:        caCert.SubjectKeyId,
	}
	if client {
		apiCert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	certPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, apiCert, caCert, &certPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		return nil, err
	}

	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	key, err := x509.MarshalECPrivateKey(certPrivateKey)
	if err != nil {
		return nil, err
	}
	certPrivateKeyPEM := new(bytes.Buffer)
	pem.Encode(certPrivateKeyPEM, &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: key,
	})
	return &certBundle{
		cert: certPEM.Bytes(),
		key:  certPrivateKeyPEM.Bytes(),
	}, nil
}
