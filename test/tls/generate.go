// +build tools

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/cloudflare/cfssl/cli/genkey"
	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/initca"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/local"
)

type certBundle struct {
	cert []byte
	key  []byte
}

func main() {
	var (
		caCommonName     string
		serverCommonName string
		serverSANs       string
		serverExpiration time.Duration
		clientCommonName string
		clientSANs       string
		clientGroups     string
		clientExpiration time.Duration

		defaultConfig        = config.DefaultConfig()
		defaultSigningConfig = config.SigningProfile{
			Expiry:       168 * time.Hour,
			ExpiryString: "168h",
		}
	)

	flag.StringVar(&caCommonName, "root-common-name", "observatorium", "")
	flag.StringVar(&serverCommonName, "server-common-name", "localhost", "")
	flag.StringVar(&serverSANs, "server-sans", "localhost,127.0.0.1", "A comma-separated list of SANs for the client.")
	flag.DurationVar(&serverExpiration, "server-duration", defaultConfig.Expiry, "")
	flag.StringVar(&clientCommonName, "client-common-name", "up", "")
	flag.StringVar(&clientSANs, "client-sans", "up", "A comma-separated list of SANs for the client.")
	flag.StringVar(&clientGroups, "client-groups", "test", "A comma-separated list of groups for the client.")
	flag.DurationVar(&clientExpiration, "client-duration", defaultConfig.Expiry, "")
	flag.Parse()

	caBundle, err := generateCACert(caCommonName)
	if err != nil {
		fmt.Printf("generate CA cert %s: %v\n", caCommonName, err)
		os.Exit(1)
	}

	serverSigningConfig := config.Signing{
		Default: &defaultSigningConfig,
		Profiles: map[string]*config.SigningProfile{
			"www": {
				Expiry:       serverExpiration,
				ExpiryString: serverExpiration.String(),
				Usage:        []string{"signing", "key encipherment", "server auth"},
			},
		},
	}

	serverBundle, err := generateCert(serverCommonName, signer.SplitHosts(serverSANs), nil, "www", &serverSigningConfig, caBundle.cert, caBundle.key)
	if err != nil {
		fmt.Printf("generate server cert %s, %s: %v\n", serverCommonName, serverSANs, err)
		os.Exit(1)
	}

	clientSigningConfig := config.Signing{
		Default: &defaultSigningConfig,
		Profiles: map[string]*config.SigningProfile{
			"client": {
				Expiry:       clientExpiration,
				ExpiryString: clientExpiration.String(),
				Usage:        []string{"signing", "key encipherment", "client auth"},
			},
		},
	}

	clientBundle, err := generateCert(clientCommonName, signer.SplitHosts(clientSANs), signer.SplitHosts(clientGroups), "client", &clientSigningConfig, caBundle.cert, caBundle.key)
	if err != nil {
		fmt.Printf("generate client cert %s, %s: %v\n", clientCommonName, clientSANs, err)
		os.Exit(1)
	}

	for file, content := range map[string][]byte{
		"ca.key":     caBundle.key,
		"ca.pem":     caBundle.cert,
		"server.key": serverBundle.key,
		"server.pem": serverBundle.cert,
		"client.key": clientBundle.key,
		"client.pem": clientBundle.cert,
	} {
		// Write certificates
		if err := ioutil.WriteFile(file, content, 0644); err != nil {
			fmt.Printf("write file: %v\n", err)
			os.Exit(1)
		}
	}
}

// Helpers

func generateCACert(commonName string) (certBundle, error) {
	cert, _, key, err := initca.New(&csr.CertificateRequest{
		CN:         commonName,
		KeyRequest: csr.NewKeyRequest(),
	})
	if err != nil {
		return certBundle{}, fmt.Errorf("initca: %w", err)
	}

	return certBundle{cert: cert, key: key}, nil
}

func generateCert(commonName string, hosts []string, groups []string, profile string, signingConfig *config.Signing, ca []byte, caKey []byte) (certBundle, error) {
	fmt.Printf("cert generate, commonName=%s, hosts=%v, groups=%v, profile=%s, signingConfig=%+v\n", commonName, hosts, groups, profile, signingConfig)
	names := make([]csr.Name, 0, len(groups))
	for _, g := range groups {
		names = append(names, csr.Name{OU: g})
	}
	req := csr.CertificateRequest{
		CN:         commonName,
		Names:      names,
		Hosts:      hosts,
		KeyRequest: csr.NewKeyRequest(),
	}

	g := &csr.Generator{Validator: genkey.Validator}
	csrBytes, key, err := g.ProcessRequest(&req)
	if err != nil {
		return certBundle{}, fmt.Errorf("process request (%+v): %w", req, err)
	}

	signReq := signer.SignRequest{
		Request: string(csrBytes),
		Hosts:   hosts,
		Profile: profile,
	}

	parsedCa, err := helpers.ParseCertificatePEM(ca)
	if err != nil {
		return certBundle{}, fmt.Errorf("parse certificate pem: %w", err)
	}

	priv, err := helpers.ParsePrivateKeyPEMWithPassword(caKey, []byte{})
	if err != nil {
		return certBundle{}, fmt.Errorf("parse private key pem with password: %w", err)
	}

	s, err := local.NewSigner(priv, parsedCa, signer.DefaultSigAlgo(priv), signingConfig)
	if err != nil {
		return certBundle{}, fmt.Errorf("new signer: %w", err)
	}

	cert, err := s.Sign(signReq)
	if err != nil {
		return certBundle{}, fmt.Errorf("sign: %w", err)
	}

	return certBundle{cert: cert, key: key}, nil
}
