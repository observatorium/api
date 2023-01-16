package testtls

import (
	"fmt"
	stdlog "log"
	"os"
	"path/filepath"
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

func GenerateCerts(
	path string,
	apiCommonName string,
	apiSANs []string,
	dexCommonName string,
	dexSANs []string,
) error {
	var (
		defaultConfig        = config.DefaultConfig()
		defaultSigningConfig = config.SigningProfile{
			Expiry:       168 * time.Hour,
			ExpiryString: "168h",
		}

		caCommonName     = "observatorium"
		serverExpiration = defaultConfig.Expiry
		clientCommonName = "up"
		clientSANs       = "up"
		clientGroups     = "test"
		clientExpiration = defaultConfig.Expiry
	)

	caBundle, err := generateCACert(caCommonName)
	if err != nil {
		return fmt.Errorf("generate CA cert %s: %v", caCommonName, err)
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

	apiBundle, err := generateCert(apiCommonName, apiSANs, nil, "www", &serverSigningConfig, caBundle.cert, caBundle.key)
	if err != nil {
		return fmt.Errorf("generate server cert %s, %s: %v", apiCommonName, apiSANs, err)
	}

	dexBundle, err := generateCert(dexCommonName, dexSANs, nil, "www", &serverSigningConfig, caBundle.cert, caBundle.key)
	if err != nil {
		return fmt.Errorf("generate server cert %s, %s: %v", dexCommonName, dexSANs, err)
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

	clientBundle, err := generateCert(
		clientCommonName, signer.SplitHosts(clientSANs), signer.SplitHosts(clientGroups),
		"client", &clientSigningConfig, caBundle.cert, caBundle.key,
	)
	if err != nil {
		return fmt.Errorf("generate client cert %s, %s: %v", clientCommonName, clientSANs, err)
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

func generateCert(
	commonName string, hosts []string, groups []string, profile string,
	signingConfig *config.Signing, ca []byte, caKey []byte,
) (certBundle, error) {
	stdlog.Printf("cert generate, commonName=%s, hosts=%v, groups=%v, profile=%s, signingConfig=%+v\n",
		commonName, hosts, groups, profile, signingConfig)

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
