package openshift

import (
	"fmt"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	af "k8s.io/apiserver/pkg/authentication/authenticatorfactory"
	"k8s.io/apiserver/pkg/authentication/request/headerrequest"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	authenticationclient "k8s.io/client-go/kubernetes/typed/authentication/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type RequestHeaderAuthenticationOptions struct {
	UsernameHeaders     StringSlice
	GroupHeaders        StringSlice
	ExtraHeaderPrefixes StringSlice
	ClientCAFile        string
	AllowedNames        StringSlice
}

type StringSlice []string

func (s *StringSlice) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func (s *StringSlice) String() string {
	return strings.Join(*s, " ")
}

// ToAuthenticationRequestHeaderConfig returns a RequestHeaderConfig config object for these options
// if necessary, nil otherwise.
func (s *RequestHeaderAuthenticationOptions) ToAuthenticationRequestHeaderConfig() (*af.RequestHeaderConfig, error) {
	if len(s.ClientCAFile) == 0 {
		return nil, nil
	}

	dynamicCAProvider, err := dynamiccertificates.NewDynamicCAContentFromFile("request-header", s.ClientCAFile)
	if err != nil {
		return nil, err
	}

	return &af.RequestHeaderConfig{
		UsernameHeaders:     headerrequest.StaticStringSlice(s.UsernameHeaders),
		GroupHeaders:        headerrequest.StaticStringSlice(s.GroupHeaders),
		ExtraHeaderPrefixes: headerrequest.StaticStringSlice(s.ExtraHeaderPrefixes),
		CAContentProvider:   dynamicCAProvider,
		AllowedClientNames:  headerrequest.StaticStringSlice(s.AllowedNames),
	}, nil
}

type ClientCertAuthenticationOptions struct {
	// ClientCA is the certificate bundle for all the signers that you'll recognize for incoming client certificates
	ClientCA string
}

// DelegatingAuthenticationOptions provides an easy way for composing API servers to delegate their authentication to
// the root kube API server.  The API federator will act as a front proxy and direction connections will be able to
// delegate to the core kube API server.
type DelegatingAuthenticationOptions struct {
	// RemoteKubeConfigFile is the file to use to connect to a "normal" kube API server which hosts the
	// TokenAccessReview.authentication.k8s.io endpoint for checking tokens.
	RemoteKubeConfigFile string

	// WebhookRetryBackoff specifies the backoff parameters for the authentication webhook retry logic.
	// This allows us to configure the sleep time at each iteration and the maximum number of retries allowed
	// before we fail the webhook call in order to limit the fan out that ensues when the system is degraded.
	WebhookRetryBackoff *wait.Backoff

	// CacheTTL is the length of time that a token authentication answer will be cached.
	CacheTTL time.Duration

	ClientCert    ClientCertAuthenticationOptions
	RequestHeader RequestHeaderAuthenticationOptions

	SkipInClusterLookup bool
}

func (s *DelegatingAuthenticationOptions) ToAuthenticationConfig() (af.DelegatingAuthenticatorConfig, error) {
	tokenClient, err := s.newAuthenticationClient()
	if err != nil {
		return af.DelegatingAuthenticatorConfig{}, err
	}

	clientCA, err := s.getClientCA()
	if err != nil {
		return af.DelegatingAuthenticatorConfig{}, err
	}

	requestHeader, err := s.getRequestHeader()
	if err != nil {
		return af.DelegatingAuthenticatorConfig{}, err
	}

	requestHeaderConfig, err := requestHeader.ToAuthenticationRequestHeaderConfig()
	if err != nil {
		return af.DelegatingAuthenticatorConfig{}, err
	}

	var clientCAProvider *dynamiccertificates.DynamicFileCAContent
	if len(clientCA.ClientCA) > 0 {
		clientCAProvider, err = dynamiccertificates.NewDynamicCAContentFromFile("client-ca-bundle", clientCA.ClientCA)
		if err != nil {
			return af.DelegatingAuthenticatorConfig{}, err
		}
	}

	ret := af.DelegatingAuthenticatorConfig{
		Anonymous:                          false,
		TokenAccessReviewClient:            tokenClient,
		CacheTTL:                           s.CacheTTL,
		ClientCertificateCAContentProvider: clientCAProvider,
		RequestHeaderConfig:                requestHeaderConfig,
		WebhookRetryBackoff:                s.WebhookRetryBackoff,
	}

	return ret, nil
}

func (s *DelegatingAuthenticationOptions) getClientCA() (*ClientCertAuthenticationOptions, error) {
	if len(s.ClientCert.ClientCA) > 0 || s.SkipInClusterLookup {
		return &s.ClientCert, nil
	}

	return nil, fmt.Errorf("no client ca-file config")
}

func (s *DelegatingAuthenticationOptions) getRequestHeader() (*RequestHeaderAuthenticationOptions, error) {
	if len(s.RequestHeader.ClientCAFile) > 0 || s.SkipInClusterLookup {
		return &s.RequestHeader, nil
	}

	return nil, fmt.Errorf("no request header config")
}

func (s *DelegatingAuthenticationOptions) newAuthenticationClient() (authenticationclient.AuthenticationV1Interface, error) {
	clientConfig, err := getClientConfig(s.RemoteKubeConfigFile)
	if err != nil {
		return nil, err
	}

	client, err := authenticationclient.NewForConfig(clientConfig)
	if err != nil {
		return nil, err
	}

	return client, nil
}

func getClientConfig(remoteKubeConfigFile string) (*rest.Config, error) {
	var (
		clientConfig *rest.Config
		err          error
	)

	if len(remoteKubeConfigFile) > 0 {
		loadingRules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: remoteKubeConfigFile}
		loader := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, &clientcmd.ConfigOverrides{})

		clientConfig, err = loader.ClientConfig()
	} else {
		// without the remote kubeconfig file, try to use the in-cluster config.  Most addon API servers will
		// use this path
		clientConfig, err = rest.InClusterConfig()
	}

	if err != nil {
		return nil, err
	}

	// set high qps/burst limits since this will effectively limit API server responsiveness
	clientConfig.QPS = 200
	clientConfig.Burst = 400

	return clientConfig, nil
}
