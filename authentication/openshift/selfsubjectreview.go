package openshift

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/user"
	"path"
	"strings"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	k8suser "k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// SelfSubjectReview is a struct that implements the Token and Request interfaces.
type SelfSubjectReview struct {
	logger log.Logger
	// RemoteKubeConfigFile is the file to use to connect to a "normal" kube API server which hosts the
	// TokenAccessReview.authentication.k8s.io endpoint for checking tokens.
	RemoteKubeConfigFile string
}

// NewSelfSubjectReview creates a new instance of SelfSubjectReview.
func NewSelfSubjectReview(kubeCfgFile string, logger log.Logger) authenticator.Request {
	return &SelfSubjectReview{
		logger:               logger,
		RemoteKubeConfigFile: kubeCfgFile,
	}
}

// AuthenticateRequest implements the authenticator.Request interface.
func (s *SelfSubjectReview) AuthenticateRequest(req *http.Request) (*authenticator.Response, bool, error) {
	authHeader := req.Header.Get("Authorization")
	level.Debug(s.logger).Log("msg", "Extracting token from Authorization header", "header", authHeader)
	if authHeader == "" {
		return nil, false, nil
	}

	const bearerPrefix = "Bearer "
	if !strings.HasPrefix(authHeader, bearerPrefix) {
		return nil, false, fmt.Errorf("invalid authorization header format")
	}

	token := strings.TrimPrefix(authHeader, bearerPrefix)
	cfg, err := getConfig(s.RemoteKubeConfigFile)
	if err != nil {
		return nil, false, err
	}

	cfg = rest.AnonymousClientConfig(cfg)
	cfg.BearerToken = token
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, false, err
	}

	ssr, err := clientset.AuthenticationV1().SelfSubjectReviews().Create(context.Background(), &authenticationv1.SelfSubjectReview{}, metav1.CreateOptions{})
	if err != nil {
		return nil, false, err
	}

	level.Debug(s.logger).Log("msg", "SelfSubjectReview",
		"username", ssr.Status.UserInfo.Username,
		"uid", ssr.Status.UserInfo.UID,
		"groups", fmt.Sprintf("%v", ssr.Status.UserInfo.Groups),
		"extra", fmt.Sprintf("%v", ssr.Status.UserInfo.Extra))

	extra := make(map[string][]string)
	for k, v := range ssr.Status.UserInfo.Extra {
		extra[k] = v
	}
	return &authenticator.Response{
		User: &k8suser.DefaultInfo{
			Name:   ssr.Status.UserInfo.Username,
			UID:    ssr.Status.UserInfo.UID,
			Groups: ssr.Status.UserInfo.Groups,
			Extra:  extra,
		},
	}, true, nil
}

func getConfig(kubeconfig string) (*rest.Config, error) {
	if len(kubeconfig) > 0 {
		loader := &clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfig}
		return loadConfig(loader)
	}
	kubeconfigPath := os.Getenv(clientcmd.RecommendedConfigPathEnvVar)
	if len(kubeconfigPath) == 0 {
		return rest.InClusterConfig() //nolint:wrapcheck
	}
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if _, ok := os.LookupEnv("HOME"); !ok {
		u, err := user.Current()
		if err != nil {
			return nil, fmt.Errorf("could not get current user: %w", err)
		}
		p := path.Join(u.HomeDir, clientcmd.RecommendedHomeDir, clientcmd.RecommendedFileName)
		loadingRules.Precedence = append(loadingRules.Precedence, p)
	}
	return loadConfig(loadingRules)
}

func loadConfig(loader clientcmd.ClientConfigLoader) (*rest.Config, error) {
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loader, nil).ClientConfig() //nolint:wrapcheck
}
