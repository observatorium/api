package e2e

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/efficientgo/e2e"
	"github.com/efficientgo/tools/core/pkg/testutil"
	"github.com/pkg/errors"
)

func TestMetricsReadAndWrite(t *testing.T) {
	e, err := e2e.NewDockerEnvironment("e2e_observatorium_api")
	testutil.Ok(t, err)
	t.Cleanup(e.Close)

	certsContainerDir, err := copyTestDir(e.SharedDir(), "../../tmp/certs", "certs")
	testutil.Ok(t, err)

	configsContainerDir, err := copyTestDir(e.SharedDir(), "../config", "config")
	testutil.Ok(t, err)

	fmt.Println(certsContainerDir)

	readEndpoint, writeEndpoint, _, rateLimiter := startAndWaitOnBaseServices(t, e, configsContainerDir, certsContainerDir)

	api, err := newObservatoriumAPIService(
		e, "observatorium-api", "", "", "", readEndpoint, writeEndpoint,
		filepath.Join(configsContainerDir, "rbac.yaml"), filepath.Join(configsContainerDir, "tenants.yaml"),
		certsContainerDir, rateLimiter,
	)
	testutil.Ok(t, err)
	testutil.Ok(t, e2e.StartAndWaitReady(api))

}

// Starts and waits until all base services required for metrics test are ready.
func startAndWaitOnBaseServices(
	t *testing.T,
	e e2e.Environment,
	configsContainerDir string,
	certsContainerDir string,
) (metricsReadEndpoint string, metricsWriteEndpoint string, logsEndpoint string, rateLimiter string) {
	dex := newDexService(e, "observatorium-dex", filepath.Join(configsContainerDir, "dex.yaml"))
	gubernator := newGubernatorService(e, "observatorium-gubernator")
	thanosReceive := newThanosReceiveService(
		e, "observatorium-thanos-receive",
		"receive_replica=\"0\"",
		"1610b0c3-c509-4592-a256-a1871353dbfa",
		filepath.Join(configsContainerDir, "hashrings.json"),
	)
	thanosQuery := newThanosQueryService(
		e, "observatorium-thanos-query",
		thanosReceive.InternalEndpoint("grpc"),
	)
	loki := newLokiService(e, "observatorium-loki", filepath.Join(configsContainerDir, "loki.yml"))
	opa := newOPAService(e, "observatorium-opa", configsContainerDir)

	testutil.Ok(t, e2e.StartAndWaitReady(
		dex, gubernator, thanosReceive, thanosQuery, loki, opa,
	))

	createTenantsYAML(
		t,
		filepath.Join(e.SharedDir(), "config"),
		configsContainerDir,
		dex.InternalEndpoint("https"),
		certsContainerDir,
		opa.InternalEndpoint("http"),
	)

	return thanosQuery.InternalEndpoint("http"),
		thanosReceive.InternalEndpoint("http"),
		loki.InternalEndpoint("http"),
		gubernator.InternalEndpoint("grpc")
}

// copyTestDir copies a directory from host to the shared directory, returning
// path to where the directory is available within a container.
func copyTestDir(sharedDir string, srcDir string, dirName string) (string, error) {
	if err := exec.Command("cp", "-r", srcDir, sharedDir).Run(); err != nil {
		return "", errors.Wrap(err, fmt.Sprintf("copying dir %s", srcDir))
	}

	return filepath.Join(dockerLocalSharedDir, dirName), nil
}
