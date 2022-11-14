package tests

import (
	"testing"

	"github.com/gruntwork-io/terratest/modules/terraform"
	"github.com/rancher/rancher/tests/framework/clients/rancher"
	"github.com/rancher/rancher/tests/framework/extensions/clusters"
	"github.com/rancher/rancher/tests/framework/pkg/config"
	"github.com/rancher/rancher/tests/framework/pkg/session"
	"github.com/rancher/rancher/tests/terratest/functions"
	"github.com/rancher/rancher/tests/terratest/tests"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLinodeK3sK8sUpgrade(t *testing.T) {
	t.Parallel()

	module   := "linode_k3s"
	provider := "k3s"
	active   := "active"

	clusterConfig := new(tests.TerratestConfig)
	config.LoadConfig("terratest", clusterConfig)

	// Set terraform.tfvars file
	functions.SetVarsTF(module)

	// Set initial infrastructure by building TFs declarative config file - [main.tf]
	successful, err := functions.SetConfigTF(module, clusterConfig.KubernetesVersion, clusterConfig.Nodepools)
	require.NoError(t, err)
	assert.Equal(t, true, successful)

	terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{

		TerraformDir: "../../modules/node_driver/" + module,
		NoColor:      true,
	})

	cleanup := func() {
		terraform.Destroy(t, terraformOptions)
		functions.CleanupConfigTF(module)
		functions.CleanupVarsTF(module)
	}

	// Deploys [main.tf] infrastructure and sets up resource cleanup
	defer cleanup()
	terraform.InitAndApply(t, terraformOptions)

	// Grab cluster name from TF outputs
	clusterName := terraform.Output(t, terraformOptions, "cluster_name")

	// Create session, client, and grab cluster specs
	testSession := session.NewSession(t)

	client, err := rancher.NewClient("", testSession)
	require.NoError(t, err)

	clusterID, err := clusters.GetClusterIDByName(client, clusterName)
	require.NoError(t, err)

	cluster, err := client.Management.Cluster.ByID(clusterID)
	require.NoError(t, err)

	// Test cluster
	assert.Equal(t, clusterName, cluster.Name)
	assert.Equal(t, provider, cluster.Provider)
	assert.Equal(t, active, cluster.State)
	assert.Equal(t, clusterConfig.KubernetesVersion, cluster.Version.GitVersion)

	// Upgrade kubernetes version
	successful, err = functions.SetConfigTF(module, clusterConfig.UpgradedKubernetesVersion, clusterConfig.Nodepools)
	require.NoError(t, err)
	assert.Equal(t, true, successful)

	terraform.Apply(t, terraformOptions)

	// Wait for cluster
	functions.WaitForActiveCluster(t, client, clusterID, module)

	// Update cluster object
	cluster, err = client.Management.Cluster.ByID(clusterID)
	require.NoError(t, err)

	// Test cluster
	assert.Equal(t, clusterName, cluster.Name)
	assert.Equal(t, provider, cluster.Provider)
	assert.Equal(t, active, cluster.State)
	assert.Equal(t, clusterConfig.UpgradedKubernetesVersion, cluster.Version.GitVersion)

}