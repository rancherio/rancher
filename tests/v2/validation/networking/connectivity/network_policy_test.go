//go:build validation

package connectivity

import (
	"errors"
	management "github.com/rancher/shepherd/clients/rancher/generated/management/v3"
	"github.com/rancher/shepherd/extensions/charts"
	"github.com/rancher/shepherd/extensions/clusters"
	"github.com/rancher/shepherd/extensions/namespaces"
	"github.com/rancher/shepherd/extensions/provisioninginput"
	"github.com/rancher/shepherd/extensions/sshkeys"
	"github.com/rancher/shepherd/extensions/workloads"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ssh"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"net/url"
	"testing"

	"github.com/rancher/shepherd/clients/rancher"
	"github.com/rancher/shepherd/pkg/session"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type NetworkPolicyTestSuite struct {
	suite.Suite
	session     *session.Session
	client      *rancher.Client
	project     *management.Project
	clusterName string
}

func (n *NetworkPolicyTestSuite) TearDownSuite() {
	n.session.Cleanup()
}

func (n *NetworkPolicyTestSuite) SetupSuite() {
	testSession := session.NewSession()
	n.session = testSession

	client, err := rancher.NewClient("", testSession)
	require.NoError(n.T(), err)

	n.client = client

	clusterName := client.RancherConfig.ClusterName
	require.NotEmpty(n.T(), clusterName, "Cluster name to install is not set")
	n.clusterName = clusterName

	cluster, err := clusters.NewClusterMeta(client, clusterName)
	require.NoError(n.T(), err)

	projectConfig := &management.Project{
		ClusterID: cluster.ID,
		Name:      pingPodProjectName,
	}

	createdProject, err := client.Management.Project.Create(projectConfig)
	require.NoError(n.T(), err)
	require.Equal(n.T(), createdProject.Name, pingPodProjectName)
	n.project = createdProject
}

func (n *NetworkPolicyTestSuite) TestPingPods() {
	names := newNames()
	n.T().Logf("Creating namespace with name [%v]", names.random["namespaceName"])
	namespace, err := namespaces.CreateNamespace(n.client, names.random["namespaceName"], "{}", map[string]string{}, map[string]string{}, n.project)
	require.NoError(n.T(), err)
	assert.Equal(n.T(), namespace.Name, names.random["namespaceName"])

	steveClient, err := n.client.Steve.ProxyDownstream(n.project.ClusterID)
	require.NoError(n.T(), err)

	testContainerPodTemplate := newPodTemplateWithTestContainer()

	n.T().Logf("Creating a daemonset with the test container with name [%v]", names.random["daemonsetName"])
	daemonsetTemplate := workloads.NewDaemonSetTemplate(names.random["daemonsetName"], namespace.Name, testContainerPodTemplate, true, nil)
	createdDaemonSet, err := steveClient.SteveType(workloads.DaemonsetSteveType).Create(daemonsetTemplate)
	require.NoError(n.T(), err)
	assert.Equal(n.T(), createdDaemonSet.Name, names.random["daemonsetName"])

	n.T().Logf("Waiting daemonset [%v] to have expected number of available replicas", names.random["daemonsetName"])
	err = charts.WatchAndWaitDaemonSets(n.client, n.project.ClusterID, namespace.Name, metav1.ListOptions{})
	require.NoError(n.T(), err)

	wc, err := n.client.WranglerContext.DownStreamClusterWranglerContext(n.project.ClusterID)
	require.NoError(n.T(), err)

	pods, err := wc.Core.Pod().List(namespace.Name, metav1.ListOptions{})
	assert.NoError(n.T(), err)
	assert.NotEmpty(n.T(), pods)

	//pod1Name := pods.Items[0].ObjectMeta.Name
	pod2Ip := pods.Items[1].Status.PodIP
	pingExecCmd := pingCmd + " " + pod2Ip
	nodeRole := "control-plane"
	_, stevecluster, err := clusters.GetProvisioningClusterByName(n.client, n.clusterName, provisioninginput.Namespace)

	query, err := url.ParseQuery("labelSelector=node-role.kubernetes.io/" + nodeRole + "=true")
	assert.NoError(n.T(), err)

	nodeList, err := steveClient.SteveType("node").List(query)
	assert.NoError(n.T(), err)

	firstMachine := nodeList.Data[0]

	sshUser, err := sshkeys.GetSSHUser(n.client, stevecluster)
	assert.NoError(n.T(), err)

	if sshUser == "" {
		assert.NoError(n.T(), errors.New("sshUser does not exist"))
	}

	sshNode, err := sshkeys.GetSSHNodeFromMachine(n.client, sshUser, &firstMachine)
	assert.NoError(n.T(), err)

	n.T().Logf("Running ping on [%v]", firstMachine.Name)

	_, err = sshNode.ExecuteCommand(pingExecCmd)
	if err != nil && !errors.Is(err, &ssh.ExitMissingError{}) {
		assert.NoError(n.T(), err)
	}

	//execCmd := []string{"kubectl", "exec", pod1Name, "-n", namespace.Name, " -- ", pingCmd, pod2Ip}
	//execCmd := []string{namespace.Name, pod1Name, pingCmd, pod2Ip}

	//cmdLog, err := kubectl.Command(n.client, nil, n.project.ClusterID, execCmd, "")
	//require.NoError(n.T(), err)
	//n.T().Logf("Log of the kubectl command {%v]", cmdLog)

}

func TestNetworkPolicyTestSuite(t *testing.T) {
	suite.Run(t, new(NetworkPolicyTestSuite))
}
