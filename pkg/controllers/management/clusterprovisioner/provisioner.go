package clusterprovisioner

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/rancher/kontainer-engine/service"
	"github.com/rancher/norman/controller"
	"github.com/rancher/norman/event"
	"github.com/rancher/norman/types/convert"
	"github.com/rancher/rancher/pkg/configfield"
	"github.com/rancher/rancher/pkg/controllers/management/rke"
	"github.com/rancher/rancher/pkg/encryptedstore"
	"github.com/rancher/types/apis/management.cattle.io/v3"
	"github.com/rancher/types/config"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/util/flowcontrol"
)

const (
	RKEDriverKey = "rancherKubernetesEngineConfig"
)

type Provisioner struct {
	ClusterController v3.ClusterController
	Clusters          v3.ClusterInterface
	Driver            service.EngineService
	EventLogger       event.Logger
	backoff           *flowcontrol.Backoff
	rke               *rke.Provisioner
}

func Register(management *config.ManagementContext) {
	store, err := encryptedstore.NewGenericEncrypedStore("c-", "", management.Core.Namespaces(""),
		management.K8sClient.CoreV1())
	if err != nil {
		logrus.Fatal(err)
	}

	p := &Provisioner{
		Driver: service.NewEngineService(&engineStore{
			store: store,
		}),
		Clusters:          management.Management.Clusters(""),
		ClusterController: management.Management.Clusters("").Controller(),
		EventLogger:       management.EventLogger,
		backoff:           flowcontrol.NewBackOff(30*time.Second, 10*time.Minute),
	}
	p.rke = rke.New(management, p.Driver)

	// Add handlers
	p.Clusters.AddLifecycle("cluster-provisioner-controller", p)
	management.Management.Nodes("").AddHandler("cluster-provisioner-controller", p.machineChanged)
}

func (p *Provisioner) Remove(cluster *v3.Cluster) (*v3.Cluster, error) {
	logrus.Infof("Deleting cluster [%s]", cluster.Name)
	if skipProvisioning(cluster) ||
		cluster.Status.Driver == "" {
		return nil, nil
	}

	for i := 0; i < 4; i++ {
		err := p.driverRemove(cluster)
		if err == nil {
			break
		}
		if i == 3 {
			return cluster, fmt.Errorf("failed to remove the cluster [%s]: %v", cluster.Name, err)
		}
		time.Sleep(1 * time.Second)
	}
	logrus.Infof("Deleted cluster [%s]", cluster.Name)

	// cluster object will definitely have changed, reload
	return p.Clusters.Get(cluster.Name, metav1.GetOptions{})
}

func (p *Provisioner) Updated(cluster *v3.Cluster) (*v3.Cluster, error) {
	obj, err := v3.ClusterConditionUpdated.Do(cluster, func() (runtime.Object, error) {
		return p.update(cluster, false)
	})

	return obj.(*v3.Cluster), err
}

func (p *Provisioner) update(cluster *v3.Cluster, create bool) (*v3.Cluster, error) {
	cluster, err := p.reconcileCluster(cluster, create)
	if err != nil {
		return cluster, err
	}

	v3.ClusterConditionProvisioned.True(cluster)
	return cluster, nil
}

func (p *Provisioner) machineChanged(key string, machine *v3.Node) error {
	parts := strings.SplitN(key, "/", 2)

	p.ClusterController.Enqueue("", parts[0])

	return nil
}

func (p *Provisioner) Create(cluster *v3.Cluster) (*v3.Cluster, error) {
	var err error

	cluster.Status.ClusterName = cluster.Spec.DisplayName
	if cluster.Status.ClusterName == "" {
		cluster.Status.ClusterName = cluster.Name
	}

	// Initialize conditions, be careful to not continually update them
	v3.ClusterConditionPending.CreateUnknownIfNotExists(cluster)
	v3.ClusterConditionProvisioned.CreateUnknownIfNotExists(cluster)

	if v3.ClusterConditionWaiting.GetStatus(cluster) == "" {
		v3.ClusterConditionWaiting.Unknown(cluster)
	}
	if v3.ClusterConditionWaiting.GetMessage(cluster) == "" {
		v3.ClusterConditionWaiting.Message(cluster, "Waiting for API to be available")
	}

	cluster, err = p.pending(cluster)
	if err != nil {
		return cluster, err
	}

	obj, err := v3.ClusterConditionProvisioned.Do(cluster, func() (runtime.Object, error) {
		return p.update(cluster, true)
	})
	return obj.(*v3.Cluster), err
}

func (p *Provisioner) pending(cluster *v3.Cluster) (*v3.Cluster, error) {
	obj, err := v3.ClusterConditionPending.DoUntilTrue(cluster, func() (runtime.Object, error) {
		v3.ClusterConditionPending.Message(cluster, "")

		if skipProvisioning(cluster) {
			return cluster, nil
		}

		driver, err := p.validateDriver(cluster)
		if err != nil {
			return cluster, err
		}

		if driver == "" {
			return cluster, &controller.ForgetError{Err: fmt.Errorf("waiting for cluster to be imported")}
		}

		if driver == v3.ClusterDriverRKE {
			cluster, err := p.rke.Prepare(cluster)
			if err != nil {
				return cluster, err
			}
		}

		if driver != cluster.Status.Driver {
			cluster.Status.Driver = driver
			if driver == v3.ClusterDriverRKE && cluster.Spec.RancherKubernetesEngineConfig == nil {
				cluster.Spec.RancherKubernetesEngineConfig = &v3.RancherKubernetesEngineConfig{}
			}
			return p.Clusters.Update(cluster)
		}

		return cluster, nil
	})

	return obj.(*v3.Cluster), err
}

func (p *Provisioner) backoffFailure(cluster *v3.Cluster, spec *v3.ClusterSpec) (bool, time.Duration) {
	if cluster.Status.FailedSpec == nil {
		return false, 0
	}

	if !reflect.DeepEqual(cluster.Status.FailedSpec, spec) {
		return false, 0
	}

	if p.backoff.IsInBackOffSinceUpdate(cluster.Name, time.Now()) {
		go func() {
			time.Sleep(p.backoff.Get(cluster.Name))
			p.ClusterController.Enqueue("", cluster.Name)
		}()
		return true, p.backoff.Get(cluster.Name)
	}

	return false, 0
}

// reconcileCluster returns true if waiting or false if ready to provision
func (p *Provisioner) reconcileCluster(cluster *v3.Cluster, create bool) (*v3.Cluster, error) {
	if skipProvisioning(cluster) {
		return cluster, nil
	}

	var (
		apiEndpoint, serviceAccountToken, caCert string
		err                                      error
	)

	spec, err := p.getSpec(cluster)
	if err != nil || spec == nil {
		return cluster, err
	}

	if ok, delay := p.backoffFailure(cluster, spec); ok {
		return cluster, &controller.ForgetError{Err: fmt.Errorf("backing off failure, delay: %v", delay)}
	}

	logrus.Infof("Provisioning cluster [%s]", cluster.Name)

	if create {
		logrus.Infof("Creating cluster [%s]", cluster.Name)
		apiEndpoint, serviceAccountToken, caCert, err = p.driverCreate(cluster, *spec)
		if err != nil && err.Error() == "cluster already exists" {
			logrus.Infof("Create done, Updating cluster [%s]", cluster.Name)
			apiEndpoint, serviceAccountToken, caCert, err = p.driverUpdate(cluster, *spec)
		}
	} else {
		logrus.Infof("Updating cluster [%s]", cluster.Name)
		apiEndpoint, serviceAccountToken, caCert, err = p.driverUpdate(cluster, *spec)
	}

	// at this point we know the cluster has been modified in driverCreate/Update so reload
	if newCluster, reloadErr := p.Clusters.Get(cluster.Name, metav1.GetOptions{}); reloadErr == nil {
		cluster = newCluster
	}

	cluster, recordErr := p.recordFailure(cluster, *spec, err)
	if recordErr != nil {
		return cluster, recordErr
	}

	// for here out we want to always return the cluster, not just nil, so that the error can be properly
	// recorded if needs be
	if err != nil {
		return cluster, err
	}

	saved := false
	for i := 0; i < 20; i++ {
		cluster, err = p.Clusters.Get(cluster.Name, metav1.GetOptions{})
		if err != nil {
			return cluster, err
		}

		cluster.Status.AppliedSpec = spec
		cluster.Status.APIEndpoint = apiEndpoint
		cluster.Status.ServiceAccountToken = serviceAccountToken
		cluster.Status.CACert = caCert

		if cluster, err = p.Clusters.Update(cluster); err == nil {
			saved = true
			break
		} else {
			logrus.Errorf("failed to update cluster [%s]: %v", cluster.Name, err)
			time.Sleep(2)
		}
	}

	if !saved {
		return cluster, fmt.Errorf("failed to update cluster")
	}

	logrus.Infof("Provisioned cluster [%s]", cluster.Name)
	return cluster, nil
}

func skipProvisioning(cluster *v3.Cluster) bool {
	return cluster.Status.Driver == v3.ClusterDriverLocal || cluster.Status.Driver == v3.ClusterDriverImported
}

func (p *Provisioner) getConfig(reconcileRKE bool, spec v3.ClusterSpec, driverName string, cluster *v3.Cluster) (*v3.ClusterSpec, interface{}, error) {
	data, err := convert.EncodeToMap(spec)
	if err != nil {
		return nil, nil, err
	}

	v, ok := data[driverName+"Config"]
	if !ok || v == nil {
		v = map[string]interface{}{}
	}

	if driverName == v3.ClusterDriverRKE && reconcileRKE {
		newSpec, err := p.rke.GetSpec(cluster)
		if err != nil {
			return nil, nil, err
		}

		copy := *newSpec.RancherKubernetesEngineConfig
		spec.RancherKubernetesEngineConfig = &copy

		data, _ = convert.EncodeToMap(spec)
		v = data[RKEDriverKey]
	}

	return &spec, v, nil
}

func (p *Provisioner) getDriver(cluster *v3.Cluster) string {
	driver := configfield.GetDriver(&cluster.Spec)

	if driver == "" {
		spec, err := p.rke.GetSpec(cluster)
		if err == nil && len(spec.RancherKubernetesEngineConfig.Nodes) > 0 {
			return v3.ClusterDriverRKE
		}
	}

	return driver
}

func (p *Provisioner) validateDriver(cluster *v3.Cluster) (string, error) {
	oldDriver := cluster.Status.Driver

	if oldDriver == v3.ClusterDriverImported {
		return v3.ClusterDriverImported, nil
	}

	newDriver := p.getDriver(cluster)

	if oldDriver == "" && newDriver == "" {
		return newDriver, nil
	}

	if oldDriver == "" {
		return newDriver, nil
	}

	if newDriver == "" {
		return "", &controller.ForgetError{Err: fmt.Errorf("waiting for nodes")}
	}

	if oldDriver != newDriver {
		return newDriver, fmt.Errorf("driver change from %s to %s not allowed", oldDriver, newDriver)
	}

	return newDriver, nil
}

func (p *Provisioner) getSpec(cluster *v3.Cluster) (*v3.ClusterSpec, error) {
	driverName, err := p.validateDriver(cluster)
	if err != nil {
		return nil, err
	}

	var appliedSpec v3.ClusterSpec
	if cluster.Status.AppliedSpec != nil {
		appliedSpec = *cluster.Status.AppliedSpec
	}

	_, oldConfig, err := p.getConfig(false, appliedSpec, driverName, cluster)
	if err != nil {
		return nil, err
	}

	newSpec, newConfig, err := p.getConfig(true, cluster.Spec, driverName, cluster)
	if err != nil {
		return nil, err
	}

	if reflect.DeepEqual(oldConfig, newConfig) {
		newSpec = nil
	}

	return newSpec, nil
}

func (p *Provisioner) recordFailure(cluster *v3.Cluster, spec v3.ClusterSpec, err error) (*v3.Cluster, error) {
	if err == nil {
		p.backoff.DeleteEntry(cluster.Name)
		if cluster.Status.FailedSpec == nil {
			return cluster, nil
		}

		cluster.Status.FailedSpec = nil
		return p.Clusters.Update(cluster)
	}

	p.backoff.Next(cluster.Name, time.Now())
	cluster.Status.FailedSpec = &spec
	newCluster, _ := p.Clusters.Update(cluster)
	// mask the error
	return newCluster, nil
}
