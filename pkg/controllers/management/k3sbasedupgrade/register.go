package k3sbasedupgrade

import (
	"context"
	"time"

	manager2 "github.com/rancher/rancher/pkg/catalog/manager"
	"github.com/rancher/rancher/pkg/clustermanager"
	wranglerv3 "github.com/rancher/rancher/pkg/generated/controllers/management.cattle.io/v3"
	v3 "github.com/rancher/rancher/pkg/generated/norman/management.cattle.io/v3"
	projectv3 "github.com/rancher/rancher/pkg/generated/norman/project.cattle.io/v3"
	"github.com/rancher/rancher/pkg/systemaccount"
	"github.com/rancher/rancher/pkg/types/config"
	"github.com/rancher/rancher/pkg/wrangler"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type handler struct {
	ctx                    context.Context
	systemUpgradeNamespace string
	clusterCache           wranglerv3.ClusterCache
	clusterClient          wranglerv3.ClusterClient
	catalogManager         manager2.CatalogManager
	apps                   projectv3.AppInterface
	appLister              projectv3.AppLister
	nodeLister             v3.NodeLister
	systemAccountManager   *systemaccount.Manager
	manager                *clustermanager.Manager
	clusterEnqueueAfter    func(name string, duration time.Duration)
}

const (
	systemUpgradeNS        = "cattle-system"
	rancherManagedPlan     = "rancher-managed"
	upgradeDisableLabelKey = "upgrade.cattle.io/disable"
	k3sUpgraderCatalogName = "system-library-rancher-k3s-upgrader"
)

func Register(ctx context.Context, wContext *wrangler.Context, mgmtCtx *config.ManagementContext, manager *clustermanager.Manager) {
	h := &handler{
		ctx:                    ctx,
		systemUpgradeNamespace: systemUpgradeNS,
		clusterCache:           wContext.Mgmt.Cluster().Cache(),
		clusterClient:          wContext.Mgmt.Cluster(),
		catalogManager:         mgmtCtx.CatalogManager,
		clusterEnqueueAfter:    wContext.Mgmt.Cluster().EnqueueAfter,
		apps:                   mgmtCtx.Project.Apps(metav1.NamespaceAll),
		appLister:              mgmtCtx.Project.Apps("").Controller().Lister(),
		nodeLister:             mgmtCtx.Management.Nodes("").Controller().Lister(),
		systemAccountManager:   systemaccount.NewManager(mgmtCtx),
		manager:                manager,
	}
	wContext.Mgmt.Cluster().OnChange(ctx, "k3s-upgrade-controller", h.onClusterChange)
}
