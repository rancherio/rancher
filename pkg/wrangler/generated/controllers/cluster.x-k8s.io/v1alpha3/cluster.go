/*
Copyright 2020 Rancher Labs, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by main. DO NOT EDIT.

package v1alpha3

import (
	"context"
	"time"

	clientset "github.com/rancher/rancher/pkg/wrangler/generated/clientset/versioned/typed/cluster.x-k8s.io/v1alpha3"
	informers "github.com/rancher/rancher/pkg/wrangler/generated/informers/externalversions/cluster.x-k8s.io/v1alpha3"
	listers "github.com/rancher/rancher/pkg/wrangler/generated/listers/cluster.x-k8s.io/v1alpha3"
	"github.com/rancher/wrangler/pkg/apply"
	"github.com/rancher/wrangler/pkg/condition"
	"github.com/rancher/wrangler/pkg/generic"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
	v1alpha3 "sigs.k8s.io/cluster-api/api/v1alpha3"
)

type ClusterHandler func(string, *v1alpha3.Cluster) (*v1alpha3.Cluster, error)

type ClusterController interface {
	generic.ControllerMeta
	ClusterClient

	OnChange(ctx context.Context, name string, sync ClusterHandler)
	OnRemove(ctx context.Context, name string, sync ClusterHandler)
	Enqueue(namespace, name string)
	EnqueueAfter(namespace, name string, duration time.Duration)

	Cache() ClusterCache
}

type ClusterClient interface {
	Create(*v1alpha3.Cluster) (*v1alpha3.Cluster, error)
	Update(*v1alpha3.Cluster) (*v1alpha3.Cluster, error)
	UpdateStatus(*v1alpha3.Cluster) (*v1alpha3.Cluster, error)
	Delete(namespace, name string, options *metav1.DeleteOptions) error
	Get(namespace, name string, options metav1.GetOptions) (*v1alpha3.Cluster, error)
	List(namespace string, opts metav1.ListOptions) (*v1alpha3.ClusterList, error)
	Watch(namespace string, opts metav1.ListOptions) (watch.Interface, error)
	Patch(namespace, name string, pt types.PatchType, data []byte, subresources ...string) (result *v1alpha3.Cluster, err error)
}

type ClusterCache interface {
	Get(namespace, name string) (*v1alpha3.Cluster, error)
	List(namespace string, selector labels.Selector) ([]*v1alpha3.Cluster, error)

	AddIndexer(indexName string, indexer ClusterIndexer)
	GetByIndex(indexName, key string) ([]*v1alpha3.Cluster, error)
}

type ClusterIndexer func(obj *v1alpha3.Cluster) ([]string, error)

type clusterController struct {
	controllerManager *generic.ControllerManager
	clientGetter      clientset.ClustersGetter
	informer          informers.ClusterInformer
	gvk               schema.GroupVersionKind
}

func NewClusterController(gvk schema.GroupVersionKind, controllerManager *generic.ControllerManager, clientGetter clientset.ClustersGetter, informer informers.ClusterInformer) ClusterController {
	return &clusterController{
		controllerManager: controllerManager,
		clientGetter:      clientGetter,
		informer:          informer,
		gvk:               gvk,
	}
}

func FromClusterHandlerToHandler(sync ClusterHandler) generic.Handler {
	return func(key string, obj runtime.Object) (ret runtime.Object, err error) {
		var v *v1alpha3.Cluster
		if obj == nil {
			v, err = sync(key, nil)
		} else {
			v, err = sync(key, obj.(*v1alpha3.Cluster))
		}
		if v == nil {
			return nil, err
		}
		return v, err
	}
}

func (c *clusterController) Updater() generic.Updater {
	return func(obj runtime.Object) (runtime.Object, error) {
		newObj, err := c.Update(obj.(*v1alpha3.Cluster))
		if newObj == nil {
			return nil, err
		}
		return newObj, err
	}
}

func UpdateClusterDeepCopyOnChange(client ClusterClient, obj *v1alpha3.Cluster, handler func(obj *v1alpha3.Cluster) (*v1alpha3.Cluster, error)) (*v1alpha3.Cluster, error) {
	if obj == nil {
		return obj, nil
	}

	copyObj := obj.DeepCopy()
	newObj, err := handler(copyObj)
	if newObj != nil {
		copyObj = newObj
	}
	if obj.ResourceVersion == copyObj.ResourceVersion && !equality.Semantic.DeepEqual(obj, copyObj) {
		return client.Update(copyObj)
	}

	return copyObj, err
}

func (c *clusterController) AddGenericHandler(ctx context.Context, name string, handler generic.Handler) {
	c.controllerManager.AddHandler(ctx, c.gvk, c.informer.Informer(), name, handler)
}

func (c *clusterController) AddGenericRemoveHandler(ctx context.Context, name string, handler generic.Handler) {
	removeHandler := generic.NewRemoveHandler(name, c.Updater(), handler)
	c.controllerManager.AddHandler(ctx, c.gvk, c.informer.Informer(), name, removeHandler)
}

func (c *clusterController) OnChange(ctx context.Context, name string, sync ClusterHandler) {
	c.AddGenericHandler(ctx, name, FromClusterHandlerToHandler(sync))
}

func (c *clusterController) OnRemove(ctx context.Context, name string, sync ClusterHandler) {
	removeHandler := generic.NewRemoveHandler(name, c.Updater(), FromClusterHandlerToHandler(sync))
	c.AddGenericHandler(ctx, name, removeHandler)
}

func (c *clusterController) Enqueue(namespace, name string) {
	c.controllerManager.Enqueue(c.gvk, c.informer.Informer(), namespace, name)
}

func (c *clusterController) EnqueueAfter(namespace, name string, duration time.Duration) {
	c.controllerManager.EnqueueAfter(c.gvk, c.informer.Informer(), namespace, name, duration)
}

func (c *clusterController) Informer() cache.SharedIndexInformer {
	return c.informer.Informer()
}

func (c *clusterController) GroupVersionKind() schema.GroupVersionKind {
	return c.gvk
}

func (c *clusterController) Cache() ClusterCache {
	return &clusterCache{
		lister:  c.informer.Lister(),
		indexer: c.informer.Informer().GetIndexer(),
	}
}

func (c *clusterController) Create(obj *v1alpha3.Cluster) (*v1alpha3.Cluster, error) {
	return c.clientGetter.Clusters(obj.Namespace).Create(context.TODO(), obj, metav1.CreateOptions{})
}

func (c *clusterController) Update(obj *v1alpha3.Cluster) (*v1alpha3.Cluster, error) {
	return c.clientGetter.Clusters(obj.Namespace).Update(context.TODO(), obj, metav1.UpdateOptions{})
}

func (c *clusterController) UpdateStatus(obj *v1alpha3.Cluster) (*v1alpha3.Cluster, error) {
	return c.clientGetter.Clusters(obj.Namespace).UpdateStatus(context.TODO(), obj, metav1.UpdateOptions{})
}

func (c *clusterController) Delete(namespace, name string, options *metav1.DeleteOptions) error {
	if options == nil {
		options = &metav1.DeleteOptions{}
	}
	return c.clientGetter.Clusters(namespace).Delete(context.TODO(), name, *options)
}

func (c *clusterController) Get(namespace, name string, options metav1.GetOptions) (*v1alpha3.Cluster, error) {
	return c.clientGetter.Clusters(namespace).Get(context.TODO(), name, options)
}

func (c *clusterController) List(namespace string, opts metav1.ListOptions) (*v1alpha3.ClusterList, error) {
	return c.clientGetter.Clusters(namespace).List(context.TODO(), opts)
}

func (c *clusterController) Watch(namespace string, opts metav1.ListOptions) (watch.Interface, error) {
	return c.clientGetter.Clusters(namespace).Watch(context.TODO(), opts)
}

func (c *clusterController) Patch(namespace, name string, pt types.PatchType, data []byte, subresources ...string) (result *v1alpha3.Cluster, err error) {
	return c.clientGetter.Clusters(namespace).Patch(context.TODO(), name, pt, data, metav1.PatchOptions{}, subresources...)
}

type clusterCache struct {
	lister  listers.ClusterLister
	indexer cache.Indexer
}

func (c *clusterCache) Get(namespace, name string) (*v1alpha3.Cluster, error) {
	return c.lister.Clusters(namespace).Get(name)
}

func (c *clusterCache) List(namespace string, selector labels.Selector) ([]*v1alpha3.Cluster, error) {
	return c.lister.Clusters(namespace).List(selector)
}

func (c *clusterCache) AddIndexer(indexName string, indexer ClusterIndexer) {
	utilruntime.Must(c.indexer.AddIndexers(map[string]cache.IndexFunc{
		indexName: func(obj interface{}) (strings []string, e error) {
			return indexer(obj.(*v1alpha3.Cluster))
		},
	}))
}

func (c *clusterCache) GetByIndex(indexName, key string) (result []*v1alpha3.Cluster, err error) {
	objs, err := c.indexer.ByIndex(indexName, key)
	if err != nil {
		return nil, err
	}
	result = make([]*v1alpha3.Cluster, 0, len(objs))
	for _, obj := range objs {
		result = append(result, obj.(*v1alpha3.Cluster))
	}
	return result, nil
}

type ClusterStatusHandler func(obj *v1alpha3.Cluster, status v1alpha3.ClusterStatus) (v1alpha3.ClusterStatus, error)

type ClusterGeneratingHandler func(obj *v1alpha3.Cluster, status v1alpha3.ClusterStatus) ([]runtime.Object, v1alpha3.ClusterStatus, error)

func RegisterClusterStatusHandler(ctx context.Context, controller ClusterController, condition condition.Cond, name string, handler ClusterStatusHandler) {
	statusHandler := &clusterStatusHandler{
		client:    controller,
		condition: condition,
		handler:   handler,
	}
	controller.AddGenericHandler(ctx, name, FromClusterHandlerToHandler(statusHandler.sync))
}

func RegisterClusterGeneratingHandler(ctx context.Context, controller ClusterController, apply apply.Apply,
	condition condition.Cond, name string, handler ClusterGeneratingHandler, opts *generic.GeneratingHandlerOptions) {
	statusHandler := &clusterGeneratingHandler{
		ClusterGeneratingHandler: handler,
		apply:                    apply,
		name:                     name,
		gvk:                      controller.GroupVersionKind(),
	}
	if opts != nil {
		statusHandler.opts = *opts
	}
	RegisterClusterStatusHandler(ctx, controller, condition, name, statusHandler.Handle)
}

type clusterStatusHandler struct {
	client    ClusterClient
	condition condition.Cond
	handler   ClusterStatusHandler
}

func (a *clusterStatusHandler) sync(key string, obj *v1alpha3.Cluster) (*v1alpha3.Cluster, error) {
	if obj == nil {
		return obj, nil
	}

	origStatus := obj.Status
	obj = obj.DeepCopy()
	newStatus, err := a.handler(obj, obj.Status)
	if err != nil {
		// Revert to old status on error
		newStatus = *origStatus.DeepCopy()
	}

	obj.Status = newStatus
	if a.condition != "" {
		if errors.IsConflict(err) {
			a.condition.SetError(obj, "", nil)
		} else {
			a.condition.SetError(obj, "", err)
		}
	}
	if !equality.Semantic.DeepEqual(origStatus, obj.Status) {
		var newErr error
		obj, newErr = a.client.UpdateStatus(obj)
		if err == nil {
			err = newErr
		}
	}
	return obj, err
}

type clusterGeneratingHandler struct {
	ClusterGeneratingHandler
	apply apply.Apply
	opts  generic.GeneratingHandlerOptions
	gvk   schema.GroupVersionKind
	name  string
}

func (a *clusterGeneratingHandler) Handle(obj *v1alpha3.Cluster, status v1alpha3.ClusterStatus) (v1alpha3.ClusterStatus, error) {
	objs, newStatus, err := a.ClusterGeneratingHandler(obj, status)
	if err != nil {
		return newStatus, err
	}

	apply := a.apply

	if !a.opts.DynamicLookup {
		apply = apply.WithStrictCaching()
	}

	if !a.opts.AllowCrossNamespace && !a.opts.AllowClusterScoped {
		apply = apply.WithSetOwnerReference(true, false).
			WithDefaultNamespace(obj.GetNamespace()).
			WithListerNamespace(obj.GetNamespace())
	}

	if !a.opts.AllowClusterScoped {
		apply = apply.WithRestrictClusterScoped()
	}

	return newStatus, apply.
		WithOwner(obj).
		WithSetID(a.name).
		ApplyObjects(objs...)
}
