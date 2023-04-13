/*
Copyright 2023 Rancher Labs, Inc.

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

package v3

import (
	"context"
	"time"

	"github.com/rancher/lasso/pkg/client"
	"github.com/rancher/lasso/pkg/controller"
	v3 "github.com/rancher/rancher/pkg/apis/project.cattle.io/v3"
	"github.com/rancher/wrangler/pkg/apply"
	"github.com/rancher/wrangler/pkg/condition"
	"github.com/rancher/wrangler/pkg/generic"
	"github.com/rancher/wrangler/pkg/kv"
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
)

type SourceCodeRepositoryHandler func(string, *v3.SourceCodeRepository) (*v3.SourceCodeRepository, error)

type SourceCodeRepositoryController interface {
	generic.ControllerMeta
	SourceCodeRepositoryClient

	OnChange(ctx context.Context, name string, sync SourceCodeRepositoryHandler)
	OnRemove(ctx context.Context, name string, sync SourceCodeRepositoryHandler)
	Enqueue(namespace, name string)
	EnqueueAfter(namespace, name string, duration time.Duration)

	Cache() SourceCodeRepositoryCache
}

type SourceCodeRepositoryClient interface {
	Create(*v3.SourceCodeRepository) (*v3.SourceCodeRepository, error)
	Update(*v3.SourceCodeRepository) (*v3.SourceCodeRepository, error)
	UpdateStatus(*v3.SourceCodeRepository) (*v3.SourceCodeRepository, error)
	Delete(namespace, name string, options *metav1.DeleteOptions) error
	Get(namespace, name string, options metav1.GetOptions) (*v3.SourceCodeRepository, error)
	List(namespace string, opts metav1.ListOptions) (*v3.SourceCodeRepositoryList, error)
	Watch(namespace string, opts metav1.ListOptions) (watch.Interface, error)
	Patch(namespace, name string, pt types.PatchType, data []byte, subresources ...string) (result *v3.SourceCodeRepository, err error)
}

type SourceCodeRepositoryCache interface {
	Get(namespace, name string) (*v3.SourceCodeRepository, error)
	List(namespace string, selector labels.Selector) ([]*v3.SourceCodeRepository, error)

	AddIndexer(indexName string, indexer SourceCodeRepositoryIndexer)
	GetByIndex(indexName, key string) ([]*v3.SourceCodeRepository, error)
}

type SourceCodeRepositoryIndexer func(obj *v3.SourceCodeRepository) ([]string, error)

type sourceCodeRepositoryController struct {
	controller    controller.SharedController
	client        *client.Client
	gvk           schema.GroupVersionKind
	groupResource schema.GroupResource
}

func NewSourceCodeRepositoryController(gvk schema.GroupVersionKind, resource string, namespaced bool, controller controller.SharedControllerFactory) SourceCodeRepositoryController {
	c := controller.ForResourceKind(gvk.GroupVersion().WithResource(resource), gvk.Kind, namespaced)
	return &sourceCodeRepositoryController{
		controller: c,
		client:     c.Client(),
		gvk:        gvk,
		groupResource: schema.GroupResource{
			Group:    gvk.Group,
			Resource: resource,
		},
	}
}

func FromSourceCodeRepositoryHandlerToHandler(sync SourceCodeRepositoryHandler) generic.Handler {
	return func(key string, obj runtime.Object) (ret runtime.Object, err error) {
		var v *v3.SourceCodeRepository
		if obj == nil {
			v, err = sync(key, nil)
		} else {
			v, err = sync(key, obj.(*v3.SourceCodeRepository))
		}
		if v == nil {
			return nil, err
		}
		return v, err
	}
}

func (c *sourceCodeRepositoryController) Updater() generic.Updater {
	return func(obj runtime.Object) (runtime.Object, error) {
		newObj, err := c.Update(obj.(*v3.SourceCodeRepository))
		if newObj == nil {
			return nil, err
		}
		return newObj, err
	}
}

func UpdateSourceCodeRepositoryDeepCopyOnChange(client SourceCodeRepositoryClient, obj *v3.SourceCodeRepository, handler func(obj *v3.SourceCodeRepository) (*v3.SourceCodeRepository, error)) (*v3.SourceCodeRepository, error) {
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

func (c *sourceCodeRepositoryController) AddGenericHandler(ctx context.Context, name string, handler generic.Handler) {
	c.controller.RegisterHandler(ctx, name, controller.SharedControllerHandlerFunc(handler))
}

func (c *sourceCodeRepositoryController) AddGenericRemoveHandler(ctx context.Context, name string, handler generic.Handler) {
	c.AddGenericHandler(ctx, name, generic.NewRemoveHandler(name, c.Updater(), handler))
}

func (c *sourceCodeRepositoryController) OnChange(ctx context.Context, name string, sync SourceCodeRepositoryHandler) {
	c.AddGenericHandler(ctx, name, FromSourceCodeRepositoryHandlerToHandler(sync))
}

func (c *sourceCodeRepositoryController) OnRemove(ctx context.Context, name string, sync SourceCodeRepositoryHandler) {
	c.AddGenericHandler(ctx, name, generic.NewRemoveHandler(name, c.Updater(), FromSourceCodeRepositoryHandlerToHandler(sync)))
}

func (c *sourceCodeRepositoryController) Enqueue(namespace, name string) {
	c.controller.Enqueue(namespace, name)
}

func (c *sourceCodeRepositoryController) EnqueueAfter(namespace, name string, duration time.Duration) {
	c.controller.EnqueueAfter(namespace, name, duration)
}

func (c *sourceCodeRepositoryController) Informer() cache.SharedIndexInformer {
	return c.controller.Informer()
}

func (c *sourceCodeRepositoryController) GroupVersionKind() schema.GroupVersionKind {
	return c.gvk
}

func (c *sourceCodeRepositoryController) Cache() SourceCodeRepositoryCache {
	return &sourceCodeRepositoryCache{
		indexer:  c.Informer().GetIndexer(),
		resource: c.groupResource,
	}
}

func (c *sourceCodeRepositoryController) Create(obj *v3.SourceCodeRepository) (*v3.SourceCodeRepository, error) {
	result := &v3.SourceCodeRepository{}
	return result, c.client.Create(context.TODO(), obj.Namespace, obj, result, metav1.CreateOptions{})
}

func (c *sourceCodeRepositoryController) Update(obj *v3.SourceCodeRepository) (*v3.SourceCodeRepository, error) {
	result := &v3.SourceCodeRepository{}
	return result, c.client.Update(context.TODO(), obj.Namespace, obj, result, metav1.UpdateOptions{})
}

func (c *sourceCodeRepositoryController) UpdateStatus(obj *v3.SourceCodeRepository) (*v3.SourceCodeRepository, error) {
	result := &v3.SourceCodeRepository{}
	return result, c.client.UpdateStatus(context.TODO(), obj.Namespace, obj, result, metav1.UpdateOptions{})
}

func (c *sourceCodeRepositoryController) Delete(namespace, name string, options *metav1.DeleteOptions) error {
	if options == nil {
		options = &metav1.DeleteOptions{}
	}
	return c.client.Delete(context.TODO(), namespace, name, *options)
}

func (c *sourceCodeRepositoryController) Get(namespace, name string, options metav1.GetOptions) (*v3.SourceCodeRepository, error) {
	result := &v3.SourceCodeRepository{}
	return result, c.client.Get(context.TODO(), namespace, name, result, options)
}

func (c *sourceCodeRepositoryController) List(namespace string, opts metav1.ListOptions) (*v3.SourceCodeRepositoryList, error) {
	result := &v3.SourceCodeRepositoryList{}
	return result, c.client.List(context.TODO(), namespace, result, opts)
}

func (c *sourceCodeRepositoryController) Watch(namespace string, opts metav1.ListOptions) (watch.Interface, error) {
	return c.client.Watch(context.TODO(), namespace, opts)
}

func (c *sourceCodeRepositoryController) Patch(namespace, name string, pt types.PatchType, data []byte, subresources ...string) (*v3.SourceCodeRepository, error) {
	result := &v3.SourceCodeRepository{}
	return result, c.client.Patch(context.TODO(), namespace, name, pt, data, result, metav1.PatchOptions{}, subresources...)
}

type sourceCodeRepositoryCache struct {
	indexer  cache.Indexer
	resource schema.GroupResource
}

func (c *sourceCodeRepositoryCache) Get(namespace, name string) (*v3.SourceCodeRepository, error) {
	obj, exists, err := c.indexer.GetByKey(namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(c.resource, name)
	}
	return obj.(*v3.SourceCodeRepository), nil
}

func (c *sourceCodeRepositoryCache) List(namespace string, selector labels.Selector) (ret []*v3.SourceCodeRepository, err error) {

	err = cache.ListAllByNamespace(c.indexer, namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*v3.SourceCodeRepository))
	})

	return ret, err
}

func (c *sourceCodeRepositoryCache) AddIndexer(indexName string, indexer SourceCodeRepositoryIndexer) {
	utilruntime.Must(c.indexer.AddIndexers(map[string]cache.IndexFunc{
		indexName: func(obj interface{}) (strings []string, e error) {
			return indexer(obj.(*v3.SourceCodeRepository))
		},
	}))
}

func (c *sourceCodeRepositoryCache) GetByIndex(indexName, key string) (result []*v3.SourceCodeRepository, err error) {
	objs, err := c.indexer.ByIndex(indexName, key)
	if err != nil {
		return nil, err
	}
	result = make([]*v3.SourceCodeRepository, 0, len(objs))
	for _, obj := range objs {
		result = append(result, obj.(*v3.SourceCodeRepository))
	}
	return result, nil
}

type SourceCodeRepositoryStatusHandler func(obj *v3.SourceCodeRepository, status v3.SourceCodeRepositoryStatus) (v3.SourceCodeRepositoryStatus, error)

type SourceCodeRepositoryGeneratingHandler func(obj *v3.SourceCodeRepository, status v3.SourceCodeRepositoryStatus) ([]runtime.Object, v3.SourceCodeRepositoryStatus, error)

func RegisterSourceCodeRepositoryStatusHandler(ctx context.Context, controller SourceCodeRepositoryController, condition condition.Cond, name string, handler SourceCodeRepositoryStatusHandler) {
	statusHandler := &sourceCodeRepositoryStatusHandler{
		client:    controller,
		condition: condition,
		handler:   handler,
	}
	controller.AddGenericHandler(ctx, name, FromSourceCodeRepositoryHandlerToHandler(statusHandler.sync))
}

func RegisterSourceCodeRepositoryGeneratingHandler(ctx context.Context, controller SourceCodeRepositoryController, apply apply.Apply,
	condition condition.Cond, name string, handler SourceCodeRepositoryGeneratingHandler, opts *generic.GeneratingHandlerOptions) {
	statusHandler := &sourceCodeRepositoryGeneratingHandler{
		SourceCodeRepositoryGeneratingHandler: handler,
		apply:                                 apply,
		name:                                  name,
		gvk:                                   controller.GroupVersionKind(),
	}
	if opts != nil {
		statusHandler.opts = *opts
	}
	controller.OnChange(ctx, name, statusHandler.Remove)
	RegisterSourceCodeRepositoryStatusHandler(ctx, controller, condition, name, statusHandler.Handle)
}

type sourceCodeRepositoryStatusHandler struct {
	client    SourceCodeRepositoryClient
	condition condition.Cond
	handler   SourceCodeRepositoryStatusHandler
}

func (a *sourceCodeRepositoryStatusHandler) sync(key string, obj *v3.SourceCodeRepository) (*v3.SourceCodeRepository, error) {
	if obj == nil {
		return obj, nil
	}

	origStatus := obj.Status.DeepCopy()
	obj = obj.DeepCopy()
	newStatus, err := a.handler(obj, obj.Status)
	if err != nil {
		// Revert to old status on error
		newStatus = *origStatus.DeepCopy()
	}

	if a.condition != "" {
		if errors.IsConflict(err) {
			a.condition.SetError(&newStatus, "", nil)
		} else {
			a.condition.SetError(&newStatus, "", err)
		}
	}
	if !equality.Semantic.DeepEqual(origStatus, &newStatus) {
		if a.condition != "" {
			// Since status has changed, update the lastUpdatedTime
			a.condition.LastUpdated(&newStatus, time.Now().UTC().Format(time.RFC3339))
		}

		var newErr error
		obj.Status = newStatus
		newObj, newErr := a.client.UpdateStatus(obj)
		if err == nil {
			err = newErr
		}
		if newErr == nil {
			obj = newObj
		}
	}
	return obj, err
}

type sourceCodeRepositoryGeneratingHandler struct {
	SourceCodeRepositoryGeneratingHandler
	apply apply.Apply
	opts  generic.GeneratingHandlerOptions
	gvk   schema.GroupVersionKind
	name  string
}

func (a *sourceCodeRepositoryGeneratingHandler) Remove(key string, obj *v3.SourceCodeRepository) (*v3.SourceCodeRepository, error) {
	if obj != nil {
		return obj, nil
	}

	obj = &v3.SourceCodeRepository{}
	obj.Namespace, obj.Name = kv.RSplit(key, "/")
	obj.SetGroupVersionKind(a.gvk)

	return nil, generic.ConfigureApplyForObject(a.apply, obj, &a.opts).
		WithOwner(obj).
		WithSetID(a.name).
		ApplyObjects()
}

func (a *sourceCodeRepositoryGeneratingHandler) Handle(obj *v3.SourceCodeRepository, status v3.SourceCodeRepositoryStatus) (v3.SourceCodeRepositoryStatus, error) {
	if !obj.DeletionTimestamp.IsZero() {
		return status, nil
	}

	objs, newStatus, err := a.SourceCodeRepositoryGeneratingHandler(obj, status)
	if err != nil {
		return newStatus, err
	}

	return newStatus, generic.ConfigureApplyForObject(a.apply, obj, &a.opts).
		WithOwner(obj).
		WithSetID(a.name).
		ApplyObjects(objs...)
}
