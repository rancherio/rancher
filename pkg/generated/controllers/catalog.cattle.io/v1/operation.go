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

package v1

import (
	"context"
	"time"

	"github.com/rancher/lasso/pkg/client"
	"github.com/rancher/lasso/pkg/controller"
	v1 "github.com/rancher/rancher/pkg/apis/catalog.cattle.io/v1"
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

type OperationHandler func(string, *v1.Operation) (*v1.Operation, error)

type OperationController interface {
	generic.ControllerMeta
	OperationClient

	OnChange(ctx context.Context, name string, sync OperationHandler)
	OnRemove(ctx context.Context, name string, sync OperationHandler)
	Enqueue(namespace, name string)
	EnqueueAfter(namespace, name string, duration time.Duration)

	Cache() OperationCache
}

type OperationClient interface {
	Create(*v1.Operation) (*v1.Operation, error)
	Update(*v1.Operation) (*v1.Operation, error)
	UpdateStatus(*v1.Operation) (*v1.Operation, error)
	Delete(namespace, name string, options *metav1.DeleteOptions) error
	Get(namespace, name string, options metav1.GetOptions) (*v1.Operation, error)
	List(namespace string, opts metav1.ListOptions) (*v1.OperationList, error)
	Watch(namespace string, opts metav1.ListOptions) (watch.Interface, error)
	Patch(namespace, name string, pt types.PatchType, data []byte, subresources ...string) (result *v1.Operation, err error)
}

type OperationCache interface {
	Get(namespace, name string) (*v1.Operation, error)
	List(namespace string, selector labels.Selector) ([]*v1.Operation, error)

	AddIndexer(indexName string, indexer OperationIndexer)
	GetByIndex(indexName, key string) ([]*v1.Operation, error)
}

type OperationIndexer func(obj *v1.Operation) ([]string, error)

type operationController struct {
	controller    controller.SharedController
	client        *client.Client
	gvk           schema.GroupVersionKind
	groupResource schema.GroupResource
}

func NewOperationController(gvk schema.GroupVersionKind, resource string, namespaced bool, controller controller.SharedControllerFactory) OperationController {
	c := controller.ForResourceKind(gvk.GroupVersion().WithResource(resource), gvk.Kind, namespaced)
	return &operationController{
		controller: c,
		client:     c.Client(),
		gvk:        gvk,
		groupResource: schema.GroupResource{
			Group:    gvk.Group,
			Resource: resource,
		},
	}
}

func FromOperationHandlerToHandler(sync OperationHandler) generic.Handler {
	return func(key string, obj runtime.Object) (ret runtime.Object, err error) {
		var v *v1.Operation
		if obj == nil {
			v, err = sync(key, nil)
		} else {
			v, err = sync(key, obj.(*v1.Operation))
		}
		if v == nil {
			return nil, err
		}
		return v, err
	}
}

func (c *operationController) Updater() generic.Updater {
	return func(obj runtime.Object) (runtime.Object, error) {
		newObj, err := c.Update(obj.(*v1.Operation))
		if newObj == nil {
			return nil, err
		}
		return newObj, err
	}
}

func UpdateOperationDeepCopyOnChange(client OperationClient, obj *v1.Operation, handler func(obj *v1.Operation) (*v1.Operation, error)) (*v1.Operation, error) {
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

func (c *operationController) AddGenericHandler(ctx context.Context, name string, handler generic.Handler) {
	c.controller.RegisterHandler(ctx, name, controller.SharedControllerHandlerFunc(handler))
}

func (c *operationController) AddGenericRemoveHandler(ctx context.Context, name string, handler generic.Handler) {
	c.AddGenericHandler(ctx, name, generic.NewRemoveHandler(name, c.Updater(), handler))
}

func (c *operationController) OnChange(ctx context.Context, name string, sync OperationHandler) {
	c.AddGenericHandler(ctx, name, FromOperationHandlerToHandler(sync))
}

func (c *operationController) OnRemove(ctx context.Context, name string, sync OperationHandler) {
	c.AddGenericHandler(ctx, name, generic.NewRemoveHandler(name, c.Updater(), FromOperationHandlerToHandler(sync)))
}

func (c *operationController) Enqueue(namespace, name string) {
	c.controller.Enqueue(namespace, name)
}

func (c *operationController) EnqueueAfter(namespace, name string, duration time.Duration) {
	c.controller.EnqueueAfter(namespace, name, duration)
}

func (c *operationController) Informer() cache.SharedIndexInformer {
	return c.controller.Informer()
}

func (c *operationController) GroupVersionKind() schema.GroupVersionKind {
	return c.gvk
}

func (c *operationController) Cache() OperationCache {
	return &operationCache{
		indexer:  c.Informer().GetIndexer(),
		resource: c.groupResource,
	}
}

func (c *operationController) Create(obj *v1.Operation) (*v1.Operation, error) {
	result := &v1.Operation{}
	return result, c.client.Create(context.TODO(), obj.Namespace, obj, result, metav1.CreateOptions{})
}

func (c *operationController) Update(obj *v1.Operation) (*v1.Operation, error) {
	result := &v1.Operation{}
	return result, c.client.Update(context.TODO(), obj.Namespace, obj, result, metav1.UpdateOptions{})
}

func (c *operationController) UpdateStatus(obj *v1.Operation) (*v1.Operation, error) {
	result := &v1.Operation{}
	return result, c.client.UpdateStatus(context.TODO(), obj.Namespace, obj, result, metav1.UpdateOptions{})
}

func (c *operationController) Delete(namespace, name string, options *metav1.DeleteOptions) error {
	if options == nil {
		options = &metav1.DeleteOptions{}
	}
	return c.client.Delete(context.TODO(), namespace, name, *options)
}

func (c *operationController) Get(namespace, name string, options metav1.GetOptions) (*v1.Operation, error) {
	result := &v1.Operation{}
	return result, c.client.Get(context.TODO(), namespace, name, result, options)
}

func (c *operationController) List(namespace string, opts metav1.ListOptions) (*v1.OperationList, error) {
	result := &v1.OperationList{}
	return result, c.client.List(context.TODO(), namespace, result, opts)
}

func (c *operationController) Watch(namespace string, opts metav1.ListOptions) (watch.Interface, error) {
	return c.client.Watch(context.TODO(), namespace, opts)
}

func (c *operationController) Patch(namespace, name string, pt types.PatchType, data []byte, subresources ...string) (*v1.Operation, error) {
	result := &v1.Operation{}
	return result, c.client.Patch(context.TODO(), namespace, name, pt, data, result, metav1.PatchOptions{}, subresources...)
}

type operationCache struct {
	indexer  cache.Indexer
	resource schema.GroupResource
}

func (c *operationCache) Get(namespace, name string) (*v1.Operation, error) {
	obj, exists, err := c.indexer.GetByKey(namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(c.resource, name)
	}
	return obj.(*v1.Operation), nil
}

func (c *operationCache) List(namespace string, selector labels.Selector) (ret []*v1.Operation, err error) {

	err = cache.ListAllByNamespace(c.indexer, namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*v1.Operation))
	})

	return ret, err
}

func (c *operationCache) AddIndexer(indexName string, indexer OperationIndexer) {
	utilruntime.Must(c.indexer.AddIndexers(map[string]cache.IndexFunc{
		indexName: func(obj interface{}) (strings []string, e error) {
			return indexer(obj.(*v1.Operation))
		},
	}))
}

func (c *operationCache) GetByIndex(indexName, key string) (result []*v1.Operation, err error) {
	objs, err := c.indexer.ByIndex(indexName, key)
	if err != nil {
		return nil, err
	}
	result = make([]*v1.Operation, 0, len(objs))
	for _, obj := range objs {
		result = append(result, obj.(*v1.Operation))
	}
	return result, nil
}

type OperationStatusHandler func(obj *v1.Operation, status v1.OperationStatus) (v1.OperationStatus, error)

type OperationGeneratingHandler func(obj *v1.Operation, status v1.OperationStatus) ([]runtime.Object, v1.OperationStatus, error)

func RegisterOperationStatusHandler(ctx context.Context, controller OperationController, condition condition.Cond, name string, handler OperationStatusHandler) {
	statusHandler := &operationStatusHandler{
		client:    controller,
		condition: condition,
		handler:   handler,
	}
	controller.AddGenericHandler(ctx, name, FromOperationHandlerToHandler(statusHandler.sync))
}

func RegisterOperationGeneratingHandler(ctx context.Context, controller OperationController, apply apply.Apply,
	condition condition.Cond, name string, handler OperationGeneratingHandler, opts *generic.GeneratingHandlerOptions) {
	statusHandler := &operationGeneratingHandler{
		OperationGeneratingHandler: handler,
		apply:                      apply,
		name:                       name,
		gvk:                        controller.GroupVersionKind(),
	}
	if opts != nil {
		statusHandler.opts = *opts
	}
	controller.OnChange(ctx, name, statusHandler.Remove)
	RegisterOperationStatusHandler(ctx, controller, condition, name, statusHandler.Handle)
}

type operationStatusHandler struct {
	client    OperationClient
	condition condition.Cond
	handler   OperationStatusHandler
}

func (a *operationStatusHandler) sync(key string, obj *v1.Operation) (*v1.Operation, error) {
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

type operationGeneratingHandler struct {
	OperationGeneratingHandler
	apply apply.Apply
	opts  generic.GeneratingHandlerOptions
	gvk   schema.GroupVersionKind
	name  string
}

func (a *operationGeneratingHandler) Remove(key string, obj *v1.Operation) (*v1.Operation, error) {
	if obj != nil {
		return obj, nil
	}

	obj = &v1.Operation{}
	obj.Namespace, obj.Name = kv.RSplit(key, "/")
	obj.SetGroupVersionKind(a.gvk)

	return nil, generic.ConfigureApplyForObject(a.apply, obj, &a.opts).
		WithOwner(obj).
		WithSetID(a.name).
		ApplyObjects()
}

func (a *operationGeneratingHandler) Handle(obj *v1.Operation, status v1.OperationStatus) (v1.OperationStatus, error) {
	if !obj.DeletionTimestamp.IsZero() {
		return status, nil
	}

	objs, newStatus, err := a.OperationGeneratingHandler(obj, status)
	if err != nil {
		return newStatus, err
	}

	return newStatus, generic.ConfigureApplyForObject(a.apply, obj, &a.opts).
		WithOwner(obj).
		WithSetID(a.name).
		ApplyObjects(objs...)
}
