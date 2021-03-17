/*
Copyright 2021 Rancher Labs, Inc.

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
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
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
)

type AzureADProviderHandler func(string, *v3.AzureADProvider) (*v3.AzureADProvider, error)

type AzureADProviderController interface {
	generic.ControllerMeta
	AzureADProviderClient

	OnChange(ctx context.Context, name string, sync AzureADProviderHandler)
	OnRemove(ctx context.Context, name string, sync AzureADProviderHandler)
	Enqueue(name string)
	EnqueueAfter(name string, duration time.Duration)

	Cache() AzureADProviderCache
}

type AzureADProviderClient interface {
	Create(*v3.AzureADProvider) (*v3.AzureADProvider, error)
	Update(*v3.AzureADProvider) (*v3.AzureADProvider, error)

	Delete(name string, options *metav1.DeleteOptions) error
	Get(name string, options metav1.GetOptions) (*v3.AzureADProvider, error)
	List(opts metav1.ListOptions) (*v3.AzureADProviderList, error)
	Watch(opts metav1.ListOptions) (watch.Interface, error)
	Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v3.AzureADProvider, err error)
}

type AzureADProviderCache interface {
	Get(name string) (*v3.AzureADProvider, error)
	List(selector labels.Selector) ([]*v3.AzureADProvider, error)

	AddIndexer(indexName string, indexer AzureADProviderIndexer)
	GetByIndex(indexName, key string) ([]*v3.AzureADProvider, error)
}

type AzureADProviderIndexer func(obj *v3.AzureADProvider) ([]string, error)

type azureADProviderController struct {
	controller    controller.SharedController
	client        *client.Client
	gvk           schema.GroupVersionKind
	groupResource schema.GroupResource
}

func NewAzureADProviderController(gvk schema.GroupVersionKind, resource string, namespaced bool, controller controller.SharedControllerFactory) AzureADProviderController {
	c := controller.ForResourceKind(gvk.GroupVersion().WithResource(resource), gvk.Kind, namespaced)
	return &azureADProviderController{
		controller: c,
		client:     c.Client(),
		gvk:        gvk,
		groupResource: schema.GroupResource{
			Group:    gvk.Group,
			Resource: resource,
		},
	}
}

func FromAzureADProviderHandlerToHandler(sync AzureADProviderHandler) generic.Handler {
	return func(key string, obj runtime.Object) (ret runtime.Object, err error) {
		var v *v3.AzureADProvider
		if obj == nil {
			v, err = sync(key, nil)
		} else {
			v, err = sync(key, obj.(*v3.AzureADProvider))
		}
		if v == nil {
			return nil, err
		}
		return v, err
	}
}

func (c *azureADProviderController) Updater() generic.Updater {
	return func(obj runtime.Object) (runtime.Object, error) {
		newObj, err := c.Update(obj.(*v3.AzureADProvider))
		if newObj == nil {
			return nil, err
		}
		return newObj, err
	}
}

func UpdateAzureADProviderDeepCopyOnChange(client AzureADProviderClient, obj *v3.AzureADProvider, handler func(obj *v3.AzureADProvider) (*v3.AzureADProvider, error)) (*v3.AzureADProvider, error) {
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

func (c *azureADProviderController) AddGenericHandler(ctx context.Context, name string, handler generic.Handler) {
	c.controller.RegisterHandler(ctx, name, controller.SharedControllerHandlerFunc(handler))
}

func (c *azureADProviderController) AddGenericRemoveHandler(ctx context.Context, name string, handler generic.Handler) {
	c.AddGenericHandler(ctx, name, generic.NewRemoveHandler(name, c.Updater(), handler))
}

func (c *azureADProviderController) OnChange(ctx context.Context, name string, sync AzureADProviderHandler) {
	c.AddGenericHandler(ctx, name, FromAzureADProviderHandlerToHandler(sync))
}

func (c *azureADProviderController) OnRemove(ctx context.Context, name string, sync AzureADProviderHandler) {
	c.AddGenericHandler(ctx, name, generic.NewRemoveHandler(name, c.Updater(), FromAzureADProviderHandlerToHandler(sync)))
}

func (c *azureADProviderController) Enqueue(name string) {
	c.controller.Enqueue("", name)
}

func (c *azureADProviderController) EnqueueAfter(name string, duration time.Duration) {
	c.controller.EnqueueAfter("", name, duration)
}

func (c *azureADProviderController) Informer() cache.SharedIndexInformer {
	return c.controller.Informer()
}

func (c *azureADProviderController) GroupVersionKind() schema.GroupVersionKind {
	return c.gvk
}

func (c *azureADProviderController) Cache() AzureADProviderCache {
	return &azureADProviderCache{
		indexer:  c.Informer().GetIndexer(),
		resource: c.groupResource,
	}
}

func (c *azureADProviderController) Create(obj *v3.AzureADProvider) (*v3.AzureADProvider, error) {
	result := &v3.AzureADProvider{}
	return result, c.client.Create(context.TODO(), "", obj, result, metav1.CreateOptions{})
}

func (c *azureADProviderController) Update(obj *v3.AzureADProvider) (*v3.AzureADProvider, error) {
	result := &v3.AzureADProvider{}
	return result, c.client.Update(context.TODO(), "", obj, result, metav1.UpdateOptions{})
}

func (c *azureADProviderController) Delete(name string, options *metav1.DeleteOptions) error {
	if options == nil {
		options = &metav1.DeleteOptions{}
	}
	return c.client.Delete(context.TODO(), "", name, *options)
}

func (c *azureADProviderController) Get(name string, options metav1.GetOptions) (*v3.AzureADProvider, error) {
	result := &v3.AzureADProvider{}
	return result, c.client.Get(context.TODO(), "", name, result, options)
}

func (c *azureADProviderController) List(opts metav1.ListOptions) (*v3.AzureADProviderList, error) {
	result := &v3.AzureADProviderList{}
	return result, c.client.List(context.TODO(), "", result, opts)
}

func (c *azureADProviderController) Watch(opts metav1.ListOptions) (watch.Interface, error) {
	return c.client.Watch(context.TODO(), "", opts)
}

func (c *azureADProviderController) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (*v3.AzureADProvider, error) {
	result := &v3.AzureADProvider{}
	return result, c.client.Patch(context.TODO(), "", name, pt, data, result, metav1.PatchOptions{}, subresources...)
}

type azureADProviderCache struct {
	indexer  cache.Indexer
	resource schema.GroupResource
}

func (c *azureADProviderCache) Get(name string) (*v3.AzureADProvider, error) {
	obj, exists, err := c.indexer.GetByKey(name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(c.resource, name)
	}
	return obj.(*v3.AzureADProvider), nil
}

func (c *azureADProviderCache) List(selector labels.Selector) (ret []*v3.AzureADProvider, err error) {

	err = cache.ListAll(c.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v3.AzureADProvider))
	})

	return ret, err
}

func (c *azureADProviderCache) AddIndexer(indexName string, indexer AzureADProviderIndexer) {
	utilruntime.Must(c.indexer.AddIndexers(map[string]cache.IndexFunc{
		indexName: func(obj interface{}) (strings []string, e error) {
			return indexer(obj.(*v3.AzureADProvider))
		},
	}))
}

func (c *azureADProviderCache) GetByIndex(indexName, key string) (result []*v3.AzureADProvider, err error) {
	objs, err := c.indexer.ByIndex(indexName, key)
	if err != nil {
		return nil, err
	}
	result = make([]*v3.AzureADProvider, 0, len(objs))
	for _, obj := range objs {
		result = append(result, obj.(*v3.AzureADProvider))
	}
	return result, nil
}
