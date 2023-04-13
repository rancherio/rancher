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

type CisConfigHandler func(string, *v3.CisConfig) (*v3.CisConfig, error)

type CisConfigController interface {
	generic.ControllerMeta
	CisConfigClient

	OnChange(ctx context.Context, name string, sync CisConfigHandler)
	OnRemove(ctx context.Context, name string, sync CisConfigHandler)
	Enqueue(namespace, name string)
	EnqueueAfter(namespace, name string, duration time.Duration)

	Cache() CisConfigCache
}

type CisConfigClient interface {
	Create(*v3.CisConfig) (*v3.CisConfig, error)
	Update(*v3.CisConfig) (*v3.CisConfig, error)

	Delete(namespace, name string, options *metav1.DeleteOptions) error
	Get(namespace, name string, options metav1.GetOptions) (*v3.CisConfig, error)
	List(namespace string, opts metav1.ListOptions) (*v3.CisConfigList, error)
	Watch(namespace string, opts metav1.ListOptions) (watch.Interface, error)
	Patch(namespace, name string, pt types.PatchType, data []byte, subresources ...string) (result *v3.CisConfig, err error)
}

type CisConfigCache interface {
	Get(namespace, name string) (*v3.CisConfig, error)
	List(namespace string, selector labels.Selector) ([]*v3.CisConfig, error)

	AddIndexer(indexName string, indexer CisConfigIndexer)
	GetByIndex(indexName, key string) ([]*v3.CisConfig, error)
}

type CisConfigIndexer func(obj *v3.CisConfig) ([]string, error)

type cisConfigController struct {
	controller    controller.SharedController
	client        *client.Client
	gvk           schema.GroupVersionKind
	groupResource schema.GroupResource
}

func NewCisConfigController(gvk schema.GroupVersionKind, resource string, namespaced bool, controller controller.SharedControllerFactory) CisConfigController {
	c := controller.ForResourceKind(gvk.GroupVersion().WithResource(resource), gvk.Kind, namespaced)
	return &cisConfigController{
		controller: c,
		client:     c.Client(),
		gvk:        gvk,
		groupResource: schema.GroupResource{
			Group:    gvk.Group,
			Resource: resource,
		},
	}
}

func FromCisConfigHandlerToHandler(sync CisConfigHandler) generic.Handler {
	return func(key string, obj runtime.Object) (ret runtime.Object, err error) {
		var v *v3.CisConfig
		if obj == nil {
			v, err = sync(key, nil)
		} else {
			v, err = sync(key, obj.(*v3.CisConfig))
		}
		if v == nil {
			return nil, err
		}
		return v, err
	}
}

func (c *cisConfigController) Updater() generic.Updater {
	return func(obj runtime.Object) (runtime.Object, error) {
		newObj, err := c.Update(obj.(*v3.CisConfig))
		if newObj == nil {
			return nil, err
		}
		return newObj, err
	}
}

func UpdateCisConfigDeepCopyOnChange(client CisConfigClient, obj *v3.CisConfig, handler func(obj *v3.CisConfig) (*v3.CisConfig, error)) (*v3.CisConfig, error) {
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

func (c *cisConfigController) AddGenericHandler(ctx context.Context, name string, handler generic.Handler) {
	c.controller.RegisterHandler(ctx, name, controller.SharedControllerHandlerFunc(handler))
}

func (c *cisConfigController) AddGenericRemoveHandler(ctx context.Context, name string, handler generic.Handler) {
	c.AddGenericHandler(ctx, name, generic.NewRemoveHandler(name, c.Updater(), handler))
}

func (c *cisConfigController) OnChange(ctx context.Context, name string, sync CisConfigHandler) {
	c.AddGenericHandler(ctx, name, FromCisConfigHandlerToHandler(sync))
}

func (c *cisConfigController) OnRemove(ctx context.Context, name string, sync CisConfigHandler) {
	c.AddGenericHandler(ctx, name, generic.NewRemoveHandler(name, c.Updater(), FromCisConfigHandlerToHandler(sync)))
}

func (c *cisConfigController) Enqueue(namespace, name string) {
	c.controller.Enqueue(namespace, name)
}

func (c *cisConfigController) EnqueueAfter(namespace, name string, duration time.Duration) {
	c.controller.EnqueueAfter(namespace, name, duration)
}

func (c *cisConfigController) Informer() cache.SharedIndexInformer {
	return c.controller.Informer()
}

func (c *cisConfigController) GroupVersionKind() schema.GroupVersionKind {
	return c.gvk
}

func (c *cisConfigController) Cache() CisConfigCache {
	return &cisConfigCache{
		indexer:  c.Informer().GetIndexer(),
		resource: c.groupResource,
	}
}

func (c *cisConfigController) Create(obj *v3.CisConfig) (*v3.CisConfig, error) {
	result := &v3.CisConfig{}
	return result, c.client.Create(context.TODO(), obj.Namespace, obj, result, metav1.CreateOptions{})
}

func (c *cisConfigController) Update(obj *v3.CisConfig) (*v3.CisConfig, error) {
	result := &v3.CisConfig{}
	return result, c.client.Update(context.TODO(), obj.Namespace, obj, result, metav1.UpdateOptions{})
}

func (c *cisConfigController) Delete(namespace, name string, options *metav1.DeleteOptions) error {
	if options == nil {
		options = &metav1.DeleteOptions{}
	}
	return c.client.Delete(context.TODO(), namespace, name, *options)
}

func (c *cisConfigController) Get(namespace, name string, options metav1.GetOptions) (*v3.CisConfig, error) {
	result := &v3.CisConfig{}
	return result, c.client.Get(context.TODO(), namespace, name, result, options)
}

func (c *cisConfigController) List(namespace string, opts metav1.ListOptions) (*v3.CisConfigList, error) {
	result := &v3.CisConfigList{}
	return result, c.client.List(context.TODO(), namespace, result, opts)
}

func (c *cisConfigController) Watch(namespace string, opts metav1.ListOptions) (watch.Interface, error) {
	return c.client.Watch(context.TODO(), namespace, opts)
}

func (c *cisConfigController) Patch(namespace, name string, pt types.PatchType, data []byte, subresources ...string) (*v3.CisConfig, error) {
	result := &v3.CisConfig{}
	return result, c.client.Patch(context.TODO(), namespace, name, pt, data, result, metav1.PatchOptions{}, subresources...)
}

type cisConfigCache struct {
	indexer  cache.Indexer
	resource schema.GroupResource
}

func (c *cisConfigCache) Get(namespace, name string) (*v3.CisConfig, error) {
	obj, exists, err := c.indexer.GetByKey(namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(c.resource, name)
	}
	return obj.(*v3.CisConfig), nil
}

func (c *cisConfigCache) List(namespace string, selector labels.Selector) (ret []*v3.CisConfig, err error) {

	err = cache.ListAllByNamespace(c.indexer, namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*v3.CisConfig))
	})

	return ret, err
}

func (c *cisConfigCache) AddIndexer(indexName string, indexer CisConfigIndexer) {
	utilruntime.Must(c.indexer.AddIndexers(map[string]cache.IndexFunc{
		indexName: func(obj interface{}) (strings []string, e error) {
			return indexer(obj.(*v3.CisConfig))
		},
	}))
}

func (c *cisConfigCache) GetByIndex(indexName, key string) (result []*v3.CisConfig, err error) {
	objs, err := c.indexer.ByIndex(indexName, key)
	if err != nil {
		return nil, err
	}
	result = make([]*v3.CisConfig, 0, len(objs))
	for _, obj := range objs {
		result = append(result, obj.(*v3.CisConfig))
	}
	return result, nil
}
