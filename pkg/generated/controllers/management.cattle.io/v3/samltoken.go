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

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/wrangler/pkg/generic"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
)

// SamlTokenController interface for managing SamlToken resources.
type SamlTokenController interface {
	generic.ControllerMeta
	SamlTokenClient

	// OnChange runs the given handler when the controller detects a resource was changed.
	OnChange(ctx context.Context, name string, sync SamlTokenHandler)

	// OnRemove runs the given handler when the controller detects a resource was changed.
	OnRemove(ctx context.Context, name string, sync SamlTokenHandler)

	// Enqueue adds the resource with the given name to the worker queue of the controller.
	Enqueue(name string)

	// EnqueueAfter runs Enqueue after the provided duration.
	EnqueueAfter(name string, duration time.Duration)

	// Cache returns a cache for the resource type T.
	Cache() SamlTokenCache
}

// SamlTokenClient interface for managing SamlToken resources in Kubernetes.
type SamlTokenClient interface {
	// Create creates a new object and return the newly created Object or an error.
	Create(*v3.SamlToken) (*v3.SamlToken, error)

	// Update updates the object and return the newly updated Object or an error.
	Update(*v3.SamlToken) (*v3.SamlToken, error)

	// Delete deletes the Object in the given name.
	Delete(name string, options *metav1.DeleteOptions) error

	// Get will attempt to retrieve the resource with the specified name.
	Get(name string, options metav1.GetOptions) (*v3.SamlToken, error)

	// List will attempt to find multiple resources.
	List(opts metav1.ListOptions) (*v3.SamlTokenList, error)

	// Watch will start watching resources.
	Watch(opts metav1.ListOptions) (watch.Interface, error)

	// Patch will patch the resource with the matching name.
	Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v3.SamlToken, err error)
}

// SamlTokenCache interface for retrieving SamlToken resources in memory.
type SamlTokenCache interface {
	// Get returns the resources with the specified name from the cache.
	Get(name string) (*v3.SamlToken, error)

	// List will attempt to find resources from the Cache.
	List(selector labels.Selector) ([]*v3.SamlToken, error)

	// AddIndexer adds  a new Indexer to the cache with the provided name.
	// If you call this after you already have data in the store, the results are undefined.
	AddIndexer(indexName string, indexer SamlTokenIndexer)

	// GetByIndex returns the stored objects whose set of indexed values
	// for the named index includes the given indexed value.
	GetByIndex(indexName, key string) ([]*v3.SamlToken, error)
}

// SamlTokenHandler is function for performing any potential modifications to a SamlToken resource.
type SamlTokenHandler func(string, *v3.SamlToken) (*v3.SamlToken, error)

// SamlTokenIndexer computes a set of indexed values for the provided object.
type SamlTokenIndexer func(obj *v3.SamlToken) ([]string, error)

// SamlTokenGenericController wraps wrangler/pkg/generic.NonNamespacedController so that the function definitions adhere to SamlTokenController interface.
type SamlTokenGenericController struct {
	generic.NonNamespacedControllerInterface[*v3.SamlToken, *v3.SamlTokenList]
}

// OnChange runs the given resource handler when the controller detects a resource was changed.
func (c *SamlTokenGenericController) OnChange(ctx context.Context, name string, sync SamlTokenHandler) {
	c.NonNamespacedControllerInterface.OnChange(ctx, name, generic.ObjectHandler[*v3.SamlToken](sync))
}

// OnRemove runs the given object handler when the controller detects a resource was changed.
func (c *SamlTokenGenericController) OnRemove(ctx context.Context, name string, sync SamlTokenHandler) {
	c.NonNamespacedControllerInterface.OnRemove(ctx, name, generic.ObjectHandler[*v3.SamlToken](sync))
}

// Cache returns a cache of resources in memory.
func (c *SamlTokenGenericController) Cache() SamlTokenCache {
	return &SamlTokenGenericCache{
		c.NonNamespacedControllerInterface.Cache(),
	}
}

// SamlTokenGenericCache wraps wrangler/pkg/generic.NonNamespacedCache so the function definitions adhere to SamlTokenCache interface.
type SamlTokenGenericCache struct {
	generic.NonNamespacedCacheInterface[*v3.SamlToken]
}

// AddIndexer adds  a new Indexer to the cache with the provided name.
// If you call this after you already have data in the store, the results are undefined.
func (c SamlTokenGenericCache) AddIndexer(indexName string, indexer SamlTokenIndexer) {
	c.NonNamespacedCacheInterface.AddIndexer(indexName, generic.Indexer[*v3.SamlToken](indexer))
}
