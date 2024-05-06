/*
Copyright 2024 Rancher Labs, Inc.

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

	v1 "github.com/rancher/rancher/pkg/apis/provisioning.cattle.io/v1"
	"github.com/rancher/wrangler/pkg/apply"
	"github.com/rancher/wrangler/pkg/condition"
	"github.com/rancher/wrangler/pkg/generic"
	"github.com/rancher/wrangler/pkg/kv"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// ClusterController interface for managing Cluster resources.
type ClusterController interface {
	generic.ControllerInterface[*v1.Cluster, *v1.ClusterList]
}

// ClusterClient interface for managing Cluster resources in Kubernetes.
type ClusterClient interface {
	generic.ClientInterface[*v1.Cluster, *v1.ClusterList]
}

// ClusterCache interface for retrieving Cluster resources in memory.
type ClusterCache interface {
	generic.CacheInterface[*v1.Cluster]
}

type ClusterStatusHandler func(obj *v1.Cluster, status v1.ClusterStatus) (v1.ClusterStatus, error)

type ClusterGeneratingHandler func(obj *v1.Cluster, status v1.ClusterStatus) ([]runtime.Object, v1.ClusterStatus, error)

func RegisterClusterStatusHandler(ctx context.Context, controller ClusterController, condition condition.Cond, name string, handler ClusterStatusHandler) {
	statusHandler := &clusterStatusHandler{
		client:    controller,
		condition: condition,
		handler:   handler,
	}
	controller.AddGenericHandler(ctx, name, generic.FromObjectHandlerToHandler(statusHandler.sync))
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
	controller.OnChange(ctx, name, statusHandler.Remove)
	RegisterClusterStatusHandler(ctx, controller, condition, name, statusHandler.Handle)
}

type clusterStatusHandler struct {
	client    ClusterClient
	condition condition.Cond
	handler   ClusterStatusHandler
}

func (a *clusterStatusHandler) sync(key string, obj *v1.Cluster) (*v1.Cluster, error) {
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

type clusterGeneratingHandler struct {
	ClusterGeneratingHandler
	apply apply.Apply
	opts  generic.GeneratingHandlerOptions
	gvk   schema.GroupVersionKind
	name  string
}

func (a *clusterGeneratingHandler) Remove(key string, obj *v1.Cluster) (*v1.Cluster, error) {
	if obj != nil {
		return obj, nil
	}

	obj = &v1.Cluster{}
	obj.Namespace, obj.Name = kv.RSplit(key, "/")
	obj.SetGroupVersionKind(a.gvk)

	return nil, generic.ConfigureApplyForObject(a.apply, obj, &a.opts).
		WithOwner(obj).
		WithSetID(a.name).
		ApplyObjects()
}

func (a *clusterGeneratingHandler) Handle(obj *v1.Cluster, status v1.ClusterStatus) (v1.ClusterStatus, error) {
	if !obj.DeletionTimestamp.IsZero() {
		return status, nil
	}

	objs, newStatus, err := a.ClusterGeneratingHandler(obj, status)
	if err != nil {
		return newStatus, err
	}

	return newStatus, generic.ConfigureApplyForObject(a.apply, obj, &a.opts).
		WithOwner(obj).
		WithSetID(a.name).
		ApplyObjects(objs...)
}
