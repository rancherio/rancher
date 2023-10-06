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

package v3

import (
	"context"
	"time"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/wrangler/v2/pkg/apply"
	"github.com/rancher/wrangler/v2/pkg/condition"
	"github.com/rancher/wrangler/v2/pkg/generic"
	"github.com/rancher/wrangler/v2/pkg/kv"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// GlobalDnsController interface for managing GlobalDns resources.
type GlobalDnsController interface {
	generic.ControllerInterface[*v3.GlobalDns, *v3.GlobalDnsList]
}

// GlobalDnsClient interface for managing GlobalDns resources in Kubernetes.
type GlobalDnsClient interface {
	generic.ClientInterface[*v3.GlobalDns, *v3.GlobalDnsList]
}

// GlobalDnsCache interface for retrieving GlobalDns resources in memory.
type GlobalDnsCache interface {
	generic.CacheInterface[*v3.GlobalDns]
}

type GlobalDnsStatusHandler func(obj *v3.GlobalDns, status v3.GlobalDNSStatus) (v3.GlobalDNSStatus, error)

type GlobalDnsGeneratingHandler func(obj *v3.GlobalDns, status v3.GlobalDNSStatus) ([]runtime.Object, v3.GlobalDNSStatus, error)

func RegisterGlobalDnsStatusHandler(ctx context.Context, controller GlobalDnsController, condition condition.Cond, name string, handler GlobalDnsStatusHandler) {
	statusHandler := &globalDnsStatusHandler{
		client:    controller,
		condition: condition,
		handler:   handler,
	}
	controller.AddGenericHandler(ctx, name, generic.FromObjectHandlerToHandler(statusHandler.sync))
}

func RegisterGlobalDnsGeneratingHandler(ctx context.Context, controller GlobalDnsController, apply apply.Apply,
	condition condition.Cond, name string, handler GlobalDnsGeneratingHandler, opts *generic.GeneratingHandlerOptions) {
	statusHandler := &globalDnsGeneratingHandler{
		GlobalDnsGeneratingHandler: handler,
		apply:                      apply,
		name:                       name,
		gvk:                        controller.GroupVersionKind(),
	}
	if opts != nil {
		statusHandler.opts = *opts
	}
	controller.OnChange(ctx, name, statusHandler.Remove)
	RegisterGlobalDnsStatusHandler(ctx, controller, condition, name, statusHandler.Handle)
}

type globalDnsStatusHandler struct {
	client    GlobalDnsClient
	condition condition.Cond
	handler   GlobalDnsStatusHandler
}

func (a *globalDnsStatusHandler) sync(key string, obj *v3.GlobalDns) (*v3.GlobalDns, error) {
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

type globalDnsGeneratingHandler struct {
	GlobalDnsGeneratingHandler
	apply apply.Apply
	opts  generic.GeneratingHandlerOptions
	gvk   schema.GroupVersionKind
	name  string
}

func (a *globalDnsGeneratingHandler) Remove(key string, obj *v3.GlobalDns) (*v3.GlobalDns, error) {
	if obj != nil {
		return obj, nil
	}

	obj = &v3.GlobalDns{}
	obj.Namespace, obj.Name = kv.RSplit(key, "/")
	obj.SetGroupVersionKind(a.gvk)

	return nil, generic.ConfigureApplyForObject(a.apply, obj, &a.opts).
		WithOwner(obj).
		WithSetID(a.name).
		ApplyObjects()
}

func (a *globalDnsGeneratingHandler) Handle(obj *v3.GlobalDns, status v3.GlobalDNSStatus) (v3.GlobalDNSStatus, error) {
	if !obj.DeletionTimestamp.IsZero() {
		return status, nil
	}

	objs, newStatus, err := a.GlobalDnsGeneratingHandler(obj, status)
	if err != nil {
		return newStatus, err
	}

	return newStatus, generic.ConfigureApplyForObject(a.apply, obj, &a.opts).
		WithOwner(obj).
		WithSetID(a.name).
		ApplyObjects(objs...)
}
