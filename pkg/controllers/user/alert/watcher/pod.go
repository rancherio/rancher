package watcher

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/runtime"

	"github.com/rancher/norman/controller"
	"github.com/rancher/rancher/pkg/controllers/user/alert/configsyncer"
	"github.com/rancher/rancher/pkg/controllers/user/alert/manager"
	"github.com/rancher/rancher/pkg/ticker"
	"github.com/rancher/types/apis/core/v1"
	"github.com/rancher/types/apis/management.cattle.io/v3"
	"github.com/rancher/types/config"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

type PodWatcher struct {
	podLister               v1.PodLister
	alertManager            *manager.AlertManager
	projectAlertPolicies    v3.ProjectAlertRuleInterface
	projectAlertGroupLister v3.ProjectAlertRuleLister
	clusterName             string
	podRestartTrack         sync.Map
	clusterLister           v3.ClusterLister
}

type restartTrack struct {
	Count int32
	Time  time.Time
}

func StartPodWatcher(ctx context.Context, cluster *config.UserContext, manager *manager.AlertManager) {
	projectAlertPolicies := cluster.Management.Management.ProjectAlertRules("")

	podWatcher := &PodWatcher{
		podLister:               cluster.Core.Pods("").Controller().Lister(),
		projectAlertPolicies:    projectAlertPolicies,
		projectAlertGroupLister: projectAlertPolicies.Controller().Lister(),
		alertManager:            manager,
		clusterName:             cluster.ClusterName,
		podRestartTrack:         sync.Map{},
		clusterLister:           cluster.Management.Management.Clusters("").Controller().Lister(),
	}

	projectAlertLifecycle := &ProjectAlertLifecycle{
		podWatcher: podWatcher,
	}
	projectAlertPolicies.AddClusterScopedLifecycle(ctx, "pod-target-alert-watcher", cluster.ClusterName, projectAlertLifecycle)

	go podWatcher.watch(ctx, syncInterval)
}

func (w *PodWatcher) watch(ctx context.Context, interval time.Duration) {
	for range ticker.Context(ctx, interval) {
		err := w.watchRule()
		if err != nil {
			logrus.Infof("Failed to watch pod, error: %v", err)
		}
	}
}

type ProjectAlertLifecycle struct {
	podWatcher *PodWatcher
}

func (l *ProjectAlertLifecycle) Create(obj *v3.ProjectAlertRule) (runtime.Object, error) {
	l.podWatcher.podRestartTrack.Store(obj.Namespace+":"+obj.Name, make([]restartTrack, 0))
	return obj, nil
}

func (l *ProjectAlertLifecycle) Updated(obj *v3.ProjectAlertRule) (runtime.Object, error) {
	return obj, nil
}

func (l *ProjectAlertLifecycle) Remove(obj *v3.ProjectAlertRule) (runtime.Object, error) {
	l.podWatcher.podRestartTrack.Delete(obj.Namespace + ":" + obj.Name)
	return obj, nil
}

func (w *PodWatcher) watchRule() error {
	if w.alertManager.IsDeploy == false {
		return nil
	}

	projectAlerts, err := w.projectAlertGroupLister.List("", labels.NewSelector())
	if err != nil {
		return err
	}

	pAlerts := []*v3.ProjectAlertRule{}
	for _, alert := range projectAlerts {
		if controller.ObjectInCluster(w.clusterName, alert) {
			pAlerts = append(pAlerts, alert)
		}
	}

	for _, alert := range pAlerts {
		if alert.Status.AlertState == "inactive" || alert.Spec.PodRule == nil {
			continue
		}

		parts := strings.Split(alert.Spec.PodRule.PodName, ":")
		if len(parts) < 2 {
			//TODO: for invalid format pod
			if err = w.projectAlertPolicies.DeleteNamespaced(alert.Namespace, alert.Name, &metav1.DeleteOptions{}); err != nil {
				return err
			}
			continue
		}

		ns := parts[0]
		podID := parts[1]
		newPod, err := w.podLister.Get(ns, podID)
		if err != nil {
			//TODO: what to do when pod not found
			if kerrors.IsNotFound(err) || newPod == nil {
				if err = w.projectAlertPolicies.DeleteNamespaced(alert.Namespace, alert.Name, &metav1.DeleteOptions{}); err != nil {
					return err
				}
			}
			logrus.Debugf("Failed to get pod %s: %v", podID, err)

			continue
		}

		switch alert.Spec.PodRule.Condition {
		case "notrunning":
			w.checkPodRunning(newPod, alert)
		case "notscheduled":
			w.checkPodScheduled(newPod, alert)
		case "restarts":
			w.checkPodRestarts(newPod, alert)
		}
	}

	return nil
}

func (w *PodWatcher) checkPodRestarts(pod *corev1.Pod, alert *v3.ProjectAlertRule) {

	for _, containerStatus := range pod.Status.ContainerStatuses {
		if containerStatus.State.Running == nil {
			curCount := containerStatus.RestartCount
			preCount := w.getRestartTimeFromTrack(alert, curCount)

			if curCount-preCount >= int32(alert.Spec.PodRule.RestartTimes) {
				ruleID := configsyncer.GetRuleID(alert.Spec.GroupName, alert.Name)

				details := ""
				if containerStatus.State.Waiting != nil {
					details = containerStatus.State.Waiting.Message
				}

				clusterDisplayName := w.clusterName
				cluster, err := w.clusterLister.Get("", w.clusterName)
				if err != nil {
					logrus.Warnf("Failed to get cluster for %s: %v", w.clusterName, err)
				} else {
					clusterDisplayName = cluster.Spec.DisplayName
				}

				data := map[string]string{}
				data["rule_id"] = ruleID
				data["group_id"] = alert.Spec.GroupName
				data["alert_type"] = "podRestarts"
				data["severity"] = alert.Spec.Severity
				data["cluster_name"] = clusterDisplayName
				data["namespace"] = pod.Namespace
				data["pod_name"] = pod.Name
				data["container_name"] = containerStatus.Name
				data["restart_times"] = strconv.Itoa(alert.Spec.PodRule.RestartTimes)
				data["restart_interval"] = strconv.Itoa(alert.Spec.PodRule.RestartIntervalSeconds)

				if details != "" {
					data["logs"] = details
				}

				if err := w.alertManager.SendAlert(data); err != nil {
					logrus.Debugf("Error occurred while getting pod %s: %v", alert.Spec.PodRule.PodName, err)
				}
			}

			return
		}
	}

}

func (w *PodWatcher) getRestartTimeFromTrack(alert *v3.ProjectAlertRule, curCount int32) int32 {
	name := alert.Name
	namespace := alert.Namespace

	obj, ok := w.podRestartTrack.Load(namespace + ":" + name)
	if !ok {
		return curCount
	}
	tracks := obj.([]restartTrack)

	now := time.Now()

	if len(tracks) == 0 {
		tracks = append(tracks, restartTrack{Count: curCount, Time: now})
		w.podRestartTrack.Store(namespace+":"+name, tracks)
		return curCount
	}

	for i, track := range tracks {
		if now.Sub(track.Time).Seconds() < float64(alert.Spec.PodRule.RestartIntervalSeconds) {
			tracks = tracks[i:]
			tracks = append(tracks, restartTrack{Count: curCount, Time: now})
			w.podRestartTrack.Store(namespace+":"+name, tracks)
			return track.Count
		}
	}

	w.podRestartTrack.Store(namespace+":"+name, []restartTrack{})
	return curCount
}

func (w *PodWatcher) checkPodRunning(pod *corev1.Pod, alert *v3.ProjectAlertRule) {
	if !w.checkPodScheduled(pod, alert) {
		return
	}

	for _, containerStatus := range pod.Status.ContainerStatuses {
		if containerStatus.State.Running == nil {
			ruleID := configsyncer.GetRuleID(alert.Spec.GroupName, alert.Name)

			//TODO: need to consider all the cases
			details := ""
			if containerStatus.State.Waiting != nil {
				details = containerStatus.State.Waiting.Message
			}

			if containerStatus.State.Terminated != nil {
				details = containerStatus.State.Terminated.Message
			}

			clusterDisplayName := w.clusterName
			cluster, err := w.clusterLister.Get("", w.clusterName)
			if err != nil {
				logrus.Warnf("Failed to get cluster for %s: %v", w.clusterName, err)
			} else {
				clusterDisplayName = cluster.Spec.DisplayName
			}

			data := map[string]string{}
			data["rule_id"] = ruleID
			data["group_id"] = alert.Spec.GroupName
			data["alert_type"] = "podNotRunning"
			data["severity"] = alert.Spec.Severity
			data["cluster_name"] = clusterDisplayName
			data["namespace"] = pod.Namespace
			data["pod_name"] = pod.Name
			data["container_name"] = containerStatus.Name

			if details != "" {
				data["logs"] = details
			}

			if err := w.alertManager.SendAlert(data); err != nil {
				logrus.Debugf("Error occurred while send alert %s: %v", alert.Spec.PodRule.PodName, err)
			}
			return
		}
	}
}

func (w *PodWatcher) checkPodScheduled(pod *corev1.Pod, alert *v3.ProjectAlertRule) bool {

	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodScheduled && condition.Status == corev1.ConditionFalse {
			ruleID := configsyncer.GetRuleID(alert.Spec.GroupName, alert.Name)

			details := condition.Message

			clusterDisplayName := w.clusterName
			cluster, err := w.clusterLister.Get("", w.clusterName)
			if err != nil {
				logrus.Warnf("Failed to get cluster for %s: %v", w.clusterName, err)
			} else {
				clusterDisplayName = cluster.Spec.DisplayName
			}

			data := map[string]string{}
			data["rule_id"] = ruleID
			data["group_id"] = alert.Spec.GroupName
			data["alert_type"] = "podNotScheduled"
			data["severity"] = alert.Spec.Severity
			data["cluster_name"] = clusterDisplayName
			data["namespace"] = pod.Namespace
			data["pod_name"] = pod.Name

			if details != "" {
				data["logs"] = details
			}

			if err := w.alertManager.SendAlert(data); err != nil {
				logrus.Debugf("Error occurred while getting pod %s: %v", alert.Spec.PodRule.PodName, err)
			}
			return false
		}
	}

	return true

}
