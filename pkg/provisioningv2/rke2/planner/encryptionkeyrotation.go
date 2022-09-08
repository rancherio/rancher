package planner

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/blang/semver"
	"github.com/pkg/errors"
	"github.com/rancher/channelserver/pkg/model"
	rkev1 "github.com/rancher/rancher/pkg/apis/rke.cattle.io/v1"
	"github.com/rancher/rancher/pkg/apis/rke.cattle.io/v1/plan"
	"github.com/rancher/rancher/pkg/controllers/provisioningv2/rke2"
	"github.com/rancher/wrangler/pkg/generic"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/api/equality"
)

const (
	encryptionKeyRotationCommandStagePrepare           = "prepare"
	encryptionKeyRotationCommandStageRotate            = "rotate"
	encryptionKeyRotationCommandStageReencryptFinished = "reencrypt_finished"

	encryptionKeyRotationCommandPrepare   = "prepare"
	encryptionKeyRotationCommandRotate    = "rotate"
	encryptionKeyRotationCommandReencrypt = "reencrypt"

	encryptionKeyRotationSecretsEncryptApplyCommand = "secrets-encrypt-apply"

	encryptionKeyRotationLeaderAnnotation = "rke.cattle.io/encrypt-key-rotation-leader"

	encryptionKeyRotationInstallRoot = "/var/lib/rancher"
	encryptionKeyRotationBinPrefix   = "rancher_v2prov_encryption_key_rotation/bin"

	encryptionKeyRotationWaitForSystemctlStatusPath      = "wait_for_systemctl_status.sh"
	encryptionKeyRotationWaitForSecretsEncryptStatusPath = "wait_for_secrets_encrypt_status.sh"
	encryptionKeyRotationActionPath                      = "action.sh"

	encryptionKeyRotationWaitForSystemctlStatus = `
#!/bin/sh

runtimeServer=$1
i=0

while [ $i -lt 10 ]; do
	systemctl is-active $runtimeServer
	if [ $? -eq 0 ]; then
		exit 0
	fi
	sleep 10
	i=$((i + 1))
done
exit 1
`

	encryptionKeyRotationWaitForSecretsEncryptStatusScript = `
#!/bin/sh

runtime=$1
phase=$2
i=0

while true; do
	output="$($runtime secrets-encrypt status)"
	if [ $? -eq 0 ]; then
		echo $output | head -3 | tail -1 | grep -q $phase
		if [ $? -eq 0 ]; then
			exit 0
		fi
	fi
	sleep 1
	i=$((i + 1))
done
exit 1
`

	idempotentActionScript = `
#!/bin/sh

currentGeneration=""
key=$1
targetGeneration=$2
runtime=$3
shift
shift
shift

dataRoot="/var/lib/rancher/$runtime/$key"
generationFile="$dataRoot/generation"

currentGeneration=$(cat "$generationFile" || echo "")

if [ "$currentGeneration" != "$targetGeneration" ]; then
	$runtime $@
else
	echo "action has already been reconciled to the current generation."
fi

mkdir -p "$dataRoot"
echo "$targetGeneration" > "$generationFile"
`

	encryptionKeyRotationEndpointEnv = "CONTAINER_RUNTIME_ENDPOINT=unix:///var/run/k3s/containerd/containerd.sock"
)

func (p *Planner) setEncryptionKeyRotateState(controlPlane *rkev1.RKEControlPlane, status *rkev1.RotateEncryptionKeys, phase rkev1.RotateEncryptionKeysPhase) error {
	if equality.Semantic.DeepEqual(controlPlane.Status.RotateEncryptionKeys, status) && equality.Semantic.DeepEqual(controlPlane.Status.RotateEncryptionKeysPhase, phase) {
		return nil
	}
	controlPlane = controlPlane.DeepCopy()
	controlPlane.Status.RotateEncryptionKeys = status
	controlPlane.Status.RotateEncryptionKeysPhase = phase
	_, err := p.rkeControlPlanes.UpdateStatus(controlPlane)
	if err != nil {
		return err
	}
	return ErrWaiting("refreshing encryption key rotation state")
}

func (p *Planner) resetEncryptionKeyRotateState(controlPlane *rkev1.RKEControlPlane) error {
	if controlPlane.Status.RotateEncryptionKeys == nil && controlPlane.Status.RotateEncryptionKeysPhase == "" {
		return nil
	}
	return p.setEncryptionKeyRotateState(controlPlane, nil, "")
}

// rotateEncryptionKeys first verifies that the control plane is in a state where the next step can be derived. If encryption key rotation is required, the corresponding phase and status fields will be set.
// The function is expected to be called multiple times throughout encryption key rotation, and will set the next corresponding phase based on previous output.
func (p *Planner) rotateEncryptionKeys(cp *rkev1.RKEControlPlane, releaseData *model.Release, clusterPlan *plan.Plan) error {
	if cp == nil || releaseData == nil || clusterPlan == nil {
		return fmt.Errorf("cannot pass nil parameters to rotateEncryptionKeys")
	}

	if cp.Spec.RotateEncryptionKeys == nil {
		return p.resetEncryptionKeyRotateState(cp)
	}

	if supported, err := encryptionKeyRotationSupported(releaseData); err != nil {
		return err
	} else if !supported {
		logrus.Debugf("rkecluster %s/%s: marking encryption key rotation phase as failed as it was not supported by version: %s", cp.Namespace, cp.Name, cp.Spec.KubernetesVersion)
		return p.setEncryptionKeyRotateState(cp, cp.Spec.RotateEncryptionKeys, rkev1.RotateEncryptionKeysPhaseFailed)
	}

	if !canRotateEncryptionKeys(cp) {
		return nil
	}

	if shouldRestartEncryptionKeyRotation(cp) {
		logrus.Debugf("[planner] rkecluster %s/%s: starting/restarting encryption key rotation", cp.Namespace, cp.Name)
		return p.setEncryptionKeyRotateState(cp, cp.Spec.RotateEncryptionKeys, rkev1.RotateEncryptionKeysPhasePrepare)
	}

	leader, err := p.encryptionKeyRotationElectLeader(cp, clusterPlan)
	if err != nil {
		return err
	}

	logrus.Debugf("[planner] rkecluster %s/%s: current encryption key rotation phase: [%s]", cp.Namespace, cp.Spec.ClusterName, cp.Status.RotateEncryptionKeysPhase)

	switch cp.Status.RotateEncryptionKeysPhase {
	case rkev1.RotateEncryptionKeysPhasePrepare:
		err = p.encryptionKeyRotationLeaderPhaseReconcile(cp, leader)
		if err != nil {
			return err
		}
		return p.setEncryptionKeyRotateState(cp, cp.Spec.RotateEncryptionKeys, rkev1.RotateEncryptionKeysPhasePostPrepareRestart)
	case rkev1.RotateEncryptionKeysPhasePostPrepareRestart:
		err = p.encryptionKeyRotationRestartNodes(cp, clusterPlan, leader)
		if err != nil {
			return err
		}
		return p.setEncryptionKeyRotateState(cp, cp.Spec.RotateEncryptionKeys, rkev1.RotateEncryptionKeysPhaseRotate)
	case rkev1.RotateEncryptionKeysPhaseRotate:
		err = p.encryptionKeyRotationLeaderPhaseReconcile(cp, leader)
		if err != nil {
			return err
		}
		return p.setEncryptionKeyRotateState(cp, cp.Spec.RotateEncryptionKeys, rkev1.RotateEncryptionKeysPhasePostRotateRestart)
	case rkev1.RotateEncryptionKeysPhasePostRotateRestart:
		err = p.encryptionKeyRotationRestartNodes(cp, clusterPlan, leader)
		if err != nil {
			return err
		}
		return p.setEncryptionKeyRotateState(cp, cp.Spec.RotateEncryptionKeys, rkev1.RotateEncryptionKeysPhaseReencrypt)
	case rkev1.RotateEncryptionKeysPhaseReencrypt:
		err = p.encryptionKeyRotationLeaderPhaseReconcile(cp, leader)
		if err != nil {
			return err
		}
		return p.setEncryptionKeyRotateState(cp, cp.Spec.RotateEncryptionKeys, rkev1.RotateEncryptionKeysPhasePostReencryptRestart)
	case rkev1.RotateEncryptionKeysPhasePostReencryptRestart:
		err = p.encryptionKeyRotationRestartNodes(cp, clusterPlan, leader)
		if err != nil {
			return err
		}
		return p.setEncryptionKeyRotateState(cp, cp.Spec.RotateEncryptionKeys, rkev1.RotateEncryptionKeysPhaseDone)
	}

	return fmt.Errorf("encountered unknown encryption key rotation phase: %s", cp.Status.RotateEncryptionKeysPhase)
}

// encryptionKeyRotationSupported returns a boolean indicating whether encryption key rotation is supported by the release,
// and an error if one was encountered.
func encryptionKeyRotationSupported(releaseData *model.Release) (bool, error) {
	if releaseData == nil {
		return false, fmt.Errorf("unable to find KDM release data for encryption key rotation support in release")
	}
	if featureVersion, ok := releaseData.FeatureVersions["encryption-key-rotation"]; ok {
		version, err := semver.Make(featureVersion)
		if err != nil {
			return false, fmt.Errorf("unable to parse semver version for encryption key rotation: %s", featureVersion)
		}
		// v2.6.4 - v2.6.6 are looking for 1.x.x, but encryption key rotation does not work in those versions. Rather than
		// enable it retroactively, those versions will not be able to rotate encryption keys since some cluster
		// configurations can break in such a way that they become unrecoverable. Additionally, we want to be careful
		// updating the encryption-key-rotation feature gate in KDM in the future, so as not to break backwards
		// compatibility for existing clusters.
		if version.Major == 2 {
			return true, nil
		}
	}
	return false, nil
}

// canRotateEncryptionKeys returns false if the controlplane does not have a Ready: True condition and encryption key rotation is not already in progress, if the spec for
// encryption key rotation is nil, or if the spec has been reconciled but the phase is done or failed.
func canRotateEncryptionKeys(cp *rkev1.RKEControlPlane) bool {
	if (!rke2.Ready.IsTrue(cp) && !rotateEncryptionKeyInProgress(cp)) ||
		cp.Spec.RotateEncryptionKeys == nil ||
		(cp.Status.RotateEncryptionKeys != nil && cp.Status.RotateEncryptionKeys.Generation == cp.Spec.RotateEncryptionKeys.Generation &&
			(cp.Status.RotateEncryptionKeysPhase == rkev1.RotateEncryptionKeysPhaseDone || cp.Status.RotateEncryptionKeysPhase == rkev1.RotateEncryptionKeysPhaseFailed)) {
		return false
	}

	return true
}

// shouldRestartEncryptionKeyRotation returns `true` if encryption key rotation is necessary and the fields on the status object are not valid for an encryption key rotation procedure.
func shouldRestartEncryptionKeyRotation(cp *rkev1.RKEControlPlane) bool {
	if !rke2.Ready.IsTrue(cp) {
		return false
	}
	if cp.Spec.RotateEncryptionKeys.Generation > 0 && cp.Status.RotateEncryptionKeys == nil {
		return true
	}
	if (cp.Status.RotateEncryptionKeysPhase == rkev1.RotateEncryptionKeysPhaseDone ||
		cp.Status.RotateEncryptionKeysPhase == rkev1.RotateEncryptionKeysPhaseFailed ||
		cp.Status.RotateEncryptionKeysPhase == "") &&
		cp.Spec.RotateEncryptionKeys.Generation != cp.Status.RotateEncryptionKeys.Generation {
		return true
	}
	if !hasValidNonFailedRotateEncryptionKeyStatus(cp) {
		return true
	}
	return false
}

// hasValidNonFailedRotateEncryptionKeyStatus verifies that the control plane encryption key status is an expected value and is not failed.
func hasValidNonFailedRotateEncryptionKeyStatus(cp *rkev1.RKEControlPlane) bool {
	return rotateEncryptionKeyInProgress(cp) ||
		cp.Status.RotateEncryptionKeysPhase == rkev1.RotateEncryptionKeysPhaseDone
}

// rotateEncryptionKeyInProgress returns true if the phase of the encryption key rotation indicates that rotation is in progress.
func rotateEncryptionKeyInProgress(cp *rkev1.RKEControlPlane) bool {
	return cp.Status.RotateEncryptionKeysPhase == rkev1.RotateEncryptionKeysPhasePrepare ||
		cp.Status.RotateEncryptionKeysPhase == rkev1.RotateEncryptionKeysPhasePostPrepareRestart ||
		cp.Status.RotateEncryptionKeysPhase == rkev1.RotateEncryptionKeysPhaseRotate ||
		cp.Status.RotateEncryptionKeysPhase == rkev1.RotateEncryptionKeysPhasePostRotateRestart ||
		cp.Status.RotateEncryptionKeysPhase == rkev1.RotateEncryptionKeysPhaseReencrypt ||
		cp.Status.RotateEncryptionKeysPhase == rkev1.RotateEncryptionKeysPhasePostReencryptRestart
}

// encryptionKeyRotationElectLeader returns the current encryption rotation leader if it is valid, otherwise, if the
// phase is "prepare", it will re-elect a new leader. It will look for the init node, and if the init node is not valid
// (etcd-only), it will elect the first suitable control plane node. If the phase is not in "prepare" and a re-election
// of the leader is necessary, the phase will be set to failed as this is unexpected.
func (p *Planner) encryptionKeyRotationElectLeader(cp *rkev1.RKEControlPlane, clusterPlan *plan.Plan) (*planEntry, error) {
	_, _, init, err := p.findInitNode(cp, clusterPlan)
	if init == nil {
		return nil, p.encryptionKeyRotationFailed(cp, err)
	}

	if machineName, ok := cp.Annotations[encryptionKeyRotationLeaderAnnotation]; ok {
		if machine, ok := clusterPlan.Machines[machineName]; ok {
			entry := &planEntry{
				Machine:  machine,
				Plan:     clusterPlan.Nodes[machineName],
				Metadata: clusterPlan.Metadata[machineName],
			}
			if encryptionKeyRotationIsSuitableControlPlane(entry) {
				return entry, nil
			}
		}
	}

	if cp.Status.RotateEncryptionKeysPhase != rkev1.RotateEncryptionKeysPhasePrepare {
		// if we are electing a leader and are not in the "prepare" phase, something is wrong.
		return nil, p.encryptionKeyRotationFailed(cp, fmt.Errorf("re-election of encryption key rotation leader occurred when phase was %s", cp.Status.RotateEncryptionKeysPhase))
	}

	leader := init
	if !isControlPlane(init) {
		machines := collect(clusterPlan, encryptionKeyRotationIsSuitableControlPlane)
		if len(machines) == 0 {
			return nil, p.encryptionKeyRotationFailed(cp, fmt.Errorf("no suitable control plane nodes for encryption key rotation"))
		}
		leader = machines[0]
	}

	cp = cp.DeepCopy()
	cp.Annotations[encryptionKeyRotationLeaderAnnotation] = leader.Machine.Name
	_, err = p.rkeControlPlanes.Update(cp)
	if err != nil {
		return nil, err
	}
	return nil, generic.ErrSkip
}

// encryptionKeyRotationIsSuitableControlPlane ensures that a control plane node has not been deleted and has a valid
// node associated with it.
func encryptionKeyRotationIsSuitableControlPlane(entry *planEntry) bool {
	return isControlPlane(entry) && entry.Machine.DeletionTimestamp == nil && entry.Machine.Status.NodeRef != nil && rke2.Ready.IsTrue(entry.Machine)
}

// encryptionKeyRotationIsControlPlaneAndNotLeaderAndInit allows us to filter cluster plans to restart healthy follower nodes.
func encryptionKeyRotationIsControlPlaneAndNotLeaderAndInit(cp *rkev1.RKEControlPlane) roleFilter {
	return func(entry *planEntry) bool {
		return isControlPlaneAndNotInitNode(entry) &&
			cp.Annotations[encryptionKeyRotationLeaderAnnotation] != entry.Machine.Name
	}
}

// encryptionKeyRotationIsEtcdAndNotControlPlaneAndNotLeaderAndInit allows us to filter cluster plans to restart healthy follower nodes.
func encryptionKeyRotationIsEtcdAndNotControlPlaneAndNotLeaderAndInit(cp *rkev1.RKEControlPlane) roleFilter {
	return func(entry *planEntry) bool {
		return isEtcd(entry) && !isControlPlane(entry) &&
			cp.Annotations[encryptionKeyRotationLeaderAnnotation] != entry.Machine.Name &&
			!isInitNode(entry)
	}
}

// encryptionKeyRotationRestartNodes restarts the leader's server service, extracting the current stage afterwards.
// The followers (if any exist) are subsequently restarted. Notably, if the encryption key rotation leader is not the init node,
// it will restart the init node, then restart the encryption key rotation leader,
// then finalize walking through etcd nodes (that are not controlplane), then finally controlplane nodes.
func (p *Planner) encryptionKeyRotationRestartNodes(cp *rkev1.RKEControlPlane, clusterPlan *plan.Plan, leader *planEntry) error {
	// in certain cases with multi-node setups, we must restart the init node before we can proceed to restarting the leader.
	if !isInitNode(leader) {
		logrus.Debugf("[planner] rkecluster %s/%s: leader %s was not the init node, finding and restarting services on init node", cp.Namespace, cp.Name, leader.Machine.Name)
		// find init node and restart service on the init node first.
		initNodeFound, _, initNode, err := p.findInitNode(cp, clusterPlan)
		if err != nil {
			return err
		}
		if !initNodeFound {
			return fmt.Errorf("unable to find init node")
		}

		err = p.encryptionKeyRotationRestartService(cp, initNode)
		if err != nil {
			return err
		}
		logrus.Debugf("[planner] rkecluster %s/%s: collecting etcd and not control plane", cp.Namespace, cp.Name)
		for _, entry := range collect(clusterPlan, encryptionKeyRotationIsEtcdAndNotControlPlaneAndNotLeaderAndInit(cp)) {
			err = p.encryptionKeyRotationRestartService(cp, entry)
			if err != nil {
				return err
			}
		}
	}

	err := p.encryptionKeyRotationRestartService(cp, leader)
	if err != nil {
		return err
	}

	logrus.Debugf("[planner] rkecluster %s/%s: collecting control plane and not leader and init nodes", cp.Namespace, cp.Name)
	for _, entry := range collect(clusterPlan, encryptionKeyRotationIsControlPlaneAndNotLeaderAndInit(cp)) {
		err = p.encryptionKeyRotationRestartService(cp, entry)
		if err != nil {
			return err
		}
	}

	return nil
}

// encryptionKeyRotationRestartService restarts the server unit on the downstream node, waits until secrets-encrypt
// status can be successfully queried, and then gets the status. leaderStage is allowed to be empty if entry is the
// leader.
func (p *Planner) encryptionKeyRotationRestartService(cp *rkev1.RKEControlPlane, entry *planEntry) error {
	nodePlan := plan.NodePlan{
		Files: []plan.File{
			{
				Content: base64.StdEncoding.EncodeToString([]byte(encryptionKeyRotationWaitForSystemctlStatus)),
				Path:    encryptionKeyRotationScriptPath(cp, encryptionKeyRotationWaitForSystemctlStatusPath),
			},
		},
		Instructions: []plan.OneTimeInstruction{
			encryptionKeyRotationRestartInstruction(cp),
			encryptionKeyRotationWaitForSystemctlStatusInstruction(cp),
		},
	}

	if isControlPlane(entry) {
		nodePlan.Files = append(nodePlan.Files,
			plan.File{
				Content: base64.StdEncoding.EncodeToString([]byte(encryptionKeyRotationWaitForSecretsEncryptStatusScript)),
				Path:    encryptionKeyRotationScriptPath(cp, encryptionKeyRotationWaitForSecretsEncryptStatusPath),
			},
		)
		nodePlan.Instructions = append(nodePlan.Instructions,
			encryptionKeyRotationWaitForSecretsEncryptStatus(cp),
		)
	}
	// retry is important here because without it, we always seem to run into some sort of issue such as:
	// - the follower node reporting the wrong status after a restart
	// - the plan failing with the k3s/rke2-server services crashing the first, and resuming subsequent times
	// It's not necessarily ideal if encryption key rotation can never complete, especially since we don't have access to
	// the downstream k3s/rke2-server service logs, but it has to be done in order for encryption key rotation to succeed
	err := assignAndCheckPlan(p.store, fmt.Sprintf("encryption key rotation [%s] for machine [%s]", cp.Status.RotateEncryptionKeysPhase, entry.Machine.Name), entry, nodePlan, 5, 5)
	if err != nil {
		if isErrWaiting(err) {
			return err
		}
		return p.encryptionKeyRotationFailed(cp, err)
	}

	return nil
}

// encryptionKeyRotationLeaderPhaseReconcile will run the secrets-encrypt command that corresponds to the phase, and scrape output to ensure that it was
// successful. If the secrets-encrypt command does not exist on the plan, that means this is the first reconciliation, and
// it must be added, otherwise reenqueue until the plan is in sync.
func (p *Planner) encryptionKeyRotationLeaderPhaseReconcile(cp *rkev1.RKEControlPlane, leader *planEntry) error {
	apply, err := encryptionKeyRotationSecretsEncryptInstruction(cp)
	if err != nil {
		return p.encryptionKeyRotationFailed(cp, err)
	}

	nodePlan := plan.NodePlan{
		Files: []plan.File{
			{
				Content: base64.StdEncoding.EncodeToString([]byte(idempotentActionScript)),
				Path:    encryptionKeyRotationScriptPath(cp, encryptionKeyRotationActionPath),
			},
			{
				Content: base64.StdEncoding.EncodeToString([]byte(encryptionKeyRotationWaitForSecretsEncryptStatusScript)),
				Path:    encryptionKeyRotationScriptPath(cp, encryptionKeyRotationWaitForSecretsEncryptStatusPath),
			},
		},
		Instructions: []plan.OneTimeInstruction{
			apply,
			encryptionKeyRotationWaitForSecretsEncryptStatus(cp),
		},
	}
	err = assignAndCheckPlan(p.store, fmt.Sprintf("encryption key rotation [%s] for machine [%s]", cp.Status.RotateEncryptionKeysPhase, leader.Machine.Name), leader, nodePlan, 1, 1)
	if err != nil {
		if isErrWaiting(err) {
			if strings.HasPrefix(err.Error(), "starting") {
				logrus.Infof("[planner] rkecluster %s/%s: applying encryption key rotation stage command: [%s]", cp.Namespace, cp.Spec.ClusterName, apply.Args[1])
			}
			return err
		}
		return p.encryptionKeyRotationFailed(cp, err)
	}
	// successful restart, complete same phases for rotate & reencrypt
	logrus.Infof("[planner] rkecluster %s/%s: successfully applied encryption key rotation stage command: [%s]", cp.Namespace, cp.Spec.ClusterName, leader.Plan.Plan.Instructions[0].Args[1])
	return nil
}

// encryptionKeyRotationUpdateControlPlanePhase updates the control plane status if it has not been done yet.
func (p *Planner) encryptionKeyRotationUpdateControlPlanePhase(cp *rkev1.RKEControlPlane, phase rkev1.RotateEncryptionKeysPhase) error {
	if cp.Status.RotateEncryptionKeysPhase != phase {
		cp = cp.DeepCopy()
		logrus.Infof("[planner] rkecluster %s/%s: applying encryption key rotation phase: [%s]", cp.Namespace, cp.Spec.ClusterName, phase)
		cp.Status.RotateEncryptionKeysPhase = phase
		_, err := p.rkeControlPlanes.UpdateStatus(cp)
		if err != nil {
			return err
		}
	}
	return nil
}

// encryptionKeyRotationSecretsEncryptInstruction generates a secrets-encrypt command to run on the leader node given
// the current secrets-encrypt phase.
func encryptionKeyRotationSecretsEncryptInstruction(cp *rkev1.RKEControlPlane) (plan.OneTimeInstruction, error) {
	if cp == nil {
		return plan.OneTimeInstruction{}, fmt.Errorf("controlplane cannot be nil")
	}

	var command string
	switch cp.Status.RotateEncryptionKeysPhase {
	case rkev1.RotateEncryptionKeysPhasePrepare:
		command = encryptionKeyRotationCommandPrepare
	case rkev1.RotateEncryptionKeysPhaseRotate:
		command = encryptionKeyRotationCommandRotate
	case rkev1.RotateEncryptionKeysPhaseReencrypt:
		command = encryptionKeyRotationCommandReencrypt
	default:
		return plan.OneTimeInstruction{}, fmt.Errorf("cannot determine desired secrets-encrypt command for phase: [%s]", cp.Status.RotateEncryptionKeysPhase)
	}

	return plan.OneTimeInstruction{
		Name:    encryptionKeyRotationSecretsEncryptApplyCommand,
		Command: "sh",
		Args: []string{
			"-xe",
			encryptionKeyRotationScriptPath(cp, encryptionKeyRotationActionPath),
			strings.ToLower(fmt.Sprintf("rancher_v2prov_encryption_key_rotation/%s", cp.Status.RotateEncryptionKeysPhase)),
			strconv.FormatInt(cp.Spec.RotateEncryptionKeys.Generation, 10),
			rke2.GetRuntimeCommand(cp.Spec.KubernetesVersion),
			"secrets-encrypt",
			command,
		},
	}, nil
}

// encryptionKeyRotationStatusEnv returns an environment variable in order to force followers to rerun their plans
// following progression of encryption key rotation. In an HA setup with split role etcd & controlplane nodes, the etcd
// nodes would have identical plans, so this variable is used to spoof an update and force the system-agent to run the
// plan.
func encryptionKeyRotationStatusEnv(cp *rkev1.RKEControlPlane) string {
	return fmt.Sprintf("ENCRYPTION_KEY_ROTATION_STAGE=%s", cp.Status.RotateEncryptionKeysPhase)
}

// encryptionKeyRotationGenerationEnv returns an environment variable in order to force followers to rerun their plans
// on subsequent generations, in the event that encryption key rotation is restarting and failed during prepare.
func encryptionKeyRotationGenerationEnv(cp *rkev1.RKEControlPlane) string {
	return fmt.Sprintf("ENCRYPTION_KEY_ROTATION_GENERATION=%d", cp.Spec.RotateEncryptionKeys.Generation)
}

func encryptionKeyRotationExpectedForPhase(cp *rkev1.RKEControlPlane) string {
	switch cp.Status.RotateEncryptionKeysPhase {
	case rkev1.RotateEncryptionKeysPhasePrepare, rkev1.RotateEncryptionKeysPhasePostPrepareRestart:
		return encryptionKeyRotationCommandStagePrepare
	case rkev1.RotateEncryptionKeysPhaseRotate, rkev1.RotateEncryptionKeysPhasePostRotateRestart:
		return encryptionKeyRotationCommandStageRotate
	case rkev1.RotateEncryptionKeysPhaseReencrypt, rkev1.RotateEncryptionKeysPhasePostReencryptRestart:
		return encryptionKeyRotationCommandStageReencryptFinished
	}
	return "" // not possible
}

// encryptionKeyRotationWaitForSystemctlStatusInstruction is intended to run after a node is restart, and wait until the
// node is online and able to provide systemctl status, ensuring that the server service is able to be restarted. If the
// service never comes active, the plan advances anyway in order to restart the service. If restarting the service
// fails, then the plan will fail.
func encryptionKeyRotationWaitForSystemctlStatusInstruction(cp *rkev1.RKEControlPlane) plan.OneTimeInstruction {
	return plan.OneTimeInstruction{
		Name:    "wait-for-systemctl-status",
		Command: "sh",
		Args: []string{
			"-x", encryptionKeyRotationScriptPath(cp, encryptionKeyRotationWaitForSystemctlStatusPath), rke2.GetRuntimeServerUnit(cp.Spec.KubernetesVersion),
		},
		Env: []string{
			encryptionKeyRotationEndpointEnv,
			encryptionKeyRotationStatusEnv(cp),
			encryptionKeyRotationGenerationEnv(cp),
		},
		SaveOutput: false,
	}
}

// encryptionKeyRotationRestartInstruction generates a restart command for the rke2/k3s server, using the last known
// leader stage in order to ensure that non-init nodes have a refreshed plan if the leader stage changes. If
// secrets-encrypt commands were run on a node that is not the init node, this ensures that after this situation is
// identified and the leader is restarted, other control plane nodes will be restarted given that the leader stage will
// have changed without a corresponding apply command.
func encryptionKeyRotationRestartInstruction(cp *rkev1.RKEControlPlane) plan.OneTimeInstruction {
	return plan.OneTimeInstruction{
		Name:    "restart-service",
		Command: "systemctl",
		Args: []string{
			"restart", rke2.GetRuntimeServerUnit(cp.Spec.KubernetesVersion),
		},
		Env: []string{
			encryptionKeyRotationStatusEnv(cp),
			encryptionKeyRotationGenerationEnv(cp),
		},
	}
}

// encryptionKeyRotationWaitForSecretsEncryptStatus is intended to run after a node is restart, and wait until the node
// is online and able to provide secrets-encrypt status, ensuring that subsequent status commands from the system-agent
// will be successful.
func encryptionKeyRotationWaitForSecretsEncryptStatus(cp *rkev1.RKEControlPlane) plan.OneTimeInstruction {
	return plan.OneTimeInstruction{
		Name:    "wait-for-secrets-encrypt-status",
		Command: "sh",
		Args: []string{
			"-x",
			encryptionKeyRotationScriptPath(cp, encryptionKeyRotationWaitForSecretsEncryptStatusPath),
			rke2.GetRuntimeCommand(cp.Spec.KubernetesVersion),
			encryptionKeyRotationExpectedForPhase(cp),
		},
		Env: []string{
			encryptionKeyRotationEndpointEnv,
			encryptionKeyRotationStatusEnv(cp),
			encryptionKeyRotationGenerationEnv(cp),
		},
		SaveOutput: true,
	}
}

// encryptionKeyRotationFailed updates the various status objects on the control plane, allowing the cluster to
// continue the reconciliation loop. Encryption key rotation will not be restarted again until requested.
func (p *Planner) encryptionKeyRotationFailed(cp *rkev1.RKEControlPlane, err error) error {
	if setErr := p.setEncryptionKeyRotateState(cp, cp.Spec.RotateEncryptionKeys, rkev1.RotateEncryptionKeysPhaseFailed); setErr != nil && !isErrWaiting(setErr) {
		return setErr
	}

	err = errors.Wrap(err, "encryption key rotation failed, please perform an etcd restore")
	logrus.Errorf("[planner] rkecluster %s/%s: %v", cp.Namespace, cp.Spec.ClusterName, err)
	return err
}

func encryptionKeyRotationScriptPath(cp *rkev1.RKEControlPlane, file string) string {
	return fmt.Sprintf("%s/%s/%s/%s", encryptionKeyRotationInstallRoot, rke2.GetRuntime(cp.Spec.KubernetesVersion), encryptionKeyRotationBinPrefix, file)
}
