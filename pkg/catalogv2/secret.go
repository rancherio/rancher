package catalogv2

import (
	v1 "github.com/rancher/rancher/pkg/apis/catalog.cattle.io/v1"
	corev1 "k8s.io/api/core/v1"
)

// TODO - CHECK WHERE SHOULD I PUT THIS INTERFACES !

type SecretGetterNoOption interface {
	Get(namespace, name string) (*corev1.Secret, error)
}

// GetSecret returns the Secret from the cluster repo's clientSecret spec field
func GetSecret(secrets SecretGetterNoOption, repoSpec *v1.RepoSpec, repoNamespace string) (*corev1.Secret, error) {
	if repoSpec.ClientSecret == nil {
		return nil, nil
	}
	ns := repoSpec.ClientSecret.Namespace
	if repoNamespace != "" {
		ns = repoNamespace
	}

	return secrets.Get(ns, repoSpec.ClientSecret.Name)
}
