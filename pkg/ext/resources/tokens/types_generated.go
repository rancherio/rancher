package tokens

import (
	"github.com/rancher/wrangler/v3/pkg/schemes"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	RancherTokenName = "ranchertokens"
)

var SchemeGroupVersion = schema.GroupVersion{Group: "ext.cattle.io", Version: "v1alpha1"}
var TokenAPIResource = metav1.APIResource{
	Name:         "ranchertokens",
	SingularName: "ranchertoken",
	Namespaced:   false,
	Kind:         "RancherToken",
	Verbs: metav1.Verbs{
		"create",
		"update",
		"patch",
		"get",
		"list",
		"watch",
		"delete",
	},
}

func Kind(kind string) schema.GroupKind {
	return SchemeGroupVersion.WithKind(kind).GroupKind()
}

func Resource(resource string) schema.GroupResource {
	return SchemeGroupVersion.WithResource(resource).GroupResource()
}

var (
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)
	AddToScheme   = SchemeBuilder.AddToScheme
)

func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(SchemeGroupVersion,
		&RancherToken{},
		&RancherTokenList{},
	)
	metav1.AddToGroupVersion(scheme, SchemeGroupVersion)
	return nil
}

var _ runtime.Object = (*RancherToken)(nil)

func (in *RancherToken) DeepCopyInto(out *RancherToken) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.Spec = in.Spec
	out.Status = in.Status
}

func (in *RancherToken) DeepCopy() *RancherToken {
	if in == nil {
		return nil
	}
	out := new(RancherToken)
	in.DeepCopyInto(out)
	return out
}

func (r *RancherToken) DeepCopyObject() runtime.Object {
	if c := r.DeepCopy(); c != nil {
		return c
	}
	return nil
}

type RancherTokenList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	Items []RancherToken `json:"items"`
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *RancherTokenList) DeepCopyInto(out *RancherTokenList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]RancherToken, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TokenList.
func (in *RancherTokenList) DeepCopy() *RancherTokenList {
	if in == nil {
		return nil
	}
	out := new(RancherTokenList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *RancherTokenList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

func init() {
	schemes.Register(AddToScheme)
}
