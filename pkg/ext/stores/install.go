package stores

import (
	"fmt"

	extv1 "github.com/rancher/rancher/pkg/apis/ext.cattle.io/v1"
	"github.com/rancher/rancher/pkg/ext/stores/tokens"
	"github.com/rancher/rancher/pkg/wrangler"
	steveext "github.com/rancher/steve/pkg/ext"

	"k8s.io/apimachinery/pkg/runtime"
)

func InstallStores(server *steveext.ExtensionAPIServer, wranglerContext *wrangler.Context, scheme *runtime.Scheme) error {
	steveext.AddToScheme(scheme)

	// To add a store to the extensionAPIServer, simply add the types to the *runtime.Scheme and

	// call InstallStore with the required fields.

	extv1.AddToScheme(scheme)

	// Note: token store without `manage-token` verb does not require the authorizer.
	// authorizer := server.GetAuthorizer()

	err := server.Install(
		tokens.SingularName,
		tokens.GVK,
		tokens.NewFromWrangler(wranglerContext))
	if err != nil {
		return fmt.Errorf("unable to install %s store: %w", tokens.SingularName, err)
	}

	return nil
}
