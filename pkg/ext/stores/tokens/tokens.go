package tokens

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"time"

	ext "github.com/rancher/rancher/pkg/apis/ext.cattle.io/v1"
	"github.com/rancher/rancher/pkg/auth/tokens/hashers"
	v3 "github.com/rancher/rancher/pkg/generated/controllers/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/wrangler"
	extcore "github.com/rancher/steve/pkg/ext"
	v1 "github.com/rancher/wrangler/v3/pkg/generated/controllers/core/v1"
	"github.com/rancher/wrangler/v3/pkg/randomtoken"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metainternalversion "k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"
)

const (
	TokenNamespace = "cattle-tokens"
	ThirtyDays     = 30 * 24 * 60 * 60 * 1000 // 30 days in milliseconds.
	UserIDLabel    = "authn.management.cattle.io/token-userId"

	// data fields used by the backing secrets to store token information
	fieldAuthProvider   = "auth-provider"
	fieldClusterName    = "cluster-name"
	fieldDescription    = "description"
	fieldDisplayName    = "display-name"
	fieldEnabled        = "enabled"
	fieldHash           = "hash"
	fieldIsLogin        = "is-login"
	fieldLastUpdateTime = "last-update-time"
	fieldLastUsedAt     = "last-used-at"
	fieldLoginName      = "login-name"
	fieldPrincipalID    = "principal-id"
	fieldTTL            = "ttl"
	fieldUID            = "kube-uid"
	fieldUserID         = "user-id"

	SingularName = "token"
)

var GV = schema.GroupVersion{
	Group:   "ext.cattle.io",
	Version: "v1",
}

var GVK = schema.GroupVersionKind{
	Group:   GV.Group,
	Version: GV.Version,
	Kind:    "token",
}
var GVR = schema.GroupVersionResource{
	Group:    GV.Group,
	Version:  GV.Version,
	Resource: "token",
}

// +k8s:openapi-gen=false
// +k8s:deepcopy-gen=false

// ////////////////////////////////////////////////////////////////////////////////

// Store is the interface to the token store seen by the extension API and
// users. Wrapped around a SystemStore it performs the necessary checks to
// ensure that Users have only access to the tokens they are permitted to.
type Store struct {
	lock sync.Mutex // serialization of access
	SystemStore
}

// +k8s:openapi-gen=false
// +k8s:deepcopy-gen=false

// SystemStore is the interface to the token store used internally by other
// parts of rancher. It does not perform any kind of permission checks, and
// operates with admin authority, except where told to not to. IOW it generally
// has access to all the tokens, in all ways.
type SystemStore struct {
	namespaceClient     v1.NamespaceClient // access to namespaces
	initialized         bool               // flag is set when this store ensured presence of the backing namespace
	secretClient        v1.SecretClient
	userAttributeClient v3.UserAttributeClient
	userClient          v3.UserClient
	timer               timeHandler // subsystem for timestamp generation
	hasher              hashHandler // subsystem for generation and hashing of secret values
	checker             userHandler // subsystem for user retrieval from context
}

// t.lock.Lock()
// defer t.lock.Unlock()

// ////////////////////////////////////////////////////////////////////////////////
// store contruction methods

// NewFromWrangler is a convenience function for creating a token store.
// It initializes the returned store from the provided wrangler context.
func NewFromWrangler(wranglerContext *wrangler.Context) *Store {
	return New(
		wranglerContext.Core.Namespace(),
		wranglerContext.Core.Secret(),
		wranglerContext.Mgmt.UserAttribute(),
		wranglerContext.Mgmt.User(),
		NewTimeHandler(),
		NewHashHandler(),
		NewUserHandler(),
	)
}

// New is the main constructor for token stores. It is supplied with accessors
// to all the other controllers the store requires for proper function. Note
// that it is recommended to use the NewFromWrangler convenience function
// instead.
func New(
	namespaceClient v1.NamespaceClient,
	secretClient v1.SecretClient,
	uaClient v3.UserAttributeController,
	userClient v3.UserController,
	timer timeHandler,
	hasher hashHandler,
	checker userHandler,
) *Store {
	tokenStore := Store{
		SystemStore: SystemStore{
			namespaceClient:     namespaceClient,
			secretClient:        secretClient,
			userAttributeClient: uaClient,
			userClient:          userClient,
			timer:               timer,
			hasher:              hasher,
			checker:             checker,
		},
	}
	return &tokenStore
}

// NewSystemFromWrangler is a convenience function for creating a system token
// store. It initializes the returned store from the provided wrangler context.
func NewSystemFromWrangler(wranglerContext *wrangler.Context) *SystemStore {
	return NewSystem(
		wranglerContext.Core.Namespace(),
		wranglerContext.Core.Secret(),
		wranglerContext.Mgmt.UserAttribute(),
		wranglerContext.Mgmt.User(),
		NewTimeHandler(),
		NewHashHandler(),
		NewUserHandler(),
	)
}

// NewSystem is the main constructor for system stores. It is supplied with
// accessors to all the other controllers the store requires for proper
// function. Note that it is recommended to use the NewSystemFromWrangler
// convenience function instead.
func NewSystem(
	namespaceClient v1.NamespaceClient,
	secretClient v1.SecretClient,
	uaClient v3.UserAttributeController,
	userClient v3.UserController,
	timer timeHandler,
	hasher hashHandler,
	checker userHandler,
) *SystemStore {
	tokenStore := SystemStore{
		namespaceClient:     namespaceClient,
		secretClient:        secretClient,
		userAttributeClient: uaClient,
		userClient:          userClient,
		timer:               timer,
		hasher:              hasher,
		checker:             checker,
	}
	return &tokenStore
}

// ////////////////////////////////////////////////////////////////////////////////
// Required interfaces:
// - [rest.GroupVersionKindProvider],
// - [rest.Scoper],
// - [rest.SingularNameProvider], and
// - [rest.Storage]

// GroupVersionKind implements [rest.GroupVersionKindProvider]
func (t *Store) GroupVersionKind(_ schema.GroupVersion) schema.GroupVersionKind {
	return GVK
}

// NamespaceScoped implements [rest.Scoper]
func (t *Store) NamespaceScoped() bool {
	return false
}

// GetSingularName implements [rest.SingularNameProvider]
func (t *Store) GetSingularName() string {
	return SingularName
}

// New implements [rest.Storage]
func (t *Store) New() runtime.Object {
	obj := &ext.Token{}
	obj.GetObjectKind().SetGroupVersionKind(GVK)
	return obj
}

// Destroy implements [rest.Storage]
func (t *Store) Destroy() {
}

// ////////////////////////////////////////////////////////////////////////////////
// Optional interfaces -- All implemented, supporting all regular k8s verbs
// - [x] create:           [rest.Creater]
// - [x] delete:           [rest.GracefulDeleter]
// - -- deletecollection: [rest.CollectionDeleter]
// - [x] get:              [rest.Getter]
// - [x] list:             [rest.Lister]
// -    patch:            [rest.Patcher] (this is Getter + Updater)
// - [x] update:           [rest.Updater]
// - [x] watch:            [rest.Watcher]

// The interface methods mostly delegate to the actual store methods, with some
// general method-dependent boilerplate behaviour before and/or after.

// NOTE: Stores serialize all access through them with a mutex.

// Create implements [rest.Creator]
func (t *Store) Create(
	ctx context.Context,
	obj runtime.Object,
	createValidation rest.ValidateObjectFunc,
	options *metav1.CreateOptions) (runtime.Object, error) {
	t.lock.Lock()
	defer t.lock.Unlock()

	if createValidation != nil {
		err := createValidation(ctx, obj)
		if err != nil {
			return obj, err
		}
	}

	objToken, ok := obj.(*ext.Token)
	if !ok {
		var zeroT *ext.Token
		return nil, apierrors.NewInternalError(fmt.Errorf("expected %T but got %T",
			zeroT, obj))
	}

	return t.create(ctx, objToken, options)
}

// Delete implements [rest.GracefulDeleter]
func (t *Store) Delete(
	ctx context.Context,
	name string,
	deleteValidation rest.ValidateObjectFunc,
	options *metav1.DeleteOptions) (runtime.Object, bool, error) {
	t.lock.Lock()
	defer t.lock.Unlock()

	// locate resource first
	obj, err := t.get(ctx, name, &metav1.GetOptions{})
	if err != nil {
		return nil, false, err
	}

	// ensure that deletion is possible
	if deleteValidation != nil {
		err := deleteValidation(ctx, obj)
		if err != nil {
			return nil, false, err
		}
	}

	// and now actually delete
	err = t.delete(ctx, obj, options)
	if err != nil {
		return nil, false, err
	}

	return obj, true, nil
}

// Get implements [rest.Getter]
func (t *Store) Get(
	ctx context.Context,
	name string,
	options *metav1.GetOptions) (runtime.Object, error) {
	t.lock.Lock()
	defer t.lock.Unlock()

	return t.get(ctx, name, options)
}

// NewList implements [rest.Lister]
func (t *Store) NewList() runtime.Object {
	objList := &ext.TokenList{}
	objList.GetObjectKind().SetGroupVersionKind(GVK)
	return objList
}

// List implements [rest.Lister]
func (t *Store) List(
	ctx context.Context,
	internaloptions *metainternalversion.ListOptions) (runtime.Object, error) {
	t.lock.Lock()
	defer t.lock.Unlock()

	options, err := extcore.ConvertListOptions(internaloptions)
	if err != nil {
		return nil, apierrors.NewInternalError(err)
	}
	return t.list(ctx, options)
}

// ConvertToTable implements [rest.Lister]
func (t *Store) ConvertToTable(
	ctx context.Context,
	object runtime.Object,
	tableOptions runtime.Object) (*metav1.Table, error) {

	return extcore.ConvertToTableDefault[*ext.Token](ctx, object, tableOptions,
		GVR.GroupResource())
}

// Update implements [rest.Updater]
func (t *Store) Update(
	ctx context.Context,
	name string,
	objInfo rest.UpdatedObjectInfo,
	createValidation rest.ValidateObjectFunc,
	updateValidation rest.ValidateObjectUpdateFunc,
	forceAllowCreate bool,
	options *metav1.UpdateOptions) (runtime.Object, bool, error) {
	t.lock.Lock()
	defer t.lock.Unlock()

	return extcore.CreateOrUpdate(ctx, name, objInfo, createValidation,
		updateValidation, forceAllowCreate, options,
		t.get, t.create, t.update)
}

// Watch implements [rest.Watcher]
func (t *Store) Watch(
	ctx context.Context,
	internaloptions *metainternalversion.ListOptions) (watch.Interface, error) {
	t.lock.Lock()
	defer t.lock.Unlock()

	options, err := extcore.ConvertListOptions(internaloptions)
	if err != nil {
		return nil, apierrors.NewInternalError(err)
	}
	return t.watch(ctx, options)
}

// ////////////////////////////////////////////////////////////////////////////////
// Actual K8s verb implementations

func (t *Store) create(ctx context.Context, token *ext.Token, options *metav1.CreateOptions) (*ext.Token, error) {
	user, err := t.checker.UserName(ctx)
	if err != nil {
		return nil, apierrors.NewInternalError(err)
	}
	if !userMatch(user, token) {
		return nil, apierrors.NewBadRequest("unable to create token for other user")
	}
	return t.SystemStore.Create(GVR.GroupResource(), token, options)
}

func (t *SystemStore) Create(group schema.GroupResource, token *ext.Token, options *metav1.CreateOptions) (*ext.Token, error) {
	// ensure existence of the namespace holding our secrets. run once per store.
	if !t.initialized {
		_, err := t.namespaceClient.Create(&corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: TokenNamespace,
			},
		})
		if err != nil && !apierrors.IsAlreadyExists(err) {
			return nil, err
		}
		t.initialized = true
	}

	ensureNameOrGenerateName(token)
	// we check the Name directly. because of the ensure... we know that
	// GenerateName is not set. as it squashes the name in that case.
	if token.Name != "" {
		// reject creation of a token which already exists
		currentSecret, err := t.secretClient.Get(TokenNamespace, token.Name, metav1.GetOptions{})
		if err == nil && currentSecret != nil {
			return nil, apierrors.NewAlreadyExists(group, token.Name)
		}
	}

	// reject user-provided token value, or hash
	if token.Status.TokenValue != "" {
		return nil, apierrors.NewBadRequest("User provided token value is not permitted")
	}
	if token.Status.TokenHash != "" {
		return nil, apierrors.NewBadRequest("User provided token hash is not permitted")
	}

	// Get derived User information for the token.
	//
	// NOTE: The creation process is not given `AuthProvider`, `User-` and `GroupPrincipals`.
	// ..... This information have to be retrieved from somewhere else in the system.
	// ..... This is in contrast to the Norman tokens who get this information either
	// ..... as part of the Login process, or by copying the information out of the
	// ..... base token the new one is derived from. None of that is possible here.
	//
	// A User's `AuthProvider` information is generally captured in their associated
	// `UserAttribute` resource. This is what we retrieve and use here now to fill these fields
	// of the token to be.
	//
	// `ProviderInfo` is not supported. Norman tokens have it as legacy fallback to hold the
	// `access_token` data managed by OIDC-based auth providers. The actual primary storage for
	// this is actually a regular k8s Secret associated with the User.
	//
	// `UserPrincipal` is filled in part with standard information, and in part from the
	// associated `User`s fields.

	attribs, err := t.userAttributeClient.Get(token.Spec.UserID, metav1.GetOptions{})
	if err != nil {
		return nil, apierrors.NewInternalError(fmt.Errorf("failed to retrieve user attributes of %s: %w",
			token.Spec.UserID, err))
	}
	if attribs == nil {
		return nil, apierrors.NewInternalError(fmt.Errorf("failed to get user attributes of %s",
			token.Spec.UserID))
	}

	if len(attribs.ExtraByProvider) != 1 {
		return nil, apierrors.NewInternalError(fmt.Errorf("bad user attributes: bogus ExtraByProvider, empty or ambigous"))
	}

	user, err := t.userClient.Get(token.Spec.UserID, metav1.GetOptions{})
	if err != nil {
		return nil, apierrors.NewInternalError(fmt.Errorf("failed to retrieve user %s: %w",
			token.Spec.UserID, err))
	}
	if user == nil {
		return nil, apierrors.NewInternalError(fmt.Errorf("failed to get user %s", token.Spec.UserID))
	}

	// Reject operation if the user is disabled.
	if user.Enabled != nil && !*user.Enabled {
		return nil, apierrors.NewBadRequest("Operation references a disabled user")
	}

	// Generate secret and its hash

	tokenValue, hashedValue, err := t.hasher.MakeAndHashSecret()
	if err != nil {
		return nil, err
	}

	// UNRELIABLE // UNRELIABLE // UNRELIABLE -- TODO rework when the modified ext API is available.
	//
	// (len == 1) => The single key in the UserAttribute map names the auth provider
	// (and where to look in GroupPrincipals, if we were using GroupPrincipals)
	var authProvider string
	for ap, _ := range attribs.ExtraByProvider {
		authProvider = ap
		break
	}

	token.Status.TokenHash = hashedValue
	token.Status.AuthProvider = authProvider
	token.Status.DisplayName = user.DisplayName
	token.Status.LoginName = user.Username // See also attribs.ExtraByProvider[ap]["username"][0]

	// UNRELIABLE // UNRELIABLE // UNRELIABLE -- TODO rework when the modified ext API is available.
	// PM: Same as with the auth provider.
	// PM: Can't use that to determine the principal that was used for this specific request.
	// PM: For the use case of creating a token for a different user this has to come in the
	// PM: spec and the requested auth provider should match the one that is used to authenticate the request.
	token.Status.PrincipalID = attribs.ExtraByProvider[authProvider]["principalid"][0]

	token.Status.LastUpdateTime = t.timer.Now()

	rest.FillObjectMetaSystemFields(token)

	secret := secretFromToken(token)

	// TODO :: For `token.ClusterName != ""`
	// TODO :: CHECK that both requesting and token users have access to that cluster
	// TODO :: QUESTION :: how to perform such a check ?

	// Save new secret
	newSecret, err := t.secretClient.Create(secret)
	if err != nil {
		if apierrors.IsAlreadyExists(err) {
			// can happen despite the early check for a pre-existing secret.
			// something else may have raced us while the secret was assembled.
			return nil, err
		}
		return nil, apierrors.NewInternalError(fmt.Errorf("failed to store token %s: %w",
			token.Name, err))
	}

	// Read changes back to return what was truly created, not what we thought we created
	newToken, err := tokenFromSecret(newSecret)
	if err != nil {
		return nil, apierrors.NewInternalError(fmt.Errorf("failed to regenerate token %s: %w",
			token.Name, err))
	}

	// users don't care about the hashed value
	newToken.Status.TokenHash = ""
	newToken.Status.TokenValue = tokenValue
	return newToken, nil
}

func (t *Store) delete(ctx context.Context, token *ext.Token, options *metav1.DeleteOptions) error {
	user, err := t.checker.UserName(ctx)
	if err != nil {
		return apierrors.NewInternalError(err)
	}
	if !userMatch(user, token) {
		return apierrors.NewNotFound(GVR.GroupResource(), token.Name)
	}

	return t.SystemStore.Delete(token.Name, options)
}

func (t *SystemStore) Delete(name string, options *metav1.DeleteOptions) error {
	err := t.secretClient.Delete(TokenNamespace, name, options)
	if err == nil {
		return nil
	}
	if apierrors.IsNotFound(err) {
		return nil
	}
	return apierrors.NewInternalError(fmt.Errorf("failed to delete token %s: %w", name, err))
}

func (t *Store) get(ctx context.Context, name string, options *metav1.GetOptions) (*ext.Token, error) {
	// note: have to get token first before we can check for a user mismatch
	token, err := t.SystemStore.Get(name, options)
	if err != nil {
		return nil, err
	}

	user, err := t.checker.UserName(ctx)
	if err != nil {
		return nil, apierrors.NewInternalError(err)
	}
	if !userMatch(user, token) {
		return nil, apierrors.NewNotFound(GVR.GroupResource(), name)
	}

	return token, nil
}

func (t *SystemStore) Get(name string, options *metav1.GetOptions) (*ext.Token, error) {
	// Core token retrieval from backing secrets
	currentSecret, err := t.secretClient.Get(TokenNamespace, name, *options)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, err
		}
		return nil, apierrors.NewInternalError(fmt.Errorf("failed to retrieve token %s: %w", name, err))
	}
	token, err := tokenFromSecret(currentSecret)
	if err != nil {
		return nil, apierrors.NewInternalError(fmt.Errorf("failed to extract token %s: %w", name, err))
	}
	token.Status.TokenValue = ""
	return token, nil
}

func (t *Store) list(ctx context.Context, options *metav1.ListOptions) (*ext.TokenList, error) {
	user, err := t.checker.UserName(ctx)
	if err != nil {
		return nil, apierrors.NewInternalError(err)
	}
	return t.SystemStore.list(false, user, options)
}

func (t *SystemStore) List(options *metav1.ListOptions) (*ext.TokenList, error) {
	return t.list(true, "", options)
}

func (t *SystemStore) list(fullView bool, user string, options *metav1.ListOptions) (*ext.TokenList, error) {
	// Core token listing from backing secrets
	secrets, err := t.secretClient.List(TokenNamespace, *options)
	if err != nil {
		return nil, apierrors.NewInternalError(fmt.Errorf("failed to list tokens: %w", err))
	}
	var tokens []ext.Token
	for _, secret := range secrets.Items {
		token, err := tokenFromSecret(&secret)
		// ignore broken tokens
		if err != nil {
			continue
		}
		// users can only list their own tokens. the system can list all for its tasks.
		if !fullView && !userMatch(user, token) {
			continue
		}
		tokens = append(tokens, *token)
	}
	list := ext.TokenList{
		ListMeta: metav1.ListMeta{
			ResourceVersion: secrets.ResourceVersion,
		},
		Items: tokens,
	}
	return &list, nil
}

func (t *Store) update(ctx context.Context, token *ext.Token, options *metav1.UpdateOptions) (*ext.Token, error) {
	user, err := t.checker.UserName(ctx)
	if err != nil {
		return nil, apierrors.NewInternalError(err)
	}
	if !userMatch(user, token) {
		return nil, apierrors.NewNotFound(GVR.GroupResource(), token.Name)
	}

	return t.SystemStore.update(false, token, options)
}

func (t *SystemStore) Update(token *ext.Token, options *metav1.UpdateOptions) (*ext.Token, error) {
	return t.update(true, token, options)
}

func (t *SystemStore) update(fullPermission bool, token *ext.Token, options *metav1.UpdateOptions) (*ext.Token, error) {
	currentSecret, err := t.secretClient.Get(TokenNamespace, token.Name, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, err
		}
		return nil, apierrors.NewInternalError(fmt.Errorf("failed to retrieve token %s: %w",
			token.Name, err))
	}
	currentToken, err := tokenFromSecret(currentSecret)
	if err != nil {
		return nil, apierrors.NewInternalError(fmt.Errorf("failed to extract token %s: %w",
			token.Name, err))
	}

	if token.Spec.UserID != currentToken.Spec.UserID {
		return nil, apierrors.NewBadRequest(fmt.Sprintf("rejecting change of token %s: forbidden to edit user id",
			token.Name))
	}
	if token.Spec.ClusterName != currentToken.Spec.ClusterName {
		return nil, apierrors.NewBadRequest(fmt.Sprintf("rejecting change of token %s: forbidden to edit cluster name",
			token.Name))
	}
	if token.Spec.IsLogin != currentToken.Spec.IsLogin {
		return nil, apierrors.NewBadRequest(fmt.Sprintf("rejecting change of token %s: forbidden to edit flag isLogin",
			token.Name))
	}

	// Work on the time to live (TTL) value is a bit more complicated. Even
	// the owning user is not allowed to extend the TTL, only keep or shrink
	// it. Only the system itself is allowed to perform an extension. Note
	// that nothing currently makes use of that.

	if !fullPermission {
		if token.Spec.TTL > currentToken.Spec.TTL {
			return nil, apierrors.NewBadRequest(fmt.Sprintf("rejecting change of token %s: forbidden to extend time-to-live",
				token.Name))
		}
	}

	// Keep the status of the resource unchanged, never store a token value, etc.
	// IOW changes to display name, login name, etc. are all ignored without a peep.
	token.Status = currentToken.Status
	token.Status.TokenValue = ""
	// Refresh time of last update to current.
	token.Status.LastUpdateTime = t.timer.Now()

	// Save changes to backing secret
	secret := secretFromToken(token)

	newSecret, err := t.secretClient.Update(secret)
	if err != nil {
		return nil, apierrors.NewInternalError(fmt.Errorf("failed to update token %s: %w",
			token.Name, err))
	}

	// Read changes back to return what was truly saved, not what we thought we saved
	newToken, err := tokenFromSecret(newSecret)
	if err != nil {
		return nil, apierrors.NewInternalError(fmt.Errorf("failed to regenerate token %s: %w",
			token.Name, err))
	}

	newToken.Status.TokenValue = ""
	return newToken, nil
}

func (t *SystemStore) UpdateLastUsedAt(name string, now time.Time) error {
	// Operate directly on the backend secret holding the token

	nowStr := now.Format(time.RFC3339)
	nowEncoded := base64.StdEncoding.EncodeToString([]byte(nowStr))

	patch, err := json.Marshal([]struct {
		Op    string `json:"op"`
		Path  string `json:"path"`
		Value any    `json:"value"`
	}{{
		Op:    "replace",
		Path:  "/data/" + fieldLastUsedAt,
		Value: nowEncoded,
	}})
	if err != nil {
		return err
	}

	_, err = t.secretClient.Patch(TokenNamespace, name, types.JSONPatchType, patch)
	return err
}

func (t *Store) watch(ctx context.Context, options *metav1.ListOptions) (watch.Interface, error) {
	user, err := t.checker.UserName(ctx)
	if err != nil {
		return nil, apierrors.NewInternalError(err)
	}

	// the channel to the consumer is given a bit of slack, allowing the
	// producer (the go routine below) to run a bit ahead of the consumer
	// for a burst of events.
	consumer := &watcher{
		ch: make(chan watch.Event, 100),
	}

	// watch the backend secrets for changes and transform their events into
	// the appropriate token events.
	go func() {
		producer, err := t.secretClient.Watch(TokenNamespace, *options)
		if err != nil {
			close(consumer.ch)
			return
		}

		defer producer.Stop()
		for {
			select {
			case <-ctx.Done():
				// terminate if the context got cancelled on us
				close(consumer.ch)
				return
			case event, more := <-producer.ResultChan():
				// terminate if the producer has nothing more to deliver
				if !more {
					close(consumer.ch)
					return
				}

				// skip bogus events on not-secrets
				secret, ok := event.Object.(*corev1.Secret)
				if !ok {
					continue
				}

				token, err := tokenFromSecret(secret)
				// skip broken tokens
				if err != nil {
					continue
				}

				// skip tokens not owned by watching user
				if !userMatch(user, token) {
					continue
				}

				// push to consumer, and terminate ourselves if
				// the consumer terminated on us
				if pushed := consumer.addEvent(watch.Event{
					Type:   event.Type,
					Object: token,
				}); !pushed {
					return
				}
			}
		}
	}()

	return consumer, nil
}

// watcher implements [watch.Interface]
type watcher struct {
	closedLock sync.RWMutex
	closed     bool
	ch         chan watch.Event
}

// Stop implements [watch.Interface]
// As documented in [watch] it is forbidden to invoke this method from the
// producer, i.e. here the token store. This method is strictly for use by the
// consumer (the caller of the `watch` method above, i.e. k8s itself).
func (w *watcher) Stop() {
	w.closedLock.Lock()
	defer w.closedLock.Unlock()

	// no operation if called multiple times.
	if w.closed {
		return
	}

	close(w.ch)
	w.closed = true
}

// ResultChan implements [watch.Interface]
func (w *watcher) ResultChan() <-chan watch.Event {
	return w.ch
}

// addEvent pushes a new event to the watcher. This fails if the watcher was
// `Stop()`ed already by the consumer. The boolean result is true on success.
// This is used by the watcher-internal goroutine to determine if it has to
// terminate, or not.
func (w *watcher) addEvent(event watch.Event) bool {
	w.closedLock.RLock()
	defer w.closedLock.RUnlock()
	if w.closed {
		return false
	}

	w.ch <- event
	return true
}

// userMatch hides the details of matching a user name against an ext token.
func userMatch(name string, token *ext.Token) bool {
	return name == token.Spec.UserID
}

// ////////////////////////////////////////////////////////////////////////////////
// Support interfaces for testability.

// Note: Review the interfaces and implementations below when we have more than
// just the token store, to consider generalization for sharing across stores.

// Mockable interfaces for permission checking, secret generation and hashing, and timing

// timeHandler is an interface hiding the details of timestamp generation from
// the store. This makes the operation mockable for store testing.
type timeHandler interface {
	Now() string
}

// hashHandler is an interface hiding the details of secret generation and
// hashing from the store. This makes these operations mockable for store
// testing.
type hashHandler interface {
	MakeAndHashSecret() (string, string, error)
}

// userHandler is an interface hiding the details of retrieving the user name
// from the store. This makes these operations mockable for store testing.
type userHandler interface {
	UserName(ctx context.Context) (string, error)
}

// Standard implementations for the above interfaces.

func NewTimeHandler() timeHandler {
	return &tokenTimer{}
}

func NewHashHandler() hashHandler {
	return &tokenHasher{}
}

func NewUserHandler() userHandler {
	return &tokenChecker{}
}

// tokenTimer is an implementation of the timeHandler interface.
type tokenTimer struct{}

// tokenHasher is an implementation of the hashHandler interface.
type tokenHasher struct{}

// tokenChecker is an implementation of the userHandler interface.
type tokenChecker struct{}

// Now returns the current time as a RFC 3339 formatted string.
func (tp *tokenTimer) Now() string {
	return time.Now().Format(time.RFC3339)
}

// MakeAndHashSecret creates a token secret, hashes it, and returns both secret and hash.
func (tp *tokenHasher) MakeAndHashSecret() (string, string, error) {
	tokenValue, err := randomtoken.Generate()
	if err != nil {
		return "", "", apierrors.NewInternalError(fmt.Errorf("failed to generate token value: %w", err))
	}
	hashedValue, err := hashers.GetHasher().CreateHash(tokenValue)
	if err != nil {
		return "", "", apierrors.NewInternalError(fmt.Errorf("failed to hash token value: %w", err))
	}

	return tokenValue, hashedValue, nil
}

// UserName hides the details of extracting a user name from the request context
func (tp *tokenChecker) UserName(ctx context.Context) (string, error) {
	userInfo, ok := request.UserFrom(ctx)
	if !ok {
		return "", fmt.Errorf("context has no user info")
	}

	return userInfo.GetName(), nil
}

// Internal supporting functionality

// secretFromToken converts the token argument into the equivalent secrets to
// store in k8s.
func secretFromToken(token *ext.Token) *corev1.Secret {
	// inject default on creation
	ttl := token.Spec.TTL
	if ttl == 0 {
		ttl = ThirtyDays
		// pass back to caller (Create)
		token.Spec.TTL = ttl
	}

	// extend labels for future filtering of tokens by user
	labels := token.Labels
	if labels == nil {
		labels = map[string]string{}
	}
	labels[UserIDLabel] = token.Spec.UserID

	// ensure that only one of name or generateName is passed through.
	name := token.Name
	genName := token.GenerateName
	if genName != "" {
		name = ""
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:    TokenNamespace,
			Name:         name,
			GenerateName: genName,
			Labels:       labels,
			Annotations:  token.Annotations,
		},
		StringData: make(map[string]string),
		Data:       make(map[string][]byte),
	}

	// system
	secret.StringData[fieldUID] = string(token.ObjectMeta.UID)

	// spec
	secret.StringData[fieldUserID] = token.Spec.UserID
	secret.StringData[fieldClusterName] = token.Spec.ClusterName
	secret.StringData[fieldTTL] = fmt.Sprintf("%d", ttl)
	secret.StringData[fieldEnabled] = fmt.Sprintf("%t", token.Spec.Enabled)
	secret.StringData[fieldDescription] = token.Spec.Description
	secret.StringData[fieldIsLogin] = fmt.Sprintf("%t", token.Spec.IsLogin)

	lastUsedAsString := ""
	if token.Status.LastUsedAt != nil {
		lastUsedAsString = token.Status.LastUsedAt.Format(time.RFC3339)
	}

	// status
	secret.StringData[fieldHash] = token.Status.TokenHash
	secret.StringData[fieldLastUpdateTime] = token.Status.LastUpdateTime
	secret.StringData[fieldLastUsedAt] = lastUsedAsString

	// Note:
	// - While the derived expiration data is not stored, the user-related information is.
	// - The expiration data is computed trivially from spec and resource data.
	// - Getting the user-related information on the other hand is expensive.
	// - It is better to cache it in the backing secret

	secret.StringData[fieldAuthProvider] = token.Status.AuthProvider
	secret.StringData[fieldDisplayName] = token.Status.DisplayName
	secret.StringData[fieldLoginName] = token.Status.LoginName
	secret.StringData[fieldPrincipalID] = token.Status.PrincipalID

	return secret
}

// tokenFromSecret converts the secret argument (retrieved from the k8s store)
// into the equivalent token.
func tokenFromSecret(secret *corev1.Secret) (*ext.Token, error) {
	// Basic result. This will be incrementally filled as data is extracted from the secret.
	// On error a partially filled token is returned.
	// See the token store `Delete` (marker **) for where this is important.
	token := &ext.Token{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Token",
			APIVersion: "ext.cattle.io/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:              secret.Name,
			CreationTimestamp: secret.CreationTimestamp,
			Labels:            secret.Labels,
			Annotations:       secret.Annotations,
		},
	}

	token.Spec.Description = string(secret.Data[fieldDescription])
	token.Spec.ClusterName = string(secret.Data[fieldClusterName])
	token.Status.DisplayName = string(secret.Data[fieldDisplayName])
	token.Status.LoginName = string(secret.Data[fieldLoginName])

	userId := string(secret.Data[fieldUserID])
	if userId == "" {
		return token, fmt.Errorf("user id missing")
	}
	token.Spec.UserID = userId

	// spec
	enabled, err := strconv.ParseBool(string(secret.Data[fieldEnabled]))
	if err != nil {
		return token, err
	}
	token.Spec.Enabled = enabled

	isLogin, err := strconv.ParseBool(string(secret.Data[fieldIsLogin]))
	if err != nil {
		return token, err
	}
	token.Spec.IsLogin = isLogin

	ttl, err := strconv.ParseInt(string(secret.Data[fieldTTL]), 10, 64)
	if err != nil {
		return token, err
	}
	// inject default on retrieval
	if ttl == 0 {
		ttl = ThirtyDays
	}
	token.Spec.TTL = ttl

	tokenHash := string(secret.Data[fieldHash])
	if tokenHash == "" {
		return token, fmt.Errorf("token hash missing")
	}
	token.Status.TokenHash = tokenHash

	authProvider := string(secret.Data[fieldAuthProvider])
	if authProvider == "" {
		return token, fmt.Errorf("auth provider missing")
	}
	token.Status.AuthProvider = authProvider

	lastUpdateTime := string(secret.Data[fieldLastUpdateTime])
	if lastUpdateTime == "" {
		return token, fmt.Errorf("last update time missing")
	}
	token.Status.LastUpdateTime = lastUpdateTime

	// The principal id is the object name of the virtual v3.Principal
	// resource and is therefore a required data element. display and login
	// name on the other hand are optional.
	principalID := string(secret.Data[fieldPrincipalID])
	if principalID == "" {
		return token, fmt.Errorf("principal id missing")
	}
	token.Status.PrincipalID = principalID

	kubeUID := string(secret.Data[fieldUID])
	if kubeUID == "" {
		return token, fmt.Errorf("kube uid missing")
	}
	token.ObjectMeta.UID = types.UID(kubeUID)

	var lastUsedAt *metav1.Time
	lastUsedAsString := string(secret.Data[fieldLastUsedAt])
	if lastUsedAsString != "" {
		lastUsed, err := time.Parse(time.RFC3339, lastUsedAsString)
		if err != nil {
			return token, fmt.Errorf("failed to parse lastUsed data: %w", err)
		}
		lastUsedTime := metav1.NewTime(lastUsed)
		lastUsedAt = &lastUsedTime
	} // else: empty => lastUsedAt == nil
	token.Status.LastUsedAt = lastUsedAt

	if err := setExpired(token); err != nil {
		return token, fmt.Errorf("failed to set expiration information: %w", err)
	}

	return token, nil
}

// setExpired computes the expiration data (isExpired, expiresAt) from token
// creation time and time to live and places the results into the associated
// token fields.
func setExpired(token *ext.Token) error {
	if token.Spec.TTL < 0 {
		token.Status.Expired = false
		token.Status.ExpiresAt = ""
		return nil
	}

	expiresAt := token.ObjectMeta.CreationTimestamp.Add(time.Duration(token.Spec.TTL) * time.Millisecond)
	isExpired := time.Now().After(expiresAt)

	eAt, err := metav1.NewTime(expiresAt).MarshalJSON()
	if err != nil {
		return err
	}

	// note: The marshalling puts quotes around the string. strip them
	// before handing this to the token and yaml adding another layer
	// of quotes around such a string
	token.Status.ExpiresAt = string(eAt[1 : len(eAt)-1])
	token.Status.Expired = isExpired
	return nil
}

// ensureNameOrGenerateName ensures that the token has either a proper name, or
// a generateName clause. Note, this function does __not generate__ the name if
// the latter is present. That is delegated to the backend store, i.e. the
// secrets holding tokens. See `secretFromToken` above.
func ensureNameOrGenerateName(token *ext.Token) error {
	// NOTE: When both name and generateName are set the generateName has precedence

	if token.ObjectMeta.GenerateName != "" {
		token.ObjectMeta.Name = ""
		return nil
	}
	if token.ObjectMeta.Name != "" {
		return nil
	}

	return apierrors.NewBadRequest(fmt.Sprintf(
		"Token \"%s\" is invalid: metadata.name: Required value: name or generateName is required",
		token.ObjectMeta.Name))
}
