package tokens

import (
	ext "github.com/rancher/rancher/pkg/apis/ext.cattle.io/v1"
	//extcore "github.com/rancher/steve/pkg/ext"

	"context"
	"fmt"
	"strconv"
	"testing"
	"time"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/wrangler/v3/pkg/generic/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
)

var (
	// properSecret is the backend secret matching the properToken
	properSecret = corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "bogus",
		},
		Data: map[string][]byte{
			"enabled":          []byte("false"),
			"is-login":         []byte("true"),
			"ttl":              []byte("4000"),
			"user-id":          []byte("lkajdlksjlkds"),
			"hash":             []byte("kla9jkdmj"),
			"auth-provider":    []byte("somebody"),
			"last-update-time": []byte("13:00:05"),
			"display-name":     []byte("myself"),
			"login-name":       []byte("hello"),
			"principal-id":     []byte("world"),
			"kube-uid":         []byte("2905498-kafld-lkad"),
		},
	}
	// missing user-id - for list tests
	badSecret = corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "bogus",
		},
		Data: map[string][]byte{
			"enabled":          []byte("false"),
			"is-login":         []byte("true"),
			"ttl":              []byte("4000"),
			"hash":             []byte("kla9jkdmj"),
			"auth-provider":    []byte("somebody"),
			"last-update-time": []byte("13:00:05"),
			"display-name":     []byte("myself"),
			"login-name":       []byte("hello"),
			"principal-id":     []byte("world"),
			"kube-uid":         []byte("2905498-kafld-lkad"),
		},
	}
	// properToken is the token matching what is stored in the properSecret
	properToken = ext.Token{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Token",
			APIVersion: "ext.cattle.io/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "bogus",
			UID:  types.UID("2905498-kafld-lkad"),
		},
		Spec: ext.TokenSpec{
			UserID:      "lkajdlksjlkds",
			Description: "",
			ClusterName: "",
			TTL:         4000,
			Enabled:     false,
			IsLogin:     true,
		},
		Status: ext.TokenStatus{
			TokenValue:     "",
			TokenHash:      "kla9jkdmj",
			Expired:        true,
			ExpiresAt:      "0001-01-01T00:00:04Z",
			AuthProvider:   "somebody",
			LastUpdateTime: "13:00:05",
			DisplayName:    "myself",
			LoginName:      "hello",
			PrincipalID:    "world",
		},
	}

	dummyToken = ext.Token{
		ObjectMeta: metav1.ObjectMeta{
			Name: "bogus",
		},
	}

	// ttlPlusSecret is the properSecret with extended ttl
	ttlPlusSecret = corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "bogus",
		},
		Data: map[string][]byte{
			"enabled":          []byte("false"),
			"is-login":         []byte("true"),
			"ttl":              []byte("5000"),
			"user-id":          []byte("lkajdlksjlkds"),
			"hash":             []byte("kla9jkdmj"),
			"auth-provider":    []byte("somebody"),
			"last-update-time": []byte("this is a fake now"),
			"display-name":     []byte("myself"),
			"login-name":       []byte("hello"),
			"principal-id":     []byte("world"),
			"kube-uid":         []byte("2905498-kafld-lkad"),
		},
	}
	// ttlSubSecret is the properSecret with reduced ttl
	ttlSubSecret = corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: "bogus",
		},
		Data: map[string][]byte{
			"enabled":          []byte("false"),
			"is-login":         []byte("true"),
			"ttl":              []byte("3000"),
			"user-id":          []byte("lkajdlksjlkds"),
			"hash":             []byte("kla9jkdmj"),
			"auth-provider":    []byte("somebody"),
			"last-update-time": []byte("this is a fake now"),
			"display-name":     []byte("myself"),
			"login-name":       []byte("hello"),
			"principal-id":     []byte("world"),
			"kube-uid":         []byte("2905498-kafld-lkad"),
		},
	}

	someerror                = fmt.Errorf("bogus")
	authProviderMissingError = fmt.Errorf("auth provider missing")
	hashMissingError         = fmt.Errorf("token hash missing")
	kubeIDMissingError       = fmt.Errorf("kube uid missing")
	lastUpdateMissingError   = fmt.Errorf("last update time missing")
	principalIDMissingError  = fmt.Errorf("principal id missing")
	userIDMissingError       = fmt.Errorf("user id missing")
	invalidContext           = fmt.Errorf("context has no user info")

	bogusNotFoundError      = apierrors.NewNotFound(GVR.GroupResource(), "bogus")
	emptyNotFoundError      = apierrors.NewNotFound(GVR.GroupResource(), "")
	createUserMismatch      = apierrors.NewBadRequest("unable to create token for other user")
	helloAlreadyExistsError = apierrors.NewAlreadyExists(GVR.GroupResource(), "hello")

	parseBoolError error
	parseIntError  error
)

func init() {
	_, parseBoolError = strconv.ParseBool("")
	_, parseIntError = strconv.ParseInt("", 10, 64)
}

func Test_Store_Delete(t *testing.T) {
	// The majority of the code is tested later, in Test_SystemStore_Delete
	// Here we test the actions and checks done before delegation to the
	// embedded system store
	t.Run("failed to get secret, arbitrary error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		secrets := fake.NewMockControllerInterface[*corev1.Secret, *corev1.SecretList](ctrl)
		store := New(nil, secrets, nil, nil, nil, nil, nil)

		secrets.EXPECT().
			Get("cattle-tokens", "bogus", gomock.Any()).
			Return(nil, someerror)

		_, ok, err := store.Delete(context.TODO(), "bogus", nil, &metav1.DeleteOptions{})

		assert.False(t, ok)
		assert.Equal(t, apierrors.NewInternalError(fmt.Errorf("failed to retrieve token bogus: %w",
			someerror)), err)
	})

	t.Run("failed to get secret, not found", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		secrets := fake.NewMockControllerInterface[*corev1.Secret, *corev1.SecretList](ctrl)
		store := New(nil, secrets, nil, nil, nil, nil, nil)

		secrets.EXPECT().
			Get("cattle-tokens", "bogus", gomock.Any()).
			Return(nil, apierrors.NewNotFound(schema.GroupResource{}, ""))

		_, ok, err := store.Delete(context.TODO(), "bogus", nil, &metav1.DeleteOptions{})
		assert.False(t, ok)
		assert.Equal(t, apierrors.NewNotFound(schema.GroupResource{}, ""), err)
	})

	t.Run("user info missing from context", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		secrets := fake.NewMockControllerInterface[*corev1.Secret, *corev1.SecretList](ctrl)
		checker := NewMockuserHandler(ctrl)
		store := New(nil, secrets, nil, nil, nil, nil, checker)

		secrets.EXPECT().
			Get("cattle-tokens", "bogus", gomock.Any()).
			Return(&properSecret, nil)

		checker.EXPECT().UserName(gomock.Any()).Return("", invalidContext)

		_, ok, err := store.Delete(context.TODO(), "bogus", nil, &metav1.DeleteOptions{})

		assert.False(t, ok)
		assert.Equal(t, apierrors.NewInternalError(invalidContext), err)
	})

	t.Run("not owned, no permission, not found", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		secrets := fake.NewMockControllerInterface[*corev1.Secret, *corev1.SecretList](ctrl)
		checker := NewMockuserHandler(ctrl)
		store := New(nil, secrets, nil, nil, nil, nil, checker)

		secrets.EXPECT().
			Get("cattle-tokens", "bogus", gomock.Any()).
			Return(&properSecret, nil)

		checker.EXPECT().UserName(gomock.Any()).Return("lkajdl/ksjlkds", nil)

		_, ok, err := store.Delete(context.TODO(), "bogus", nil, &metav1.DeleteOptions{})

		assert.False(t, ok)
		assert.Equal(t, bogusNotFoundError, err)
	})

	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		secrets := fake.NewMockControllerInterface[*corev1.Secret, *corev1.SecretList](ctrl)
		checker := NewMockuserHandler(ctrl)
		store := New(nil, secrets, nil, nil, nil, nil, checker)

		secrets.EXPECT().
			Get("cattle-tokens", "bogus", gomock.Any()).
			Return(&properSecret, nil)

		secrets.EXPECT().
			Delete("cattle-tokens", "bogus", gomock.Any()).
			Return(nil)

		checker.EXPECT().UserName(gomock.Any()).Return("lkajdlksjlkds", nil).Times(2)

		_, ok, err := store.Delete(context.TODO(), "bogus", nil, &metav1.DeleteOptions{})

		assert.True(t, ok)
		assert.Nil(t, err)
	})
}

func Test_Store_Get(t *testing.T) {
	// The majority of the code is tested later, in Test_SystemStore_Get
	// Here we only test the permission checks done after delegation to the
	// embedded system store
	t.Run("not owned, no permission, not found", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		secrets := fake.NewMockControllerInterface[*corev1.Secret, *corev1.SecretList](ctrl)
		checker := NewMockuserHandler(ctrl)
		store := New(nil, secrets, nil, nil, nil, nil, checker)

		secrets.EXPECT().
			Get("cattle-tokens", "bogus", gomock.Any()).
			Return(&properSecret, nil)

		checker.EXPECT().UserName(gomock.Any()).Return("lkajdl/ksjlkds", nil)

		tok, err := store.Get(context.TODO(), "bogus", &metav1.GetOptions{})

		assert.Equal(t, bogusNotFoundError, err)
		assert.Nil(t, tok)
	})

	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		secrets := fake.NewMockControllerInterface[*corev1.Secret, *corev1.SecretList](ctrl)
		checker := NewMockuserHandler(ctrl)
		store := New(nil, secrets, nil, nil, nil, nil, checker)

		secrets.EXPECT().
			Get("cattle-tokens", "bogus", gomock.Any()).
			Return(&properSecret, nil)

		checker.EXPECT().UserName(gomock.Any()).Return("lkajdlksjlkds", nil)

		tok, err := store.Get(context.TODO(), "bogus", &metav1.GetOptions{})

		assert.Nil(t, err)
		assert.Equal(t, &properToken, tok)
	})
}

func Test_Store_Update(t *testing.T) {
	// The majority of the code is tested later, in Test_SystemStore_Update
	// Here we only test the permission checks done before delegation to the
	// embedded system store
	t.Run("not owned, no permission, not found", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		secrets := fake.NewMockControllerInterface[*corev1.Secret, *corev1.SecretList](ctrl)
		checker := NewMockuserHandler(ctrl)
		store := New(nil, secrets, nil, nil, nil, nil, checker)

		checker.EXPECT().UserName(gomock.Any()).Return("lkajdl/ksjlkds", nil)

		tok, err := store.update(context.TODO(), &ext.Token{
			ObjectMeta: metav1.ObjectMeta{
				Name: "bogus",
			},
		}, &metav1.UpdateOptions{})

		assert.Equal(t, bogusNotFoundError, err)
		assert.Nil(t, tok)
	})

	t.Run("owned", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		secrets := fake.NewMockControllerInterface[*corev1.Secret, *corev1.SecretList](ctrl)
		timer := NewMocktimeHandler(ctrl)
		checker := NewMockuserHandler(ctrl)
		store := New(nil, secrets, nil, nil, timer, nil, checker)

		checker.EXPECT().UserName(gomock.Any()).Return("lkajdlksjlkds", nil)

		secrets.EXPECT().
			Get("cattle-tokens", "bogus", gomock.Any()).
			Return(&properSecret, nil)

		changed := properSecret.DeepCopy()
		changed.Data["ttl"] = []byte("2000")
		changed.Data["last-update-time"] = []byte("this is a fake now")

		// Fake current time
		timer.EXPECT().Now().Return("this is a fake now")

		// Update: Return modified data
		secrets.EXPECT().
			Update(gomock.Any()).
			Return(changed, nil)

		modified := properToken.DeepCopy()
		modified.Spec.TTL = 2000

		tok, err := store.update(context.TODO(), modified, &metav1.UpdateOptions{})

		// set the expected status changes
		modified.Status.LastUpdateTime = "this is a fake now"
		modified.Status.ExpiresAt = "0001-01-01T00:00:02Z"

		assert.Nil(t, err)
		assert.Equal(t, modified, tok)
	})
}

func Test_Store_Watch(t *testing.T) {
	// This test suite is a bit special, as it is not table driven like all other suites coming
	// after it.  This is done because we need stronger control about the environment the
	// various store calls are in, i.e. the channels involved, the context, and the goroutine
	// internal to `Watch`.

	t.Run("backend watch creation error closes watch channel", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		secrets := fake.NewMockControllerInterface[*corev1.Secret, *corev1.SecretList](ctrl)
		checker := NewMockuserHandler(ctrl)
		store := New(nil, secrets, nil, nil, nil, nil, checker)

		secrets.EXPECT().Watch("cattle-tokens", gomock.Any()).
			Return(nil, someerror)

		checker.EXPECT().UserName(gomock.Any()).Return("lkajdlksjlkds", nil)

		consumer, err := store.watch(context.TODO(), &metav1.ListOptions{})
		assert.Nil(t, err)

		_, more := (<-consumer.ResultChan())
		assert.False(t, more)
	})

	t.Run("context cancellation closes watch channel", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		secrets := fake.NewMockControllerInterface[*corev1.Secret, *corev1.SecretList](ctrl)
		checker := NewMockuserHandler(ctrl)
		store := New(nil, secrets, nil, nil, nil, nil, checker)

		secrets.EXPECT().Watch("cattle-tokens", gomock.Any()).
			Return(NewWatcher(), nil)

		checker.EXPECT().UserName(gomock.Any()).Return("lkajdlksjlkds", nil)

		todo, cancel := context.WithCancel(context.TODO())

		consumer, err := store.watch(todo, &metav1.ListOptions{})
		assert.Nil(t, err)

		cancel()

		_, more := (<-consumer.ResultChan()) // no events received, and none pending
		assert.False(t, more)
	})

	t.Run("closing backend channel closes watch channel", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		secrets := fake.NewMockControllerInterface[*corev1.Secret, *corev1.SecretList](ctrl)
		checker := NewMockuserHandler(ctrl)
		store := New(nil, secrets, nil, nil, nil, nil, checker)

		watcher := NewWatcher()
		secrets.EXPECT().Watch("cattle-tokens", gomock.Any()).
			Return(watcher, nil)

		checker.EXPECT().UserName(gomock.Any()).Return("lkajdlksjlkds", nil)

		consumer, err := store.watch(context.TODO(), &metav1.ListOptions{})
		assert.Nil(t, err)

		watcher.Done() // close backend channel

		_, more := (<-consumer.ResultChan()) // no events received, and none pending
		assert.False(t, more)
	})

	t.Run("event for non-secret is ignored", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		secrets := fake.NewMockControllerInterface[*corev1.Secret, *corev1.SecretList](ctrl)
		checker := NewMockuserHandler(ctrl)
		store := New(nil, secrets, nil, nil, nil, nil, checker)

		watcher := NewWatcherFor(watch.Event{Object: &corev1.Namespace{}})
		secrets.EXPECT().Watch("cattle-tokens", gomock.Any()).
			Return(watcher, nil)

		checker.EXPECT().UserName(gomock.Any()).Return("lkajdlksjlkds", nil)

		consumer, err := store.watch(context.TODO(), &metav1.ListOptions{})
		assert.Nil(t, err)

		watcher.Done() // close backend channel - also closes consumer channel

		_, more := (<-consumer.ResultChan()) // no events received, and none pending
		assert.False(t, more)
	})

	t.Run("event for broken secret is ignored", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		secrets := fake.NewMockControllerInterface[*corev1.Secret, *corev1.SecretList](ctrl)
		checker := NewMockuserHandler(ctrl)
		store := New(nil, secrets, nil, nil, nil, nil, checker)

		watcher := NewWatcherFor(watch.Event{Object: &corev1.Secret{}})
		secrets.EXPECT().Watch("cattle-tokens", gomock.Any()).
			Return(watcher, nil)

		checker.EXPECT().UserName(gomock.Any()).Return("lkajdlksjlkds", nil)

		consumer, err := store.watch(context.TODO(), &metav1.ListOptions{})
		assert.Nil(t, err)

		watcher.Done() // close backend channel - also closes consumer channel

		_, more := (<-consumer.ResultChan()) // no events received, and none pending
		assert.False(t, more)
	})

	t.Run("event for non-owned secret is ignored", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		secrets := fake.NewMockControllerInterface[*corev1.Secret, *corev1.SecretList](ctrl)
		checker := NewMockuserHandler(ctrl)
		store := New(nil, secrets, nil, nil, nil, nil, checker)

		watcher := NewWatcherFor(watch.Event{Object: &properSecret})
		secrets.EXPECT().Watch("cattle-tokens", gomock.Any()).
			Return(watcher, nil)

		checker.EXPECT().UserName(gomock.Any()).Return("lkajdl/ksjlkds", nil)

		consumer, err := store.watch(context.TODO(), &metav1.ListOptions{})
		assert.Nil(t, err)

		watcher.Done() // close backend channel - also closes consumer channel

		_, more := (<-consumer.ResultChan()) // no events received, and none pending
		assert.False(t, more)
	})

	t.Run("receive event for owned secret", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		secrets := fake.NewMockControllerInterface[*corev1.Secret, *corev1.SecretList](ctrl)
		checker := NewMockuserHandler(ctrl)
		store := New(nil, secrets, nil, nil, nil, nil, checker)

		watcher := NewWatcherFor(watch.Event{Object: &properSecret, Type: "update"})
		secrets.EXPECT().Watch("cattle-tokens", gomock.Any()).
			Return(watcher, nil)

		checker.EXPECT().UserName(gomock.Any()).Return("lkajdlksjlkds", nil)

		consumer, err := store.watch(context.TODO(), &metav1.ListOptions{})
		assert.Nil(t, err)

		event, more := (<-consumer.ResultChan()) // receive update event
		assert.True(t, more)
		assert.Equal(t, watch.EventType("update"), event.Type)
		assert.Equal(t, &properToken, event.Object)

		watcher.Done() // close backend channel - also closes consumer channel

		_, more = (<-consumer.ResultChan()) // no events received, and none pending
		assert.False(t, more)
	})
}

func Test_Store_Create(t *testing.T) {
	tests := []struct {
		name       string                // test name
		err        error                 // expected op result, error
		tok        *ext.Token            // token input
		rtok       *ext.Token            // expected op result, created token
		opts       *metav1.CreateOptions // create options
		storeSetup func(                 // configure store backend clients
			space *fake.MockNonNamespacedControllerInterface[*corev1.Namespace, *corev1.NamespaceList],
			secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
			uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
			users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList],
			timer *MocktimeHandler,
			hasher *MockhashHandler,
			checker *MockuserHandler)
	}{
		{
			name: "permission error", // forbidden, or failed in the check
			err:  apierrors.NewBadRequest("unable to create token for other user"),
			tok:  &ext.Token{},
			opts: &metav1.CreateOptions{},
			storeSetup: func( // configure store backend clients
				space *fake.MockNonNamespacedControllerInterface[*corev1.Namespace, *corev1.NamespaceList],
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList],
				timer *MocktimeHandler,
				hasher *MockhashHandler,
				checker *MockuserHandler) {

				checker.EXPECT().UserName(gomock.Any()).Return("lkajdl/ksjlkds", nil)
			},
		},
		{
			name: "user name mismatch",
			err:  createUserMismatch,
			tok:  &ext.Token{},
			opts: &metav1.CreateOptions{},
			storeSetup: func( // configure store backend clients
				space *fake.MockNonNamespacedControllerInterface[*corev1.Namespace, *corev1.NamespaceList],
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList],
				timer *MocktimeHandler,
				hasher *MockhashHandler,
				checker *MockuserHandler) {

				checker.EXPECT().UserName(gomock.Any()).Return("lkajdlksjlkds", nil)
			},
		},
		{
			name: "namespace creation error",
			err:  someerror,
			tok:  &ext.Token{},
			opts: &metav1.CreateOptions{},
			storeSetup: func( // configure store backend clients
				space *fake.MockNonNamespacedControllerInterface[*corev1.Namespace, *corev1.NamespaceList],
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList],
				timer *MocktimeHandler,
				hasher *MockhashHandler,
				checker *MockuserHandler) {

				checker.EXPECT().UserName(gomock.Any()).Return("", nil)

				space.EXPECT().Create(gomock.Any()).
					Return(nil, someerror)
			},
		},
		{
			name: "reject already existing token",
			err:  helloAlreadyExistsError,
			tok: &ext.Token{
				ObjectMeta: metav1.ObjectMeta{
					Name: "hello",
				},
			},
			opts: &metav1.CreateOptions{},
			storeSetup: func( // configure store backend clients
				space *fake.MockNonNamespacedControllerInterface[*corev1.Namespace, *corev1.NamespaceList],
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList],
				timer *MocktimeHandler,
				hasher *MockhashHandler,
				checker *MockuserHandler) {

				checker.EXPECT().UserName(gomock.Any()).Return("", nil)

				space.EXPECT().Create(gomock.Any()).
					Return(nil, nil)

				secrets.EXPECT().Get("cattle-tokens", "hello", gomock.Any()).
					Return(&corev1.Secret{}, nil)
			},
		},
		{
			name: "reject a specified token value",
			err:  apierrors.NewBadRequest("User provided token value is not permitted"),
			tok: &ext.Token{
				ObjectMeta: metav1.ObjectMeta{
					Name: "hello",
				},
				Status: ext.TokenStatus{
					TokenValue: "kfakdslfk",
				},
			},
			opts: &metav1.CreateOptions{},
			storeSetup: func( // configure store backend clients
				space *fake.MockNonNamespacedControllerInterface[*corev1.Namespace, *corev1.NamespaceList],
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList],
				timer *MocktimeHandler,
				hasher *MockhashHandler,
				checker *MockuserHandler) {

				checker.EXPECT().UserName(gomock.Any()).Return("", nil)

				space.EXPECT().Create(gomock.Any()).
					Return(nil, nil)

				secrets.EXPECT().Get("cattle-tokens", "hello", gomock.Any()).
					Return(nil, someerror)
			},
		},
		{
			name: "reject a specified token hash",
			err:  apierrors.NewBadRequest("User provided token hash is not permitted"),
			tok: &ext.Token{
				ObjectMeta: metav1.ObjectMeta{
					Name: "hello",
				},
				Status: ext.TokenStatus{
					TokenHash: "kfakdslfk",
				},
			},
			opts: &metav1.CreateOptions{},
			storeSetup: func( // configure store backend clients
				space *fake.MockNonNamespacedControllerInterface[*corev1.Namespace, *corev1.NamespaceList],
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList],
				timer *MocktimeHandler,
				hasher *MockhashHandler,
				checker *MockuserHandler) {

				checker.EXPECT().UserName(gomock.Any()).Return("", nil)

				space.EXPECT().Create(gomock.Any()).
					Return(nil, nil)

				secrets.EXPECT().Get("cattle-tokens", "hello", gomock.Any()).
					Return(nil, someerror)
			},
		},
		// token generation and hash errors -- no mocking -- unable to induce and test
		{
			name: "user attribute retrieval error",
			err:  apierrors.NewInternalError(fmt.Errorf("failed to retrieve user attributes of world: %w", someerror)),
			tok: &ext.Token{
				ObjectMeta: metav1.ObjectMeta{
					Name: "hello",
				},
				Spec: ext.TokenSpec{
					UserID: "world",
				},
			},
			opts: &metav1.CreateOptions{},
			storeSetup: func( // configure store backend clients
				space *fake.MockNonNamespacedControllerInterface[*corev1.Namespace, *corev1.NamespaceList],
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList],
				timer *MocktimeHandler,
				hasher *MockhashHandler,
				checker *MockuserHandler) {

				checker.EXPECT().UserName(gomock.Any()).Return("world", nil)

				space.EXPECT().Create(gomock.Any()).
					Return(nil, nil)

				secrets.EXPECT().Get("cattle-tokens", "hello", gomock.Any()).
					Return(nil, someerror)

				uattrs.EXPECT().Get("world", gomock.Any()).
					Return(nil, someerror)
			},
		},
		{
			name: "user attribute retrieval nil result",
			err:  apierrors.NewInternalError(fmt.Errorf("failed to get user attributes of world")),
			tok: &ext.Token{
				ObjectMeta: metav1.ObjectMeta{
					Name: "hello",
				},
				Spec: ext.TokenSpec{
					UserID: "world",
				},
			},
			opts: &metav1.CreateOptions{},
			storeSetup: func( // configure store backend clients
				space *fake.MockNonNamespacedControllerInterface[*corev1.Namespace, *corev1.NamespaceList],
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList],
				timer *MocktimeHandler,
				hasher *MockhashHandler,
				checker *MockuserHandler) {

				checker.EXPECT().UserName(gomock.Any()).Return("world", nil)

				space.EXPECT().Create(gomock.Any()).
					Return(nil, nil)

				secrets.EXPECT().Get("cattle-tokens", "hello", gomock.Any()).
					Return(nil, someerror)

				uattrs.EXPECT().Get("world", gomock.Any()).
					Return(nil, nil)
			},
		},
		{
			name: "user attribute without provider",
			err:  apierrors.NewInternalError(fmt.Errorf("bad user attributes: bogus ExtraByProvider, empty or ambigous")),
			tok: &ext.Token{
				ObjectMeta: metav1.ObjectMeta{
					Name: "hello",
				},
				Spec: ext.TokenSpec{
					UserID: "world",
				},
			},
			opts: &metav1.CreateOptions{},
			storeSetup: func( // configure store backend clients
				space *fake.MockNonNamespacedControllerInterface[*corev1.Namespace, *corev1.NamespaceList],
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList],
				timer *MocktimeHandler,
				hasher *MockhashHandler,
				checker *MockuserHandler) {

				checker.EXPECT().UserName(gomock.Any()).Return("world", nil)

				space.EXPECT().Create(gomock.Any()).
					Return(nil, nil)

				secrets.EXPECT().Get("cattle-tokens", "hello", gomock.Any()).
					Return(nil, someerror)

				uattrs.EXPECT().Get("world", gomock.Any()).
					Return(&v3.UserAttribute{}, nil)
			},
		},
		{
			name: "user attribute with ambigous providers",
			err:  apierrors.NewInternalError(fmt.Errorf("bad user attributes: bogus ExtraByProvider, empty or ambigous")),
			tok: &ext.Token{
				ObjectMeta: metav1.ObjectMeta{
					Name: "hello",
				},
				Spec: ext.TokenSpec{
					UserID: "world",
				},
			},
			opts: &metav1.CreateOptions{},
			storeSetup: func( // configure store backend clients
				space *fake.MockNonNamespacedControllerInterface[*corev1.Namespace, *corev1.NamespaceList],
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList],
				timer *MocktimeHandler,
				hasher *MockhashHandler,
				checker *MockuserHandler) {

				checker.EXPECT().UserName(gomock.Any()).Return("world", nil)

				space.EXPECT().Create(gomock.Any()).
					Return(nil, nil)

				secrets.EXPECT().Get("cattle-tokens", "hello", gomock.Any()).
					Return(nil, someerror)

				uattrs.EXPECT().Get("world", gomock.Any()).
					Return(&v3.UserAttribute{
						ExtraByProvider: map[string]map[string][]string{
							"local":      map[string][]string{},
							"some-other": map[string][]string{},
						},
					}, nil)
			},
		},
		{
			name: "user retrieval error",
			err:  apierrors.NewInternalError(fmt.Errorf("failed to retrieve user world: %w", someerror)),
			tok: &ext.Token{
				ObjectMeta: metav1.ObjectMeta{
					Name: "hello",
				},
				Spec: ext.TokenSpec{
					UserID: "world",
				},
			},
			opts: &metav1.CreateOptions{},
			storeSetup: func( // configure store backend clients
				space *fake.MockNonNamespacedControllerInterface[*corev1.Namespace, *corev1.NamespaceList],
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList],
				timer *MocktimeHandler,
				hasher *MockhashHandler,
				checker *MockuserHandler) {

				checker.EXPECT().UserName(gomock.Any()).Return("world", nil)

				space.EXPECT().Create(gomock.Any()).
					Return(nil, nil)

				secrets.EXPECT().Get("cattle-tokens", "hello", gomock.Any()).
					Return(nil, someerror)

				uattrs.EXPECT().Get("world", gomock.Any()).
					Return(&v3.UserAttribute{
						ExtraByProvider: map[string]map[string][]string{
							"local": map[string][]string{},
						},
					}, nil)

				users.EXPECT().Get("world", gomock.Any()).
					Return(nil, someerror)
			},
		},
		{
			name: "user retrieval nil result",
			err:  apierrors.NewInternalError(fmt.Errorf("failed to get user world")),
			tok: &ext.Token{
				ObjectMeta: metav1.ObjectMeta{
					Name: "hello",
				},
				Spec: ext.TokenSpec{
					UserID: "world",
				},
			},
			opts: &metav1.CreateOptions{},
			storeSetup: func( // configure store backend clients
				space *fake.MockNonNamespacedControllerInterface[*corev1.Namespace, *corev1.NamespaceList],
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList],
				timer *MocktimeHandler,
				hasher *MockhashHandler,
				checker *MockuserHandler) {

				checker.EXPECT().UserName(gomock.Any()).Return("world", nil)

				space.EXPECT().Create(gomock.Any()).
					Return(nil, nil)

				secrets.EXPECT().Get("cattle-tokens", "hello", gomock.Any()).
					Return(nil, someerror)

				uattrs.EXPECT().Get("world", gomock.Any()).
					Return(&v3.UserAttribute{
						ExtraByProvider: map[string]map[string][]string{
							"local": map[string][]string{},
						},
					}, nil)

				users.EXPECT().Get("world", gomock.Any()).
					Return(nil, nil)
			},
		},
		{
			name: "generation or hash error",
			err:  someerror,
			tok: &ext.Token{
				ObjectMeta: metav1.ObjectMeta{
					Name: "hello",
				},
				Spec: ext.TokenSpec{
					UserID: "world",
				},
			},
			opts: &metav1.CreateOptions{},
			storeSetup: func( // configure store backend clients
				space *fake.MockNonNamespacedControllerInterface[*corev1.Namespace, *corev1.NamespaceList],
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList],
				timer *MocktimeHandler,
				hasher *MockhashHandler,
				checker *MockuserHandler) {

				checker.EXPECT().UserName(gomock.Any()).Return("world", nil)

				space.EXPECT().Create(gomock.Any()).
					Return(nil, nil)

				secrets.EXPECT().Get("cattle-tokens", "hello", gomock.Any()).
					Return(nil, someerror)

				uattrs.EXPECT().Get("world", gomock.Any()).
					Return(&v3.UserAttribute{
						ExtraByProvider: map[string]map[string][]string{
							"local": map[string][]string{},
						},
					}, nil)

				users.EXPECT().Get("world", gomock.Any()).
					Return(&v3.User{}, nil)

				hasher.EXPECT().MakeAndHashSecret().
					Return("", "", someerror)
			},
		},
		{
			name: "failed to create secret - some error",
			err:  apierrors.NewInternalError(fmt.Errorf("failed to store token hello: %w", someerror)),
			tok: &ext.Token{
				ObjectMeta: metav1.ObjectMeta{
					Name: "hello",
				},
				Spec: ext.TokenSpec{
					UserID: "world",
				},
			},
			opts: &metav1.CreateOptions{},
			storeSetup: func( // configure store backend clients
				space *fake.MockNonNamespacedControllerInterface[*corev1.Namespace, *corev1.NamespaceList],
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList],
				timer *MocktimeHandler,
				hasher *MockhashHandler,
				checker *MockuserHandler) {

				checker.EXPECT().UserName(gomock.Any()).Return("world", nil)

				space.EXPECT().Create(gomock.Any()).
					Return(nil, nil)

				secrets.EXPECT().Get("cattle-tokens", "hello", gomock.Any()).
					Return(nil, someerror)

				uattrs.EXPECT().Get("world", gomock.Any()).
					Return(&v3.UserAttribute{
						ExtraByProvider: map[string]map[string][]string{
							"local": map[string][]string{
								"principalid": []string{
									"local://world",
								},
							},
						},
					}, nil)

				users.EXPECT().Get("world", gomock.Any()).
					Return(&v3.User{
						DisplayName: "worldwide",
						Username:    "wide",
					}, nil)

				// Fake value and hash
				hasher.EXPECT().MakeAndHashSecret().Return("", "", nil)

				// Fake current time
				timer.EXPECT().Now().Return("this is a fake now")

				secrets.EXPECT().Create(gomock.Any()).
					Return(nil, someerror)
			},
		},
		{
			name: "failed to create secret - already exists",
			err:  helloAlreadyExistsError,
			tok: &ext.Token{
				ObjectMeta: metav1.ObjectMeta{
					Name: "hello",
				},
				Spec: ext.TokenSpec{
					UserID: "world",
				},
			},
			opts: &metav1.CreateOptions{},
			storeSetup: func( // configure store backend clients
				space *fake.MockNonNamespacedControllerInterface[*corev1.Namespace, *corev1.NamespaceList],
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList],
				timer *MocktimeHandler,
				hasher *MockhashHandler,
				checker *MockuserHandler) {

				checker.EXPECT().UserName(gomock.Any()).Return("world", nil)

				space.EXPECT().Create(gomock.Any()).
					Return(nil, nil)

				secrets.EXPECT().Get("cattle-tokens", "hello", gomock.Any()).
					Return(nil, someerror)

				uattrs.EXPECT().Get("world", gomock.Any()).
					Return(&v3.UserAttribute{
						ExtraByProvider: map[string]map[string][]string{
							"local": map[string][]string{
								"principalid": []string{
									"local://world",
								},
							},
						},
					}, nil)

				users.EXPECT().Get("world", gomock.Any()).
					Return(&v3.User{
						DisplayName: "worldwide",
						Username:    "wide",
					}, nil)

				// Fake value and hash
				hasher.EXPECT().MakeAndHashSecret().Return("", "", nil)

				// Fake current time
				timer.EXPECT().Now().Return("this is a fake now")

				secrets.EXPECT().Create(gomock.Any()).
					Return(nil, helloAlreadyExistsError)
			},
		},
		{
			name: "created secret reads back as bogus",
			err:  apierrors.NewInternalError(fmt.Errorf("failed to regenerate token hello: %w", userIDMissingError)),
			tok: &ext.Token{
				ObjectMeta: metav1.ObjectMeta{
					Name: "hello",
				},
				Spec: ext.TokenSpec{
					UserID: "world",
				},
			},
			opts: &metav1.CreateOptions{},
			storeSetup: func( // configure store backend clients
				space *fake.MockNonNamespacedControllerInterface[*corev1.Namespace, *corev1.NamespaceList],
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList],
				timer *MocktimeHandler,
				hasher *MockhashHandler,
				checker *MockuserHandler) {

				checker.EXPECT().UserName(gomock.Any()).Return("world", nil)

				space.EXPECT().Create(gomock.Any()).
					Return(nil, nil)

				secrets.EXPECT().Get("cattle-tokens", "hello", gomock.Any()).
					Return(nil, someerror)

				uattrs.EXPECT().Get("world", gomock.Any()).
					Return(&v3.UserAttribute{
						ExtraByProvider: map[string]map[string][]string{
							"local": map[string][]string{
								"principalid": []string{
									"local://world",
								},
							},
						},
					}, nil)

				users.EXPECT().Get("world", gomock.Any()).
					Return(&v3.User{
						DisplayName: "worldwide",
						Username:    "wide",
					}, nil)

				// Fake value and hash
				hasher.EXPECT().MakeAndHashSecret().Return("", "", nil)

				// Fake current time
				timer.EXPECT().Now().Return("this is a fake now")

				// note: returning an arbitrary bad secret here.
				// no connection to the token spec which went into create
				secrets.EXPECT().Create(gomock.Any()).
					Return(&badSecret, nil)
			},
		},
		{
			name: "created secret ok",
			err:  nil,
			tok: &ext.Token{
				ObjectMeta: metav1.ObjectMeta{
					Name: "hello",
				},
				Spec: ext.TokenSpec{
					UserID: "world",
				},
			},
			opts: &metav1.CreateOptions{},
			storeSetup: func( // configure store backend clients
				space *fake.MockNonNamespacedControllerInterface[*corev1.Namespace, *corev1.NamespaceList],
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				uattrs *fake.MockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList],
				users *fake.MockNonNamespacedControllerInterface[*v3.User, *v3.UserList],
				timer *MocktimeHandler,
				hasher *MockhashHandler,
				checker *MockuserHandler) {

				checker.EXPECT().UserName(gomock.Any()).Return("world", nil)

				space.EXPECT().Create(gomock.Any()).
					Return(nil, nil)

				secrets.EXPECT().Get("cattle-tokens", "hello", gomock.Any()).
					Return(nil, someerror)

				uattrs.EXPECT().Get("world", gomock.Any()).
					Return(&v3.UserAttribute{
						ExtraByProvider: map[string]map[string][]string{
							"local": map[string][]string{
								"principalid": []string{
									"local://world",
								},
							},
						},
					}, nil)

				users.EXPECT().Get("world", gomock.Any()).
					Return(&v3.User{
						DisplayName: "worldwide",
						Username:    "wide",
					}, nil)

				// Fake value and hash -- See rtok below
				hasher.EXPECT().MakeAndHashSecret().Return("94084kdlafj43", "", nil)

				// Fake current time
				timer.EXPECT().Now().Return("this is a fake now")

				// note: returning an arbitrary good secret here.
				// no connection to the token spec which went into create
				secrets.EXPECT().Create(gomock.Any()).
					Return(&properSecret, nil)
			},
			rtok: func() *ext.Token {
				copy := properToken.DeepCopy()
				copy.Status.TokenHash = ""
				copy.Status.TokenValue = "94084kdlafj43"
				return copy
			}(),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)

			// assemble and configure a store from mock clients ...
			space := fake.NewMockNonNamespacedControllerInterface[*corev1.Namespace, *corev1.NamespaceList](ctrl)
			secrets := fake.NewMockControllerInterface[*corev1.Secret, *corev1.SecretList](ctrl)
			uattrs := fake.NewMockNonNamespacedControllerInterface[*v3.UserAttribute, *v3.UserAttributeList](ctrl)
			users := fake.NewMockNonNamespacedControllerInterface[*v3.User, *v3.UserList](ctrl)
			timer := NewMocktimeHandler(ctrl)
			hasher := NewMockhashHandler(ctrl)
			checker := NewMockuserHandler(ctrl)
			store := New(space, secrets, uattrs, users, timer, hasher, checker)
			test.storeSetup(space, secrets, uattrs, users, timer, hasher, checker)

			// perform test and validate results
			tok, err := store.create(context.TODO(), test.tok, test.opts)
			if test.err != nil {
				assert.Equal(t, test.err, err)
				assert.Nil(t, tok)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.rtok, tok)
			}
		})
	}
}

func Test_SystemStore_List(t *testing.T) {
	tests := []struct {
		name       string              // test name
		user       string              // user making request
		opts       *metav1.ListOptions // list options
		err        error               // expected op result, error
		toks       *ext.TokenList      // expected op result, token list
		storeSetup func(               // configure store backend clients
			secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList])
	}{
		{
			name: "some arbitrary error",
			user: "",
			opts: &metav1.ListOptions{},
			err:  apierrors.NewInternalError(fmt.Errorf("failed to list tokens: %w", someerror)),
			toks: nil,
			storeSetup: func(secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList]) {
				secrets.EXPECT().
					List("cattle-tokens", gomock.Any()).
					Return(nil, someerror)
			},
		},
		{
			name: "ok, empty",
			user: "",
			opts: &metav1.ListOptions{},
			err:  nil,
			toks: &ext.TokenList{},
			storeSetup: func(secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList]) {
				secrets.EXPECT().
					List("cattle-tokens", gomock.Any()).
					Return(&corev1.SecretList{}, nil)
			},
		},
		{
			name: "ok, not empty",
			user: "lkajdlksjlkds",
			opts: &metav1.ListOptions{},
			err:  nil,
			toks: &ext.TokenList{
				Items: []ext.Token{
					properToken,
				},
			},
			storeSetup: func(secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList]) {
				secrets.EXPECT().
					List("cattle-tokens", gomock.Any()).
					Return(&corev1.SecretList{
						Items: []corev1.Secret{
							properSecret,
						},
					}, nil)
			},
		},
		{
			name: "ok, ignore broken secrets",
			user: "lkajdlksjlkds",
			opts: &metav1.ListOptions{},
			err:  nil,
			toks: &ext.TokenList{
				Items: []ext.Token{
					properToken,
				},
			},
			storeSetup: func(secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList]) {
				secrets.EXPECT().
					List("cattle-tokens", gomock.Any()).
					Return(&corev1.SecretList{
						Items: []corev1.Secret{
							properSecret,
							badSecret,
						},
					}, nil)
			},
		},
		{
			name: "ok, ignore non-owned results",
			user: "other",
			opts: &metav1.ListOptions{},
			err:  nil,
			toks: &ext.TokenList{},
			storeSetup: func(secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList]) {
				secrets.EXPECT().
					List("cattle-tokens", gomock.Any()).
					Return(&corev1.SecretList{
						Items: []corev1.Secret{
							properSecret,
						},
					}, nil)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)

			// assemble and configure store from mock clients ...
			secrets := fake.NewMockControllerInterface[*corev1.Secret, *corev1.SecretList](ctrl)
			store := NewSystem(nil, secrets, nil, nil, nil, nil, nil)
			test.storeSetup(secrets)

			// perform test and validate results
			toks, err := store.list(false, test.user, test.opts)
			if test.err != nil {
				assert.Equal(t, test.err, err)
				assert.Nil(t, toks)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.toks, toks)
			}
		})
	}
}

func Test_SystemStore_Delete(t *testing.T) {
	tests := []struct {
		name       string                // test name
		token      string                // name of token to delete
		opts       *metav1.DeleteOptions // delete options
		err        error                 // expected op result, error
		storeSetup func(                 // configure store backend clients
			secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList])
	}{
		{
			name:  "secret not found is ok",
			token: "bogus",
			opts:  &metav1.DeleteOptions{},
			err:   nil,
			storeSetup: func(secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList]) {
				secrets.EXPECT().
					Delete("cattle-tokens", "bogus", gomock.Any()).
					Return(emptyNotFoundError)

			},
		},
		{
			name:  "secret other error is fail",
			token: "bogus",
			opts:  &metav1.DeleteOptions{},
			err:   apierrors.NewInternalError(fmt.Errorf("failed to delete token bogus: %w", someerror)),
			storeSetup: func(secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList]) {
				secrets.EXPECT().
					Delete("cattle-tokens", "bogus", gomock.Any()).
					Return(someerror)
			},
		},
		{
			name:  "secret deleted is ok",
			token: "bogus",
			opts:  &metav1.DeleteOptions{},
			err:   nil,
			storeSetup: func(secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList]) {
				secrets.EXPECT().
					Delete("cattle-tokens", "bogus", gomock.Any()).
					Return(nil)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)

			// assemble and configure store from mock clients ...
			secrets := fake.NewMockControllerInterface[*corev1.Secret, *corev1.SecretList](ctrl)
			store := NewSystem(nil, secrets, nil, nil, nil, nil, nil)
			test.storeSetup(secrets)

			// perform test and validate results
			err := store.Delete(test.token, test.opts)
			if test.err != nil {
				assert.Equal(t, test.err, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func Test_SystemStore_UpdateLastUsedAt(t *testing.T) {
	t.Run("patch last-used-at, ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		// assemble and configure store from mock clients ...
		secrets := fake.NewMockControllerInterface[*corev1.Secret, *corev1.SecretList](ctrl)
		store := NewSystem(nil, secrets, nil, nil, nil, nil, nil)

		var patchData []byte
		secrets.EXPECT().Patch("cattle-tokens", "atoken", types.JSONPatchType, gomock.Any()).
			DoAndReturn(func(space, name string, pt types.PatchType, data []byte, subresources ...any) (*ext.Token, error) {
				patchData = data
				return nil, nil
			}).Times(1)

		now, nerr := time.Parse(time.RFC3339, "2024-12-06T03:02:01Z")
		assert.NoError(t, nerr)

		err := store.UpdateLastUsedAt("atoken", now)
		assert.NoError(t, err)
		require.NotEmpty(t, patchData)
		require.Equal(t,
			`[{"op":"replace","path":"/data/last-used-at","value":"MjAyNC0xMi0wNlQwMzowMjowMVo="}]`,
			string(patchData))
	})

	t.Run("patch last-used-at, error", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		// assemble and configure store from mock clients ...
		secrets := fake.NewMockControllerInterface[*corev1.Secret, *corev1.SecretList](ctrl)
		store := NewSystem(nil, secrets, nil, nil, nil, nil, nil)

		secrets.EXPECT().Patch("cattle-tokens", "atoken", types.JSONPatchType, gomock.Any()).
			Return(nil, fmt.Errorf("some error")).
			Times(1)

		now, _ := time.Parse(time.RFC3339, "2024-12-06T03:00:00")
		err := store.UpdateLastUsedAt("atoken", now)
		assert.Equal(t, fmt.Errorf("some error"), err)
	})
}

func Test_SystemStore_Update(t *testing.T) {
	tests := []struct {
		name       string                // test name
		fullPerm   bool                  // permission level: full or not
		token      *ext.Token            // token to update, with changed fields
		opts       *metav1.UpdateOptions // update options
		rtok       *ext.Token            // expected op result, token
		err        error                 // expected op result, error
		storeSetup func(                 // configure store backend clients
			secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
			timer *MocktimeHandler,
			hasher *MockhashHandler,
			checker *MockuserHandler)
	}{
		// The first set of tests is equivalent to Get, as that (has to) happen internally
		// before Update can check for (allowed) differences and performing actual storage.
		{
			name:     "backing secret not found",
			fullPerm: true,
			opts:     &metav1.UpdateOptions{},
			token:    &dummyToken,
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				timer *MocktimeHandler,
				hasher *MockhashHandler,
				checker *MockuserHandler) {
				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(nil, emptyNotFoundError)
			},
			err: emptyNotFoundError,
		},
		{
			name:     "some other error",
			fullPerm: true,
			opts:     &metav1.UpdateOptions{},
			token:    &dummyToken,
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				timer *MocktimeHandler,
				hasher *MockhashHandler,
				checker *MockuserHandler) {
				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(nil, someerror)
			},
			err: apierrors.NewInternalError(fmt.Errorf("failed to retrieve token %s: %w", "bogus", someerror)),
		},
		{
			name:     "empty secret (no user id)",
			fullPerm: true,
			opts:     &metav1.UpdateOptions{},
			token:    &dummyToken,
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				timer *MocktimeHandler,
				hasher *MockhashHandler,
				checker *MockuserHandler) {
				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(&corev1.Secret{}, nil)
			},
			err: apierrors.NewInternalError(fmt.Errorf("failed to extract token %s: %w", "bogus", userIDMissingError)),
		},
		{
			name:     "part-filled secret (no enabled)",
			fullPerm: true,
			opts:     &metav1.UpdateOptions{},
			token:    &dummyToken,
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				timer *MocktimeHandler,
				hasher *MockhashHandler,
				checker *MockuserHandler) {

				reduced := properSecret.DeepCopy()
				delete(reduced.Data, "enabled")

				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(reduced, nil)
			},
			err: apierrors.NewInternalError(fmt.Errorf("failed to extract token %s: %w", "bogus", parseBoolError)),
		},
		{
			name:     "part-filled secret (no is-login)",
			fullPerm: true,
			opts:     &metav1.UpdateOptions{},
			token:    &dummyToken,
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				timer *MocktimeHandler,
				hasher *MockhashHandler,
				checker *MockuserHandler) {

				reduced := properSecret.DeepCopy()
				delete(reduced.Data, "is-login")

				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(reduced, nil)
			},
			err: apierrors.NewInternalError(fmt.Errorf("failed to extract token %s: %w", "bogus", parseBoolError)),
		},
		{
			name:     "part-filled secret (no ttl)",
			fullPerm: true,
			opts:     &metav1.UpdateOptions{},
			token:    &dummyToken,
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				timer *MocktimeHandler,
				hasher *MockhashHandler,
				checker *MockuserHandler) {

				reduced := properSecret.DeepCopy()
				delete(reduced.Data, "ttl")

				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(reduced, nil)
			},
			err: apierrors.NewInternalError(fmt.Errorf("failed to extract token %s: %w", "bogus", parseIntError)),
		},
		{
			name:     "part-filled secret (no hash)",
			fullPerm: true,
			opts:     &metav1.UpdateOptions{},
			token:    &dummyToken,
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				timer *MocktimeHandler,
				hasher *MockhashHandler,
				checker *MockuserHandler) {

				reduced := properSecret.DeepCopy()
				delete(reduced.Data, "hash")

				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(reduced, nil)
			},
			err: apierrors.NewInternalError(fmt.Errorf("failed to extract token %s: %w", "bogus", hashMissingError)),
		},
		{
			name:     "part-filled secret (no auth provider)",
			fullPerm: true,
			opts:     &metav1.UpdateOptions{},
			token:    &dummyToken,
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				timer *MocktimeHandler,
				hasher *MockhashHandler,
				checker *MockuserHandler) {

				reduced := properSecret.DeepCopy()
				delete(reduced.Data, "auth-provider")

				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(reduced, nil)
			},
			err: apierrors.NewInternalError(fmt.Errorf("failed to extract token %s: %w", "bogus", authProviderMissingError)),
		},
		{
			name:     "part-filled secret (no last update)",
			fullPerm: true,
			opts:     &metav1.UpdateOptions{},
			token:    &dummyToken,
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				timer *MocktimeHandler,
				hasher *MockhashHandler,
				checker *MockuserHandler) {

				reduced := properSecret.DeepCopy()
				delete(reduced.Data, "last-update-time")

				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(reduced, nil)
			},
			err: apierrors.NewInternalError(fmt.Errorf("failed to extract token %s: %w", "bogus", lastUpdateMissingError)),
		},
		{
			name:     "part-filled secret (no principal id)",
			fullPerm: true,
			opts:     &metav1.UpdateOptions{},
			token:    &dummyToken,
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				timer *MocktimeHandler,
				hasher *MockhashHandler,
				checker *MockuserHandler) {

				reduced := properSecret.DeepCopy()
				delete(reduced.Data, "principal-id")

				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(reduced, nil)
			},
			err: apierrors.NewInternalError(fmt.Errorf("failed to extract token %s: %w", "bogus", principalIDMissingError)),
		},
		{
			name:     "part-filled secret (no kube id)",
			fullPerm: true,
			opts:     &metav1.UpdateOptions{},
			token:    &dummyToken,
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				timer *MocktimeHandler,
				hasher *MockhashHandler,
				checker *MockuserHandler) {

				reduced := properSecret.DeepCopy()
				delete(reduced.Data, "kube-uid")

				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(reduced, nil)
			},
			err: apierrors.NewInternalError(fmt.Errorf("failed to extract token %s: %w", "bogus", kubeIDMissingError)),
		},
		// Second set of tests, compare inbound token against stored token, and reject forbidden changes
		{
			name:     "reject user id change",
			fullPerm: true,
			opts:     &metav1.UpdateOptions{},
			token: func() *ext.Token {
				changed := properToken.DeepCopy()
				changed.Spec.UserID = "dummy"
				return changed
			}(),
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				timer *MocktimeHandler,
				hasher *MockhashHandler,
				checker *MockuserHandler) {
				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(&properSecret, nil)
			},
			err: apierrors.NewBadRequest("rejecting change of token bogus: forbidden to edit user id"),
		},
		{
			name:     "reject cluster name change",
			fullPerm: true,
			opts:     &metav1.UpdateOptions{},
			token: func() *ext.Token {
				changed := properToken.DeepCopy()
				changed.Spec.ClusterName = "a-cluster"
				return changed
			}(),
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				timer *MocktimeHandler,
				hasher *MockhashHandler,
				checker *MockuserHandler) {
				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(&properSecret, nil)
			},
			err: apierrors.NewBadRequest("rejecting change of token bogus: forbidden to edit cluster name"),
		},
		{
			name:     "reject login flag change",
			fullPerm: true,
			opts:     &metav1.UpdateOptions{},
			token: func() *ext.Token {
				changed := properToken.DeepCopy()
				changed.Spec.IsLogin = false
				return changed
			}(),
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				timer *MocktimeHandler,
				hasher *MockhashHandler,
				checker *MockuserHandler) {
				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(&properSecret, nil)
			},
			err: apierrors.NewBadRequest("rejecting change of token bogus: forbidden to edit flag isLogin"),
		},
		// Third set, accepted changes and other errors
		{
			name:     "accept ttl extension (full permission)",
			fullPerm: true,
			opts:     &metav1.UpdateOptions{},
			token: func() *ext.Token {
				changed := properToken.DeepCopy()
				changed.Spec.TTL = 5000
				return changed
			}(),
			rtok: func() *ext.Token {
				changed := properToken.DeepCopy()
				changed.Spec.TTL = 5000
				changed.Status.LastUpdateTime = "this is a fake now"
				changed.Status.ExpiresAt = "0001-01-01T00:00:05Z"
				return changed
			}(),
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				timer *MocktimeHandler,
				hasher *MockhashHandler,
				checker *MockuserHandler) {

				// Get: Unchanged stored token
				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(&properSecret, nil)

				// Fake current time
				timer.EXPECT().Now().Return("this is a fake now")

				// Update: Return changed stored token
				secrets.EXPECT().
					Update(gomock.Any()).
					Return(&ttlPlusSecret, nil)
			},
			err: nil,
		},
		{
			name:     "accept ttl reduction (full permission)",
			fullPerm: true,
			opts:     &metav1.UpdateOptions{},
			token: func() *ext.Token {
				changed := properToken.DeepCopy()
				changed.Spec.TTL = 3000
				return changed
			}(),
			rtok: func() *ext.Token {
				changed := properToken.DeepCopy()
				changed.Spec.TTL = 3000
				changed.Status.LastUpdateTime = "this is a fake now"
				changed.Status.ExpiresAt = "0001-01-01T00:00:03Z"
				return changed
			}(),
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				timer *MocktimeHandler,
				hasher *MockhashHandler,
				checker *MockuserHandler) {

				// Get: Unchanged stored token
				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(&properSecret, nil)

				// Fake current time
				timer.EXPECT().Now().Return("this is a fake now")

				// Update: Return changed stored token
				secrets.EXPECT().
					Update(gomock.Any()).
					Return(&ttlSubSecret, nil)
			},
			err: nil,
		},
		{
			name:     "reject ttl extension (limited permission)",
			fullPerm: false,
			opts:     &metav1.UpdateOptions{},
			token: func() *ext.Token {
				changed := properToken.DeepCopy()
				changed.Spec.TTL = 5000
				return changed
			}(),
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				timer *MocktimeHandler,
				hasher *MockhashHandler,
				checker *MockuserHandler) {

				// Get: Unchanged stored token
				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(&properSecret, nil)
			},
			err: apierrors.NewBadRequest("rejecting change of token bogus: forbidden to extend time-to-live"),
		},
		{
			name:     "accept ttl reduction (limited permission)",
			fullPerm: false,
			opts:     &metav1.UpdateOptions{},
			token: func() *ext.Token {
				changed := properToken.DeepCopy()
				changed.Spec.TTL = 3000
				return changed
			}(),
			rtok: func() *ext.Token {
				changed := properToken.DeepCopy()
				changed.Spec.TTL = 3000
				changed.Status.LastUpdateTime = "this is a fake now"
				changed.Status.ExpiresAt = "0001-01-01T00:00:03Z"
				return changed
			}(),
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				timer *MocktimeHandler,
				hasher *MockhashHandler,
				checker *MockuserHandler) {

				// Get: Unchanged stored token
				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(&properSecret, nil)

				// Fake current time
				timer.EXPECT().Now().Return("this is a fake now")

				// Update: Return changed stored token
				secrets.EXPECT().
					Update(gomock.Any()).
					Return(&ttlSubSecret, nil)
			},
			err: nil,
		},
		{
			name:     "fail to save changes",
			fullPerm: true,
			opts:     &metav1.UpdateOptions{},
			token: func() *ext.Token {
				changed := properToken.DeepCopy()
				changed.Spec.TTL = 2000
				return changed
			}(),
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				timer *MocktimeHandler,
				hasher *MockhashHandler,
				checker *MockuserHandler) {

				// Get: Unchanged stored token
				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(&properSecret, nil)

				// Fake current time
				timer.EXPECT().Now().Return("this is a fake now")

				// Update: Fail
				secrets.EXPECT().
					Update(gomock.Any()).
					Return(nil, someerror)
			},
			err: apierrors.NewInternalError(fmt.Errorf("failed to update token bogus: %w", someerror)),
		},
		{
			name:     "read back broken data after update",
			fullPerm: true,
			opts:     &metav1.UpdateOptions{},
			token: func() *ext.Token {
				changed := properToken.DeepCopy()
				changed.Spec.TTL = 2000
				return changed
			}(),
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				timer *MocktimeHandler,
				hasher *MockhashHandler,
				checker *MockuserHandler) {

				// Get: Unchanged stored token
				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(&properSecret, nil)

				reduced := properSecret.DeepCopy()
				delete(reduced.Data, "user-id")

				// Fake current time
				timer.EXPECT().Now().Return("this is a fake now")

				// Update: Return broken data (piece missing)
				secrets.EXPECT().
					Update(gomock.Any()).
					Return(reduced, nil)
			},
			err: apierrors.NewInternalError(fmt.Errorf("failed to regenerate token bogus: %w", userIDMissingError)),
		},
		{
			name:     "ok",
			fullPerm: true,
			opts:     &metav1.UpdateOptions{},
			token: func() *ext.Token {
				changed := properToken.DeepCopy()
				changed.Spec.TTL = 2000
				return changed
			}(),
			rtok: func() *ext.Token {
				changed := properToken.DeepCopy()
				changed.Spec.TTL = 2000
				changed.Status.LastUpdateTime = "this is a fake now"
				changed.Status.ExpiresAt = "0001-01-01T00:00:02Z"
				return changed
			}(),
			storeSetup: func(
				secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList],
				timer *MocktimeHandler,
				hasher *MockhashHandler,
				checker *MockuserHandler) {

				// Get: Unchanged stored token
				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(&properSecret, nil)

				// Fake current time
				timer.EXPECT().Now().Return("this is a fake now")

				changed := properSecret.DeepCopy()
				changed.Data["ttl"] = []byte("2000")
				changed.Data["last-update-time"] = []byte("this is a fake now")

				// Update: Return modified data
				secrets.EXPECT().
					Update(gomock.Any()).
					Return(changed, nil)
			},
			err: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)

			// assemble and configure store from mock clients ...
			secrets := fake.NewMockControllerInterface[*corev1.Secret, *corev1.SecretList](ctrl)
			timer := NewMocktimeHandler(ctrl)
			hasher := NewMockhashHandler(ctrl)
			checker := NewMockuserHandler(ctrl)
			store := NewSystem(nil, secrets, nil, nil, timer, hasher, checker)
			test.storeSetup(secrets, timer, hasher, checker)

			// perform test and validate results
			tok, err := store.update(test.fullPerm, test.token, test.opts)

			if test.err != nil {
				assert.Equal(t, test.err, err)
				assert.Nil(t, tok)
			} else {
				assert.NoError(t, err)

				// Force equality on the fields update changes on semi-unpredictably on us
				// (ExpiresAt) -- Can we do this better ?
				// rtok.Status.ExpiresAt = test.token.Status.ExpiresAt

				assert.Equal(t, test.rtok, tok)
			}
		})
	}
}

func Test_SystemStore_Get(t *testing.T) {
	tests := []struct {
		name       string             // test name
		tokname    string             // name of token to retrieve
		opts       *metav1.GetOptions // retrieval options
		err        error              // expected op result, error
		tok        *ext.Token         // expected op result, token
		storeSetup func(              // configure store backend clients
			secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList])
	}{
		{
			name: "backing secret not found",
			storeSetup: func(secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList]) {
				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(nil, emptyNotFoundError)
			},
			tokname: "bogus",
			opts:    &metav1.GetOptions{},
			err:     emptyNotFoundError,
			tok:     nil,
		},
		{
			name: "some other error",
			storeSetup: func(secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList]) {
				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(nil, someerror)
			},
			tokname: "bogus",
			opts:    &metav1.GetOptions{},
			err:     apierrors.NewInternalError(fmt.Errorf("failed to retrieve token %s: %w", "bogus", someerror)),
			tok:     nil,
		},
		{
			name: "empty secret (no user id)",
			storeSetup: func(secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList]) {
				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(&corev1.Secret{}, nil)
			},
			tokname: "bogus",
			opts:    &metav1.GetOptions{},
			err:     apierrors.NewInternalError(fmt.Errorf("failed to extract token %s: %w", "bogus", userIDMissingError)),
			tok:     nil,
		},
		{
			name: "part-filled secret (no enabled)",
			storeSetup: func(secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList]) {
				reduced := properSecret.DeepCopy()
				delete(reduced.Data, "enabled")

				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(reduced, nil)
			},
			tokname: "bogus",
			opts:    &metav1.GetOptions{},
			err:     apierrors.NewInternalError(fmt.Errorf("failed to extract token %s: %w", "bogus", parseBoolError)),
			tok:     nil,
		},
		{
			name: "part-filled secret (no is-login)",
			storeSetup: func(secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList]) {
				reduced := properSecret.DeepCopy()
				delete(reduced.Data, "is-login")

				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(reduced, nil)
			},
			tokname: "bogus",
			opts:    &metav1.GetOptions{},
			err:     apierrors.NewInternalError(fmt.Errorf("failed to extract token %s: %w", "bogus", parseBoolError)),
			tok:     nil,
		},
		{
			name: "part-filled secret (no ttl)",
			storeSetup: func(secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList]) {
				reduced := properSecret.DeepCopy()
				delete(reduced.Data, "ttl")

				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(reduced, nil)
			},
			tokname: "bogus",
			opts:    &metav1.GetOptions{},
			err:     apierrors.NewInternalError(fmt.Errorf("failed to extract token %s: %w", "bogus", parseIntError)),
			tok:     nil,
		},
		{
			name: "part-filled secret (no hash)",
			storeSetup: func(secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList]) {
				reduced := properSecret.DeepCopy()
				delete(reduced.Data, "hash")

				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(reduced, nil)
			},
			tokname: "bogus",
			opts:    &metav1.GetOptions{},
			err:     apierrors.NewInternalError(fmt.Errorf("failed to extract token %s: %w", "bogus", hashMissingError)),
			tok:     nil,
		},
		{
			name: "part-filled secret (no auth provider)",
			storeSetup: func(secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList]) {
				reduced := properSecret.DeepCopy()
				delete(reduced.Data, "auth-provider")

				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(reduced, nil)
			},
			tokname: "bogus",
			opts:    &metav1.GetOptions{},
			err:     apierrors.NewInternalError(fmt.Errorf("failed to extract token %s: %w", "bogus", authProviderMissingError)),
			tok:     nil,
		},
		{
			name: "part-filled secret (no last update)",
			storeSetup: func(secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList]) {

				reduced := properSecret.DeepCopy()
				delete(reduced.Data, "last-update-time")

				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(reduced, nil)
			},
			tokname: "bogus",
			opts:    &metav1.GetOptions{},
			err:     apierrors.NewInternalError(fmt.Errorf("failed to extract token %s: %w", "bogus", lastUpdateMissingError)),
			tok:     nil,
		},
		{
			name: "part-filled secret (no principal id)",
			storeSetup: func(secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList]) {
				reduced := properSecret.DeepCopy()
				delete(reduced.Data, "principal-id")

				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(reduced, nil)
			},
			tokname: "bogus",
			opts:    &metav1.GetOptions{},
			err:     apierrors.NewInternalError(fmt.Errorf("failed to extract token %s: %w", "bogus", principalIDMissingError)),
			tok:     nil,
		},
		{
			name: "part-filled secret (no kube id)",
			storeSetup: func(secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList]) {

				reduced := properSecret.DeepCopy()
				delete(reduced.Data, "kube-uid")

				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(reduced, nil)
			},
			tokname: "bogus",
			opts:    &metav1.GetOptions{},
			err:     apierrors.NewInternalError(fmt.Errorf("failed to extract token %s: %w", "bogus", kubeIDMissingError)),
			tok:     nil,
		},
		{
			name: "filled secret",
			storeSetup: func(secrets *fake.MockControllerInterface[*corev1.Secret, *corev1.SecretList]) {
				secrets.EXPECT().
					Get("cattle-tokens", "bogus", gomock.Any()).
					Return(&properSecret, nil)
			},
			tokname: "bogus",
			opts:    &metav1.GetOptions{},
			err:     nil,
			tok: &ext.Token{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Token",
					APIVersion: "ext.cattle.io/v1alpha1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: "bogus",
					UID:  types.UID("2905498-kafld-lkad"),
				},
				Spec: ext.TokenSpec{
					UserID:      "lkajdlksjlkds",
					Description: "",
					ClusterName: "",
					TTL:         4000,
					Enabled:     false,
					IsLogin:     true,
				},
				Status: ext.TokenStatus{
					TokenValue:     "",
					TokenHash:      "kla9jkdmj",
					Expired:        true,
					ExpiresAt:      "0001-01-01T00:00:04Z",
					AuthProvider:   "somebody",
					LastUpdateTime: "13:00:05",
					DisplayName:    "myself",
					LoginName:      "hello",
					PrincipalID:    "world",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)

			// assemble and configure store from mock clients ...
			secrets := fake.NewMockControllerInterface[*corev1.Secret, *corev1.SecretList](ctrl)
			store := NewSystem(nil, secrets, nil, nil, nil, nil, nil)
			test.storeSetup(secrets)

			// perform test and validate results
			tok, err := store.Get(test.tokname, test.opts)
			if test.err != nil {
				assert.Equal(t, test.err, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, test.tok, tok)
		})
	}
}

// helpers

// implementation of the k8s user info interface for mocking

type mockUser struct {
	name string
}

func (u *mockUser) GetName() string {
	return u.name
}

func (u *mockUser) GetUID() string {
	return ""
}

func (u *mockUser) GetGroups() []string {
	return []string{}
}

func (u *mockUser) GetExtra() map[string][]string {
	return map[string][]string{}
}

// implementation of the k8s watch interface for mocking

func NewWatcher() *mockWatch {
	return &mockWatch{
		ch: make(chan watch.Event),
	}
}

func NewWatcherFor(e watch.Event) *mockWatch {
	ch := make(chan watch.Event, 1)
	ch <- e
	return &mockWatch{
		ch: ch,
	}
}

type mockWatch struct {
	ch chan watch.Event
}

func (w *mockWatch) Done() {
	close(w.ch)
}

func (w *mockWatch) ResultChan() <-chan watch.Event {
	return w.ch
}

func (w *mockWatch) Stop() {
}
