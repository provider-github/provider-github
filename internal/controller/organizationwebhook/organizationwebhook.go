/*
Copyright 2026 The Crossplane Authors.

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

package organizationwebhook

import (
	"context"
	"strconv"
	"time"

	"github.com/google/go-github/v90/github"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	pointer "k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	"github.com/crossplane/crossplane-runtime/pkg/connection"
	"github.com/crossplane/crossplane-runtime/pkg/controller"
	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/crossplane/crossplane-runtime/pkg/meta"
	"github.com/crossplane/crossplane-runtime/pkg/ratelimiter"
	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/pkg/resource"

	"github.com/crossplane/provider-github/apis/organizations/v1alpha1"
	apisv1alpha1 "github.com/crossplane/provider-github/apis/v1alpha1"
	ghclient "github.com/crossplane/provider-github/internal/clients"
	"github.com/crossplane/provider-github/internal/features"
	"github.com/crossplane/provider-github/internal/telemetry"
	"github.com/crossplane/provider-github/internal/util"
)

const (
	errNotOrganizationWebhook = "managed resource is not an OrganizationWebhook custom resource"
	errTrackPCUsage           = "cannot track ProviderConfig usage"
	errGetPC                  = "cannot get ProviderConfig"
	errNewClient              = "cannot create new Service"
	errNoID                   = "webhook ID is not known"
	errNoConnectionSecretRef  = "spec.writeConnectionSecretToRef must be set when secretKeyRef is used"

	// connectionSecretKey holds the last applied webhook secret in the connection secret.
	connectionSecretKey = "secret"
)

// Setup adds a controller that reconciles OrganizationWebhook managed resources.
func Setup(mgr ctrl.Manager, o controller.Options, metrics *telemetry.RateLimitMetrics) error {
	return SetupWithTimeout(mgr, o, metrics, 0)
}

// SetupWithTimeout adds a controller that reconciles OrganizationWebhook managed resources with configurable timeout.
func SetupWithTimeout(mgr ctrl.Manager, o controller.Options, metrics *telemetry.RateLimitMetrics, timeout time.Duration) error {
	name := managed.ControllerName(v1alpha1.OrganizationWebhookGroupKind)

	cps := []managed.ConnectionPublisher{managed.NewAPISecretPublisher(mgr.GetClient(), mgr.GetScheme())}
	if o.Features.Enabled(features.EnableAlphaExternalSecretStores) {
		cps = append(cps, connection.NewDetailsManager(mgr.GetClient(), apisv1alpha1.StoreConfigGroupVersionKind))
	}

	reconcilerOptions := []managed.ReconcilerOption{
		managed.WithExternalConnecter(&connector{
			kube:    mgr.GetClient(),
			usage:   resource.NewProviderConfigUsageTracker(mgr.GetClient(), &apisv1alpha1.ProviderConfigUsage{}),
			metrics: metrics}),
		managed.WithLogger(o.Logger.WithValues("controller", name)),
		managed.WithPollInterval(o.PollInterval),
		managed.WithRecorder(event.NewAPIRecorder(mgr.GetEventRecorderFor(name))),
		managed.WithConnectionPublishers(cps...),
	}

	if timeout > 0 {
		reconcilerOptions = append(reconcilerOptions, managed.WithTimeout(timeout))
	}

	r := managed.NewReconciler(mgr,
		resource.ManagedKind(v1alpha1.OrganizationWebhookGroupVersionKind),
		reconcilerOptions...)

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		WithOptions(o.ForControllerRuntime()).
		WithEventFilter(resource.DesiredStateChanged()).
		For(&v1alpha1.OrganizationWebhook{}).
		Complete(ratelimiter.NewReconciler(name, r, o.GlobalRateLimiter))
}

type connector struct {
	kube    client.Client
	usage   resource.Tracker
	metrics *telemetry.RateLimitMetrics
}

func (c *connector) Connect(ctx context.Context, mg resource.Managed) (managed.ExternalClient, error) {
	cr, ok := mg.(*v1alpha1.OrganizationWebhook)
	if !ok {
		return nil, errors.New(errNotOrganizationWebhook)
	}

	if err := c.usage.Track(ctx, mg); err != nil {
		return nil, errors.Wrap(err, errTrackPCUsage)
	}

	pc := &apisv1alpha1.ProviderConfig{}
	if err := c.kube.Get(ctx, types.NamespacedName{Name: cr.GetProviderConfigReference().Name}, pc); err != nil {
		return nil, errors.Wrap(err, errGetPC)
	}

	gh, err := ghclient.ResolveAndConnect(ctx, c.kube, pc, c.metrics, cr.Spec.ForProvider.Org)
	if err != nil {
		return nil, errors.Wrap(err, errNewClient)
	}

	return &external{github: gh, kube: c.kube}, nil
}

type external struct {
	github *ghclient.Client
	kube   client.Client
}

func (c *external) Observe(ctx context.Context, mg resource.Managed) (managed.ExternalObservation, error) {
	cr, ok := mg.(*v1alpha1.OrganizationWebhook)
	if !ok {
		return managed.ExternalObservation{}, errors.New(errNotOrganizationWebhook)
	}

	p := cr.Spec.ForProvider
	if p.SecretKeyRef != nil && cr.Spec.WriteConnectionSecretToReference == nil && !meta.WasDeleted(cr) {
		return managed.ExternalObservation{}, errors.New(errNoConnectionSecretRef)
	}

	h, err := c.findHook(ctx, cr)
	if err != nil {
		return managed.ExternalObservation{}, err
	}
	if h == nil {
		return managed.ExternalObservation{ResourceExists: false}, nil
	}
	cr.Status.AtProvider.ID = h.GetID()

	// Persist the adopted hook ID as the external name.
	id := strconv.FormatInt(h.GetID(), 10)
	lateInit := meta.GetExternalName(cr) != id
	if lateInit {
		meta.SetExternalName(cr, id)
	}

	if !configUpToDate(h, p) {
		return managed.ExternalObservation{ResourceExists: true, ResourceUpToDate: false, ResourceLateInitialized: lateInit}, nil
	}
	secretOK, err := c.secretUpToDate(ctx, cr, h)
	if err != nil {
		return managed.ExternalObservation{}, err
	}
	if !secretOK {
		return managed.ExternalObservation{ResourceExists: true, ResourceUpToDate: false, ResourceLateInitialized: lateInit}, nil
	}

	cr.SetConditions(xpv1.Available())
	return managed.ExternalObservation{ResourceExists: true, ResourceUpToDate: true, ResourceLateInitialized: lateInit}, nil
}

// configUpToDate compares every hook field except the secret.
func configUpToDate(h *github.Hook, p v1alpha1.OrganizationWebhookParameters) bool {
	return h.Config.GetURL() == p.Url &&
		h.Config.GetContentType() == p.ContentType &&
		util.EqualUnordered(h.Events, p.Events) &&
		h.GetActive() == pointer.Deref(p.Active, true) &&
		(h.Config.GetInsecureSSL() == "1") == pointer.Deref(p.InsecureSsl, false)
}

func (c *external) Create(ctx context.Context, mg resource.Managed) (managed.ExternalCreation, error) {
	cr, ok := mg.(*v1alpha1.OrganizationWebhook)
	if !ok {
		return managed.ExternalCreation{}, errors.New(errNotOrganizationWebhook)
	}

	hook, secret, err := c.desiredHook(ctx, cr)
	if err != nil {
		return managed.ExternalCreation{}, err
	}

	h, _, err := c.github.Organizations.CreateHook(ctx, cr.Spec.ForProvider.Org, hook)
	if err != nil {
		return managed.ExternalCreation{}, err
	}
	meta.SetExternalName(cr, strconv.FormatInt(h.GetID(), 10))
	cr.Status.AtProvider.ID = h.GetID()

	return managed.ExternalCreation{ConnectionDetails: connectionDetails(secret)}, nil
}

func (c *external) Update(ctx context.Context, mg resource.Managed) (managed.ExternalUpdate, error) {
	cr, ok := mg.(*v1alpha1.OrganizationWebhook)
	if !ok {
		return managed.ExternalUpdate{}, errors.New(errNotOrganizationWebhook)
	}

	id, ok := hookID(cr)
	if !ok {
		return managed.ExternalUpdate{}, errors.New(errNoID)
	}

	hook, secret, err := c.desiredHook(ctx, cr)
	if err != nil {
		return managed.ExternalUpdate{}, err
	}

	if _, _, err := c.github.Organizations.EditHook(ctx, cr.Spec.ForProvider.Org, id, hook); err != nil {
		return managed.ExternalUpdate{}, err
	}

	return managed.ExternalUpdate{ConnectionDetails: connectionDetails(secret)}, nil
}

func (c *external) Delete(ctx context.Context, mg resource.Managed) error {
	cr, ok := mg.(*v1alpha1.OrganizationWebhook)
	if !ok {
		return errors.New(errNotOrganizationWebhook)
	}

	id, ok := hookID(cr)
	if !ok {
		return nil
	}

	_, err := c.github.Organizations.DeleteHook(ctx, cr.Spec.ForProvider.Org, id)
	if err != nil && !ghclient.Is404(err) {
		return err
	}
	return nil
}

// findHook gets the hook by the ID in the external name, or else
// looks it up by URL. It returns nil if there is none.
func (c *external) findHook(ctx context.Context, cr *v1alpha1.OrganizationWebhook) (*github.Hook, error) {
	org := cr.Spec.ForProvider.Org
	if id, ok := hookID(cr); ok {
		h, _, err := c.github.Organizations.GetHook(ctx, org, id)
		if ghclient.Is404(err) {
			return nil, nil
		}
		return h, err
	}

	opts := &github.ListOptions{PerPage: 100}
	for {
		hooks, resp, err := c.github.Organizations.ListHooks(ctx, org, opts)
		if err != nil {
			return nil, err
		}
		for _, h := range hooks {
			if h.Config.GetURL() == cr.Spec.ForProvider.Url {
				return h, nil
			}
		}
		if resp.NextPage == 0 {
			return nil, nil
		}
		opts.Page = resp.NextPage
	}
}

// secretUpToDate compares the referenced secret with the one last
// applied, since GitHub only reports whether a secret is set.
func (c *external) secretUpToDate(ctx context.Context, cr *v1alpha1.OrganizationWebhook, h *github.Hook) (bool, error) {
	ghHasSecret := h.Config != nil && h.Config.Secret != nil
	if cr.Spec.ForProvider.SecretKeyRef == nil {
		return !ghHasSecret, nil
	}
	if !ghHasSecret {
		return false, nil
	}

	desired, err := c.desiredSecret(ctx, cr.Spec.ForProvider.SecretKeyRef)
	if err != nil {
		return false, err
	}
	applied, err := c.appliedSecret(ctx, cr.Spec.WriteConnectionSecretToReference)
	if err != nil {
		return false, err
	}
	return applied == desired, nil
}

// desiredHook builds the GitHub hook from the spec and returns the
// resolved secret, empty when the spec has none.
func (c *external) desiredHook(ctx context.Context, cr *v1alpha1.OrganizationWebhook) (*github.Hook, string, error) {
	p := cr.Spec.ForProvider
	insecureSsl := "0"
	if pointer.Deref(p.InsecureSsl, false) {
		insecureSsl = "1"
	}
	hook := &github.Hook{
		Config: &github.HookConfig{
			ContentType: github.Ptr(p.ContentType),
			InsecureSSL: github.Ptr(insecureSsl),
			URL:         github.Ptr(p.Url),
		},
		Events: p.Events,
		Active: github.Ptr(pointer.Deref(p.Active, true)),
	}
	if p.SecretKeyRef == nil {
		return hook, "", nil
	}
	secret, err := c.desiredSecret(ctx, p.SecretKeyRef)
	if err != nil {
		return nil, "", err
	}
	hook.Config.Secret = github.Ptr(secret)
	return hook, secret, nil
}

func (c *external) desiredSecret(ctx context.Context, ref *xpv1.SecretKeySelector) (string, error) {
	s := &corev1.Secret{}
	if err := c.kube.Get(ctx, types.NamespacedName{Name: ref.Name, Namespace: ref.Namespace}, s); err != nil {
		return "", errors.Wrapf(err, "cannot get secret `%s/%s`", ref.Namespace, ref.Name)
	}
	data, ok := s.Data[ref.Key]
	if !ok {
		return "", errors.Errorf("secret key `%s` not found in secret `%s/%s`", ref.Key, ref.Namespace, ref.Name)
	}
	return string(data), nil
}

// appliedSecret reads the last applied secret from the connection
// secret, which may not exist yet.
func (c *external) appliedSecret(ctx context.Context, ref *xpv1.SecretReference) (string, error) {
	s := &corev1.Secret{}
	if err := c.kube.Get(ctx, types.NamespacedName{Name: ref.Name, Namespace: ref.Namespace}, s); resource.IgnoreNotFound(err) != nil {
		return "", errors.Wrapf(err, "cannot get connection secret `%s/%s`", ref.Namespace, ref.Name)
	}
	return string(s.Data[connectionSecretKey]), nil
}

func connectionDetails(secret string) managed.ConnectionDetails {
	if secret == "" {
		return nil
	}
	return managed.ConnectionDetails{connectionSecretKey: []byte(secret)}
}

// hookID parses the hook ID from the external name, which holds the CR
// name until the hook is created or adopted.
func hookID(cr *v1alpha1.OrganizationWebhook) (int64, bool) {
	id, err := strconv.ParseInt(meta.GetExternalName(cr), 10, 64)
	return id, err == nil
}
