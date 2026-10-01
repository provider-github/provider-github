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

package dependabotsecretaccess

import (
	"context"
	"strings"
	"time"

	"github.com/google/go-github/v62/github"
	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/types"
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
	"github.com/crossplane/provider-github/internal/controller/secretaccess"
	"github.com/crossplane/provider-github/internal/features"
	"github.com/crossplane/provider-github/internal/telemetry"
)

const (
	errNotDependabotSecretAccess = "managed resource is not a DependabotSecretAccess custom resource"
	errTrackPCUsage              = "cannot track ProviderConfig usage"
	errGetPC                     = "cannot get ProviderConfig"
	errNewClient                 = "cannot create new Service"
)

// Setup adds a controller that reconciles DependabotSecretAccess managed resources.
func Setup(mgr ctrl.Manager, o controller.Options, metrics *telemetry.RateLimitMetrics) error {
	return SetupWithTimeout(mgr, o, metrics, 0)
}

// SetupWithTimeout adds a controller that reconciles DependabotSecretAccess managed resources with configurable timeout.
func SetupWithTimeout(mgr ctrl.Manager, o controller.Options, metrics *telemetry.RateLimitMetrics, timeout time.Duration) error {
	name := managed.ControllerName(v1alpha1.DependabotSecretAccessGroupKind)

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
		resource.ManagedKind(v1alpha1.DependabotSecretAccessGroupVersionKind),
		reconcilerOptions...)

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		WithOptions(o.ForControllerRuntime()).
		WithEventFilter(resource.DesiredStateChanged()).
		For(&v1alpha1.DependabotSecretAccess{}).
		Complete(ratelimiter.NewReconciler(name, r, o.GlobalRateLimiter))
}

type connector struct {
	kube    client.Client
	usage   resource.Tracker
	metrics *telemetry.RateLimitMetrics
}

func (c *connector) Connect(ctx context.Context, mg resource.Managed) (managed.ExternalClient, error) {
	cr, ok := mg.(*v1alpha1.DependabotSecretAccess)
	if !ok {
		return nil, errors.New(errNotDependabotSecretAccess)
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

	return &external{github: gh}, nil
}

type external struct {
	github *ghclient.Client
}

func (c *external) Observe(ctx context.Context, mg resource.Managed) (managed.ExternalObservation, error) {
	cr, ok := mg.(*v1alpha1.DependabotSecretAccess)
	if !ok {
		return managed.ExternalObservation{}, errors.New(errNotDependabotSecretAccess)
	}

	// Nothing to delete on GitHub, so report the resource gone to let the finalizer be removed.
	if meta.WasDeleted(cr) {
		return managed.ExternalObservation{ResourceExists: false}, nil
	}

	name := meta.GetExternalName(cr)
	org := cr.Spec.ForProvider.Org
	visibility := cr.Spec.ForProvider.Visibility

	s, _, err := c.github.Dependabot.GetOrgSecret(ctx, org, name)
	if ghclient.Is404(err) {
		cr.SetConditions(secretaccess.SecretNotFound(name))
		return managed.ExternalObservation{ResourceExists: true, ResourceUpToDate: true}, nil
	}
	if err != nil {
		return managed.ExternalObservation{}, err
	}

	if s.Visibility != visibility {
		cr.SetConditions(secretaccess.VisibilityMismatch(s.Visibility, visibility))
		return managed.ExternalObservation{ResourceExists: true, ResourceUpToDate: true}, nil
	}

	if visibility == secretaccess.VisibilitySelected {
		ghNames, err := secretaccess.ListRepoNames(ctx, c.github.Dependabot, org, name)
		if err != nil {
			return managed.ExternalObservation{}, err
		}
		if !secretaccess.SameRepos(cr.Spec.ForProvider.SelectedRepositories, ghNames) {
			return managed.ExternalObservation{ResourceExists: true, ResourceUpToDate: false}, nil
		}
	}

	cr.SetConditions(xpv1.Available())
	return managed.ExternalObservation{ResourceExists: true, ResourceUpToDate: true}, nil
}

func (c *external) Create(_ context.Context, mg resource.Managed) (managed.ExternalCreation, error) {
	cr, ok := mg.(*v1alpha1.DependabotSecretAccess)
	if !ok {
		return managed.ExternalCreation{}, errors.New(errNotDependabotSecretAccess)
	}
	return managed.ExternalCreation{}, secretaccess.SecretNotFoundError(meta.GetExternalName(cr))
}

func (c *external) Update(ctx context.Context, mg resource.Managed) (managed.ExternalUpdate, error) {
	cr, ok := mg.(*v1alpha1.DependabotSecretAccess)
	if !ok {
		return managed.ExternalUpdate{}, errors.New(errNotDependabotSecretAccess)
	}

	org := cr.Spec.ForProvider.Org
	name := meta.GetExternalName(cr)

	// IDs of repositories already selected come from the list; only newly
	// added names cost a Repositories.Get. Update cost must scale with the
	// repositories added, not the list size, or a large secret cannot
	// converge within the reconcile timeout. known is keyed by lowercased
	// name; Repositories.Get keeps the spec spelling (GitHub accepts any case).
	known, err := secretaccess.ListRepoIDs(ctx, c.github.Dependabot, org, name)
	if err != nil {
		return managed.ExternalUpdate{}, err
	}
	names := secretaccess.RepoNames(cr.Spec.ForProvider.SelectedRepositories)
	var added []string
	for _, n := range names {
		if _, ok := known[strings.ToLower(n)]; !ok {
			added = append(added, n)
		}
	}
	addedIDs, err := ghclient.NewRepoIDResolver(c.github, org).BatchGetIDs(ctx, added)
	if err != nil {
		return managed.ExternalUpdate{}, err
	}
	if err := secretaccess.RenamedRepoError(known, added, addedIDs); err != nil {
		return managed.ExternalUpdate{}, err
	}
	for i, n := range added {
		known[strings.ToLower(n)] = addedIDs[i]
	}
	ids := make([]int64, 0, len(names))
	for _, n := range names {
		ids = append(ids, known[strings.ToLower(n)])
	}

	_, err = c.github.Dependabot.SetSelectedReposForOrgSecret(ctx, org, name, github.DependabotSecretsSelectedRepoIDs(ids))
	return managed.ExternalUpdate{}, err
}

// Delete leaves the secret alone: the provider does not own it.
func (c *external) Delete(_ context.Context, _ resource.Managed) error {
	return nil
}
