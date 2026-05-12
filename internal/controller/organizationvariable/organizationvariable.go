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

package organizationvariable

import (
	"context"
	"reflect"
	"sort"
	"sync"
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
	"github.com/crossplane/provider-github/internal/features"
	"github.com/crossplane/provider-github/internal/telemetry"
)

const (
	errNotOrganizationVariable = "managed resource is not an OrganizationVariable custom resource"
	errTrackPCUsage            = "cannot track ProviderConfig usage"
	errGetPC                   = "cannot get ProviderConfig"
	errNewClient               = "cannot create new Service"

	visibilitySelected = "selected"
)

// Setup adds a controller that reconciles OrganizationVariable managed resources.
func Setup(mgr ctrl.Manager, o controller.Options, metrics *telemetry.RateLimitMetrics) error {
	return SetupWithTimeout(mgr, o, metrics, 0)
}

// SetupWithTimeout adds a controller that reconciles OrganizationVariable managed resources with configurable timeout.
func SetupWithTimeout(mgr ctrl.Manager, o controller.Options, metrics *telemetry.RateLimitMetrics, timeout time.Duration) error {
	name := managed.ControllerName(v1alpha1.OrganizationVariableGroupKind)

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
		resource.ManagedKind(v1alpha1.OrganizationVariableGroupVersionKind),
		reconcilerOptions...)

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		WithOptions(o.ForControllerRuntime()).
		WithEventFilter(resource.DesiredStateChanged()).
		For(&v1alpha1.OrganizationVariable{}).
		Complete(ratelimiter.NewReconciler(name, r, o.GlobalRateLimiter))
}

type connector struct {
	kube    client.Client
	usage   resource.Tracker
	metrics *telemetry.RateLimitMetrics
}

func (c *connector) Connect(ctx context.Context, mg resource.Managed) (managed.ExternalClient, error) {
	cr, ok := mg.(*v1alpha1.OrganizationVariable)
	if !ok {
		return nil, errors.New(errNotOrganizationVariable)
	}

	if err := c.usage.Track(ctx, mg); err != nil {
		return nil, errors.Wrap(err, errTrackPCUsage)
	}

	pc := &apisv1alpha1.ProviderConfig{}
	if err := c.kube.Get(ctx, types.NamespacedName{Name: cr.GetProviderConfigReference().Name}, pc); err != nil {
		return nil, errors.Wrap(err, errGetPC)
	}

	rlc, err := ghclient.ResolveAndConnect(ctx, c.kube, pc, c.metrics, cr.Spec.ForProvider.Org)
	if err != nil {
		return nil, errors.Wrap(err, errNewClient)
	}

	return &external{github: rlc}, nil
}

type external struct {
	github *ghclient.RateLimitClient
}

func (c *external) Observe(ctx context.Context, mg resource.Managed) (managed.ExternalObservation, error) {
	cr, ok := mg.(*v1alpha1.OrganizationVariable)
	if !ok {
		return managed.ExternalObservation{}, errors.New(errNotOrganizationVariable)
	}

	name := meta.GetExternalName(cr)
	org := cr.Spec.ForProvider.Org

	v, _, err := c.github.Actions.GetOrgVariable(ctx, org, name)
	if ghclient.Is404(err) {
		return managed.ExternalObservation{ResourceExists: false}, nil
	}
	if err != nil {
		return managed.ExternalObservation{}, err
	}

	ghVisibility := ""
	if v.Visibility != nil {
		ghVisibility = *v.Visibility
	}
	if v.Value != cr.Spec.ForProvider.Value || ghVisibility != cr.Spec.ForProvider.Visibility {
		return managed.ExternalObservation{ResourceExists: true, ResourceUpToDate: false}, nil
	}

	if cr.Spec.ForProvider.Visibility == visibilitySelected {
		cache := newRepoIDCache(c.github, org)
		crIDs, err := cache.batchGetIDs(ctx, repoNamesFromCR(cr.Spec.ForProvider.SelectedRepositories))
		if err != nil {
			return managed.ExternalObservation{}, err
		}
		ghIDs, err := listSelectedRepoIDs(ctx, c.github, org, name)
		if err != nil {
			return managed.ExternalObservation{}, err
		}
		sortInt64(crIDs)
		sortInt64(ghIDs)
		if !reflect.DeepEqual(crIDs, ghIDs) {
			return managed.ExternalObservation{ResourceExists: true, ResourceUpToDate: false}, nil
		}
	}

	cr.SetConditions(xpv1.Available())
	return managed.ExternalObservation{ResourceExists: true, ResourceUpToDate: true}, nil
}

func (c *external) Create(ctx context.Context, mg resource.Managed) (managed.ExternalCreation, error) {
	cr, ok := mg.(*v1alpha1.OrganizationVariable)
	if !ok {
		return managed.ExternalCreation{}, errors.New(errNotOrganizationVariable)
	}

	v, err := buildActionsVariable(ctx, c.github, cr)
	if err != nil {
		return managed.ExternalCreation{}, err
	}

	_, err = c.github.Actions.CreateOrgVariable(ctx, cr.Spec.ForProvider.Org, v)
	if err != nil {
		return managed.ExternalCreation{}, err
	}

	return managed.ExternalCreation{}, nil
}

func (c *external) Update(ctx context.Context, mg resource.Managed) (managed.ExternalUpdate, error) {
	cr, ok := mg.(*v1alpha1.OrganizationVariable)
	if !ok {
		return managed.ExternalUpdate{}, errors.New(errNotOrganizationVariable)
	}

	v, err := buildActionsVariable(ctx, c.github, cr)
	if err != nil {
		return managed.ExternalUpdate{}, err
	}

	_, err = c.github.Actions.UpdateOrgVariable(ctx, cr.Spec.ForProvider.Org, v)
	if err != nil {
		return managed.ExternalUpdate{}, err
	}

	return managed.ExternalUpdate{}, nil
}

func (c *external) Delete(ctx context.Context, mg resource.Managed) error {
	cr, ok := mg.(*v1alpha1.OrganizationVariable)
	if !ok {
		return errors.New(errNotOrganizationVariable)
	}

	name := meta.GetExternalName(cr)
	_, err := c.github.Actions.DeleteOrgVariable(ctx, cr.Spec.ForProvider.Org, name)
	if err != nil && !ghclient.Is404(err) {
		return err
	}
	return nil
}

// buildActionsVariable produces the payload for CreateOrgVariable /
// UpdateOrgVariable. For visibility=selected, it resolves repository
// names to IDs so they're sent in the same request.
func buildActionsVariable(ctx context.Context, gh *ghclient.RateLimitClient, cr *v1alpha1.OrganizationVariable) (*github.ActionsVariable, error) {
	visibility := cr.Spec.ForProvider.Visibility
	v := &github.ActionsVariable{
		Name:       meta.GetExternalName(cr),
		Value:      cr.Spec.ForProvider.Value,
		Visibility: &visibility,
	}

	if visibility == visibilitySelected {
		cache := newRepoIDCache(gh, cr.Spec.ForProvider.Org)
		ids, err := cache.batchGetIDs(ctx, repoNamesFromCR(cr.Spec.ForProvider.SelectedRepositories))
		if err != nil {
			return nil, err
		}
		repoIDs := github.SelectedRepoIDs(ids)
		v.SelectedRepositoryIDs = &repoIDs
	}

	return v, nil
}

func repoNamesFromCR(refs []v1alpha1.VariableSelectedRepo) []string {
	names := make([]string, 0, len(refs))
	for _, r := range refs {
		names = append(names, r.Repo)
	}
	return names
}

// listSelectedRepoIDs paginates through all repositories that have
// access to the variable on GitHub's side, returning their numeric IDs.
func listSelectedRepoIDs(ctx context.Context, gh *ghclient.RateLimitClient, org, name string) ([]int64, error) {
	opts := &github.ListOptions{PerPage: 100}
	var ids []int64
	for {
		list, resp, err := gh.Actions.ListSelectedReposForOrgVariable(ctx, org, name, opts)
		if err != nil {
			return nil, err
		}
		for _, r := range list.Repositories {
			ids = append(ids, r.GetID())
		}
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return ids, nil
}

func sortInt64(s []int64) {
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
}

// repoIDCache resolves repository names to numeric IDs once per
// reconcile. Avoids hitting Repositories.Get more than once for the
// same name when both Observe and Update need IDs for the same
// SelectedRepositories list.
type repoIDCache struct {
	mu    sync.Mutex
	cache map[string]int64
	gh    *ghclient.RateLimitClient
	org   string
}

func newRepoIDCache(gh *ghclient.RateLimitClient, org string) *repoIDCache {
	return &repoIDCache{cache: map[string]int64{}, gh: gh, org: org}
}

func (c *repoIDCache) batchGetIDs(ctx context.Context, names []string) ([]int64, error) {
	if len(names) == 0 {
		return []int64{}, nil
	}
	ids := make([]int64, 0, len(names))
	for _, n := range names {
		id, err := c.getID(ctx, n)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func (c *repoIDCache) getID(ctx context.Context, name string) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if id, ok := c.cache[name]; ok {
		return id, nil
	}
	r, _, err := c.gh.Repositories.Get(ctx, c.org, name)
	if err != nil {
		return 0, err
	}
	id := r.GetID()
	c.cache[name] = id
	return id, nil
}
