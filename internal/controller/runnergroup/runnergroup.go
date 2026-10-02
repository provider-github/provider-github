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

package runnergroup

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/google/go-github/v90/github"
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
	"github.com/crossplane/provider-github/internal/util"
)

const (
	errNotRunnerGroup = "managed resource is not a RunnerGroup custom resource"
	errTrackPCUsage   = "cannot track ProviderConfig usage"
	errGetPC          = "cannot get ProviderConfig"
	errNewClient      = "cannot create new Service"
	errNoID           = "runner group ID is not known"

	visibilitySelected = "selected"
)

// Setup adds a controller that reconciles RunnerGroup managed resources.
func Setup(mgr ctrl.Manager, o controller.Options, metrics *telemetry.RateLimitMetrics) error {
	return SetupWithTimeout(mgr, o, metrics, 0)
}

// SetupWithTimeout adds a controller that reconciles RunnerGroup managed resources with configurable timeout.
func SetupWithTimeout(mgr ctrl.Manager, o controller.Options, metrics *telemetry.RateLimitMetrics, timeout time.Duration) error {
	name := managed.ControllerName(v1alpha1.RunnerGroupGroupKind)

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
		resource.ManagedKind(v1alpha1.RunnerGroupGroupVersionKind),
		reconcilerOptions...)

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		WithOptions(o.ForControllerRuntime()).
		WithEventFilter(resource.DesiredStateChanged()).
		For(&v1alpha1.RunnerGroup{}).
		Complete(ratelimiter.NewReconciler(name, r, o.GlobalRateLimiter))
}

type connector struct {
	kube    client.Client
	usage   resource.Tracker
	metrics *telemetry.RateLimitMetrics
}

func (c *connector) Connect(ctx context.Context, mg resource.Managed) (managed.ExternalClient, error) {
	cr, ok := mg.(*v1alpha1.RunnerGroup)
	if !ok {
		return nil, errors.New(errNotRunnerGroup)
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
	cr, ok := mg.(*v1alpha1.RunnerGroup)
	if !ok {
		return managed.ExternalObservation{}, errors.New(errNotRunnerGroup)
	}

	org := cr.Spec.ForProvider.Org

	g, err := findRunnerGroup(ctx, c.github, org, meta.GetExternalName(cr))
	if err != nil {
		return managed.ExternalObservation{}, err
	}
	if g == nil {
		return managed.ExternalObservation{ResourceExists: false}, nil
	}
	cr.Status.AtProvider.ID = g.GetID()

	p := cr.Spec.ForProvider
	want := workflowStrings(p.SelectedWorkflows)
	if g.GetVisibility() != p.Visibility ||
		g.GetAllowsPublicRepositories() != p.AllowsPublicRepositories ||
		g.GetRestrictedToWorkflows() != (len(want) > 0) ||
		!util.EqualUnordered(g.SelectedWorkflows, want) {
		return managed.ExternalObservation{ResourceExists: true, ResourceUpToDate: false}, nil
	}

	if p.Visibility == visibilitySelected {
		ghRepos, err := listAccessRepos(ctx, c.github, org, g.GetID())
		if err != nil {
			return managed.ExternalObservation{}, err
		}
		upToDate, err := repoAccessUpToDate(ctx, c.github, org, repoNamesFromCR(p.SelectedRepositories), ghRepos)
		if err != nil {
			return managed.ExternalObservation{}, err
		}
		if !upToDate {
			return managed.ExternalObservation{ResourceExists: true, ResourceUpToDate: false}, nil
		}
	}

	cr.SetConditions(xpv1.Available())
	return managed.ExternalObservation{ResourceExists: true, ResourceUpToDate: true}, nil
}

func (c *external) Create(ctx context.Context, mg resource.Managed) (managed.ExternalCreation, error) {
	cr, ok := mg.(*v1alpha1.RunnerGroup)
	if !ok {
		return managed.ExternalCreation{}, errors.New(errNotRunnerGroup)
	}

	p := cr.Spec.ForProvider
	want := workflowStrings(p.SelectedWorkflows)
	req := github.CreateRunnerGroupRequest{
		Name:                     github.Ptr(meta.GetExternalName(cr)),
		Visibility:               github.Ptr(p.Visibility),
		AllowsPublicRepositories: github.Ptr(p.AllowsPublicRepositories),
		RestrictedToWorkflows:    github.Ptr(len(want) > 0),
		SelectedWorkflows:        want,
	}
	if p.Visibility == visibilitySelected {
		ids, err := ghclient.NewRepoIDResolver(c.github, p.Org).BatchGetIDs(ctx, repoNamesFromCR(p.SelectedRepositories))
		if err != nil {
			return managed.ExternalCreation{}, err
		}
		req.SelectedRepositoryIDs = ids
	}

	g, _, err := c.github.Actions.CreateOrganizationRunnerGroup(ctx, p.Org, req)
	if err != nil {
		return managed.ExternalCreation{}, err
	}
	cr.Status.AtProvider.ID = g.GetID()

	return managed.ExternalCreation{}, nil
}

func (c *external) Update(ctx context.Context, mg resource.Managed) (managed.ExternalUpdate, error) {
	cr, ok := mg.(*v1alpha1.RunnerGroup)
	if !ok {
		return managed.ExternalUpdate{}, errors.New(errNotRunnerGroup)
	}

	id := cr.Status.AtProvider.ID
	if id == 0 {
		return managed.ExternalUpdate{}, errors.New(errNoID)
	}

	p := cr.Spec.ForProvider
	want := workflowStrings(p.SelectedWorkflows)
	req := github.UpdateRunnerGroupRequest{
		Name:                     github.Ptr(meta.GetExternalName(cr)),
		Visibility:               github.Ptr(p.Visibility),
		AllowsPublicRepositories: github.Ptr(p.AllowsPublicRepositories),
		RestrictedToWorkflows:    github.Ptr(len(want) > 0),
		SelectedWorkflows:        want,
	}
	if _, _, err := c.github.Actions.UpdateOrganizationRunnerGroup(ctx, p.Org, id, req); err != nil {
		return managed.ExternalUpdate{}, err
	}

	if p.Visibility == visibilitySelected {
		ids, err := ghclient.NewRepoIDResolver(c.github, p.Org).BatchGetIDs(ctx, repoNamesFromCR(p.SelectedRepositories))
		if err != nil {
			return managed.ExternalUpdate{}, err
		}
		if _, err := c.github.Actions.SetRepositoryAccessRunnerGroup(ctx, p.Org, id, github.SetRepoAccessRunnerGroupRequest{SelectedRepositoryIDs: ids}); err != nil {
			return managed.ExternalUpdate{}, err
		}
	}

	return managed.ExternalUpdate{}, nil
}

func (c *external) Delete(ctx context.Context, mg resource.Managed) error {
	cr, ok := mg.(*v1alpha1.RunnerGroup)
	if !ok {
		return errors.New(errNotRunnerGroup)
	}

	id := cr.Status.AtProvider.ID
	if id == 0 {
		return nil
	}

	_, err := c.github.Actions.DeleteOrganizationRunnerGroup(ctx, cr.Spec.ForProvider.Org, id)
	if err != nil && !ghclient.Is404(err) {
		return err
	}
	return nil
}

// findRunnerGroup pages through the organization's runner groups and
// returns the one named name, or nil if there is none.
func findRunnerGroup(ctx context.Context, gh *ghclient.Client, org, name string) (*github.RunnerGroup, error) {
	opts := &github.ListOrgRunnerGroupOptions{ListOptions: github.ListOptions{PerPage: 100}}
	for {
		list, resp, err := gh.Actions.ListOrganizationRunnerGroups(ctx, org, opts)
		if err != nil {
			return nil, err
		}
		for _, g := range list.RunnerGroups {
			if g.GetName() == name {
				return g, nil
			}
		}
		if resp.NextPage == 0 {
			return nil, nil
		}
		opts.Page = resp.NextPage
	}
}

// listAccessRepos pages through the repositories that can use the
// runner group on GitHub's side.
func listAccessRepos(ctx context.Context, gh *ghclient.Client, org string, groupID int64) ([]*github.Repository, error) {
	opts := &github.ListOptions{PerPage: 100}
	var repos []*github.Repository
	for {
		list, resp, err := gh.Actions.ListRepositoryAccessRunnerGroup(ctx, org, groupID, opts)
		if err != nil {
			return nil, err
		}
		repos = append(repos, list.Repositories...)
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return repos, nil
}

// repoAccessUpToDate compares by name first, then by ID to catch renamed repositories.
func repoAccessUpToDate(ctx context.Context, gh *ghclient.Client, org string, specNames []string, ghRepos []*github.Repository) (bool, error) {
	ghNames := make([]string, 0, len(ghRepos))
	ghIDs := make([]int64, 0, len(ghRepos))
	for _, r := range ghRepos {
		ghNames = append(ghNames, strings.ToLower(r.GetName()))
		ghIDs = append(ghIDs, r.GetID())
	}
	lowered := make([]string, 0, len(specNames))
	for _, n := range specNames {
		lowered = append(lowered, strings.ToLower(n))
	}
	if util.EqualUnordered(lowered, ghNames) {
		return true, nil
	}

	specIDs, err := ghclient.NewRepoIDResolver(gh, org).BatchGetIDs(ctx, specNames)
	if err != nil {
		return false, err
	}
	ghclient.SortInt64(specIDs)
	ghclient.SortInt64(ghIDs)
	return slices.Equal(specIDs, ghIDs), nil
}

func repoNamesFromCR(refs []v1alpha1.RunnerGroupSelectedRepo) []string {
	names := make([]string, 0, len(refs))
	for _, r := range refs {
		names = append(names, r.Repo)
	}
	return names
}

// workflowStrings converts spec workflow entries to the strings the API uses.
func workflowStrings(wfs []v1alpha1.WorkflowRef) []string {
	out := make([]string, 0, len(wfs))
	for _, w := range wfs {
		out = append(out, string(w))
	}
	return out
}
