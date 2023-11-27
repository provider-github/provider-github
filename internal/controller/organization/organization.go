/*
Copyright 2022 The Crossplane Authors.

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

package organization

import (
	"context"
	"reflect"
	"slices"

	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	"github.com/crossplane/crossplane-runtime/pkg/connection"
	"github.com/crossplane/crossplane-runtime/pkg/controller"
	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/crossplane/crossplane-runtime/pkg/meta"
	"github.com/crossplane/crossplane-runtime/pkg/ratelimiter"
	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/pkg/resource"
	"github.com/crossplane/provider-github/internal/util"
	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/pointer"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/crossplane/provider-github/apis/organizations/v1alpha1"
	apisv1alpha1 "github.com/crossplane/provider-github/apis/v1alpha1"
	ghclient "github.com/crossplane/provider-github/internal/clients"
	"github.com/crossplane/provider-github/internal/features"

	"github.com/google/go-github/v54/github"
)

const (
	errNotOrganization = "managed resource is not a Organization custom resource"
	errTrackPCUsage    = "cannot track ProviderConfig usage"
	errGetPC           = "cannot get ProviderConfig"
	errGetCreds        = "cannot get credentials"

	errNewClient = "cannot create new Service"
)

// Setup adds a controller that reconciles Organization managed resources.
func Setup(mgr ctrl.Manager, o controller.Options) error {
	name := managed.ControllerName(v1alpha1.OrganizationGroupKind)

	cps := []managed.ConnectionPublisher{managed.NewAPISecretPublisher(mgr.GetClient(), mgr.GetScheme())}
	if o.Features.Enabled(features.EnableAlphaExternalSecretStores) {
		cps = append(cps, connection.NewDetailsManager(mgr.GetClient(), apisv1alpha1.StoreConfigGroupVersionKind))
	}

	r := managed.NewReconciler(mgr,
		resource.ManagedKind(v1alpha1.OrganizationGroupVersionKind),
		managed.WithExternalConnecter(&connector{
			kube:        mgr.GetClient(),
			usage:       resource.NewProviderConfigUsageTracker(mgr.GetClient(), &apisv1alpha1.ProviderConfigUsage{}),
			newClientFn: ghclient.NewClient}),
		managed.WithLogger(o.Logger.WithValues("controller", name)),
		managed.WithPollInterval(o.PollInterval),
		managed.WithRecorder(event.NewAPIRecorder(mgr.GetEventRecorderFor(name))),
		managed.WithConnectionPublishers(cps...))

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		WithOptions(o.ForControllerRuntime()).
		WithEventFilter(resource.DesiredStateChanged()).
		For(&v1alpha1.Organization{}).
		Complete(ratelimiter.NewReconciler(name, r, o.GlobalRateLimiter))
}

type connector struct {
	kube        client.Client
	usage       resource.Tracker
	newClientFn func(string) (*ghclient.Client, error)
}

// Initializes external client
func (c *connector) Connect(ctx context.Context, mg resource.Managed) (managed.ExternalClient, error) {
	cr, ok := mg.(*v1alpha1.Organization)
	if !ok {
		return nil, errors.New(errNotOrganization)
	}

	if err := c.usage.Track(ctx, mg); err != nil {
		return nil, errors.Wrap(err, errTrackPCUsage)
	}

	pc := &apisv1alpha1.ProviderConfig{}
	if err := c.kube.Get(ctx, types.NamespacedName{Name: cr.GetProviderConfigReference().Name}, pc); err != nil {
		return nil, errors.Wrap(err, errGetPC)
	}

	cd := pc.Spec.Credentials
	data, err := resource.CommonCredentialExtractor(ctx, cd.Source, c.kube, cd.CommonCredentialSelectors)
	if err != nil {
		return nil, errors.Wrap(err, errGetCreds)
	}

	gh, err := c.newClientFn(string(data))
	if err != nil {
		return nil, errors.Wrap(err, errNewClient)
	}

	return &external{github: gh}, nil
}

type external struct {
	// A 'client' used to connect to the external resource API. In practice this
	// would be something like an AWS SDK client.
	github *ghclient.Client
}

func (c *external) Observe(ctx context.Context, mg resource.Managed) (managed.ExternalObservation, error) {
	cr, ok := mg.(*v1alpha1.Organization)
	if !ok {
		return managed.ExternalObservation{}, errors.New(errNotOrganization)
	}

	name := meta.GetExternalName(cr)

	org, _, err := c.github.Organizations.Get(ctx, name)

	if ghclient.Is404(err) {
		return managed.ExternalObservation{
			ResourceExists: false,
		}, nil
	}

	if err != nil {
		return managed.ExternalObservation{}, err
	}

	// To use this function, the organization permission policy for enabled_repositories must be configured to selected, otherwise you get error 409 Conflict
	aResp, _, err := c.github.Actions.ListEnabledReposInOrg(ctx, name, &github.ListOptions{PerPage: 100})

	if err != nil {
		return managed.ExternalObservation{}, err
	}

	notUpToDate := managed.ExternalObservation{
		ResourceExists:   true,
		ResourceUpToDate: false,
	}

	aRepos := getSortedRepoNames(aResp.Repositories)

	crARepos := getSortedEnabledReposFromCr(cr.Spec.ForProvider.Actions.EnabledRepos)

	if err != nil {
		return managed.ExternalObservation{}, err
	}
	if !reflect.DeepEqual(aRepos, crARepos) {
		return notUpToDate, nil
	}

	if cr.Spec.ForProvider.Description != pointer.StringDeref(org.Description, "") {
		return notUpToDate, nil
	}

	cr.SetConditions(xpv1.Available())

	return managed.ExternalObservation{
		ResourceExists:   true,
		ResourceUpToDate: true,
	}, nil
}

func (c *external) Create(ctx context.Context, mg resource.Managed) (managed.ExternalCreation, error) {
	_, ok := mg.(*v1alpha1.Organization)
	if !ok {
		return managed.ExternalCreation{}, errors.New(errNotOrganization)
	}

	return managed.ExternalCreation{}, errors.New("Creation of organizations not supported!")
}

func (c *external) Update(ctx context.Context, mg resource.Managed) (managed.ExternalUpdate, error) {
	cr, ok := mg.(*v1alpha1.Organization)
	if !ok {
		return managed.ExternalUpdate{}, errors.New(errNotOrganization)
	}

	name := meta.GetExternalName(cr)
	gh := c.github
	req := &github.Organization{
		Description: &cr.Spec.ForProvider.Description,
	}

	_, _, err := gh.Organizations.Edit(ctx, name, req)
	if err != nil {
		return managed.ExternalUpdate{}, err
	}

	crARepos := getSortedEnabledReposFromCr(cr.Spec.ForProvider.Actions.EnabledRepos)

	// To use this function, the organization permission policy for enabled_repositories must be configured to selected, otherwise you get error 409 Conflict
	aResp, _, err := gh.Actions.ListEnabledReposInOrg(ctx, name, &github.ListOptions{PerPage: 100})
	if err != nil {
		return managed.ExternalUpdate{}, err
	}

	// Extract repository names from the list
	aRepos := getSortedRepoNames(aResp.Repositories)

	missingReposIds, err := getUpdateRepoIds(ctx, gh, name, crARepos, aRepos)
	if err != nil {
		return managed.ExternalUpdate{}, err
	}
	if cr.Spec.ForProvider.Actions.EnabledRepos != nil {
		for _, missingRepo := range missingReposIds {
			_, err := gh.Actions.AddEnabledReposInOrg(ctx, name, missingRepo)
			if err != nil {
				return managed.ExternalUpdate{}, err
			}
		}
	}

	toDeleteReposIds, err := getUpdateRepoIds(ctx, gh, name, aRepos, crARepos)
	if err != nil {
		return managed.ExternalUpdate{}, err
	}

	// Disable actions for missing repositories
	if cr.Spec.ForProvider.Actions.EnabledRepos != nil {
		for _, toDeleteRepo := range toDeleteReposIds {
			_, err := gh.Actions.RemoveEnabledRepoInOrg(ctx, name, toDeleteRepo)
			if err != nil {
				return managed.ExternalUpdate{}, err
			}
		}
	}

	return managed.ExternalUpdate{}, nil
}

func (c *external) Delete(ctx context.Context, mg resource.Managed) error {
	cr, ok := mg.(*v1alpha1.Organization)
	if !ok {
		return errors.New(errNotOrganization)
	}
	cr.Status.SetConditions(xpv1.Deleting())

	return nil
}

func getSortedEnabledReposFromCr(repos []v1alpha1.ActionEnabledRepo) []string {
	crAEnabledRepos := make([]string, 0, len(repos))
	for _, repo := range repos {
		crAEnabledRepos = append(crAEnabledRepos, repo.Repo)
	}
	slices.Sort(crAEnabledRepos)
	return crAEnabledRepos
}

func getSortedRepoNames(repos []*github.Repository) []string {
	repoNames := make([]string, 0, len(repos))
	for _, repo := range repos {
		repoNames = append(repoNames, repo.GetName())
	}
	slices.Sort(repoNames)
	return repoNames
}

func getUpdateRepoIds(ctx context.Context, gh *ghclient.Client, org string, crRepos []string, aRepos []string) ([]int64, error) {
	var updateRepos []string
	for _, repo := range crRepos {
		// Check if the repository from CRD is not in GitHub
		if !util.Contains(aRepos, repo) {
			updateRepos = append(updateRepos, repo)
		}
	}
	reposIds := make([]int64, 0, len(updateRepos))
	for _, repo := range updateRepos {
		repo, _, err := gh.Repositories.Get(ctx, org, repo)
		repoID := repo.GetID()
		reposIds = append(reposIds, repoID)
		if err != nil {
			return nil, err
		}
	}
	return reposIds, nil
}
