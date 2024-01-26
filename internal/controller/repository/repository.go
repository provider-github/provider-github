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

package repository

import (
	"context"
	"fmt"
	"reflect"
	"sort"

	"k8s.io/utils/pointer"

	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/google/go-github/v58/github"
	"github.com/gosimple/slug"

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
	"github.com/crossplane/provider-github/internal/util"
)

const (
	errNotRepository = "managed resource is not a Repository custom resource"
	errTrackPCUsage  = "cannot track ProviderConfig usage"
	errGetPC         = "cannot get ProviderConfig"
	errGetCreds      = "cannot get credentials"

	errNewClient = "cannot create new Service"
)

// Setup adds a controller that reconciles Repository managed resources.
func Setup(mgr ctrl.Manager, o controller.Options) error {
	name := managed.ControllerName(v1alpha1.RepositoryGroupKind)

	cps := []managed.ConnectionPublisher{managed.NewAPISecretPublisher(mgr.GetClient(), mgr.GetScheme())}
	if o.Features.Enabled(features.EnableAlphaExternalSecretStores) {
		cps = append(cps, connection.NewDetailsManager(mgr.GetClient(), apisv1alpha1.StoreConfigGroupVersionKind))
	}

	r := managed.NewReconciler(mgr,
		resource.ManagedKind(v1alpha1.RepositoryGroupVersionKind),
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
		For(&v1alpha1.Repository{}).
		Complete(ratelimiter.NewReconciler(name, r, o.GlobalRateLimiter))
}

type connector struct {
	kube        client.Client
	usage       resource.Tracker
	newClientFn func(string) (*ghclient.Client, error)
}

func (c *connector) Connect(ctx context.Context, mg resource.Managed) (managed.ExternalClient, error) {
	cr, ok := mg.(*v1alpha1.Repository)
	if !ok {
		return nil, errors.New(errNotRepository)
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
	github *ghclient.Client
}

//nolint:gocyclo
func (c *external) Observe(ctx context.Context, mg resource.Managed) (managed.ExternalObservation, error) {
	cr, ok := mg.(*v1alpha1.Repository)
	if !ok {
		return managed.ExternalObservation{}, errors.New(errNotRepository)
	}

	name := meta.GetExternalName(cr)

	repo, _, err := c.github.Repositories.Get(ctx, cr.Spec.ForProvider.Org, name)
	if ghclient.Is404(err) {
		return managed.ExternalObservation{ResourceExists: false}, nil
	}
	if err != nil {
		return managed.ExternalObservation{}, err
	}

	notUpToDate := managed.ExternalObservation{
		ResourceExists:   true,
		ResourceUpToDate: false,
	}

	crMToPermission := getUserPermissionMapFromCr(cr.Spec.ForProvider.Permissions.Users)
	ghMToPermission, err := getRepoUsersWithPermissions(ctx, c.github, cr.Spec.ForProvider.Org, name)

	if err != nil {
		return managed.ExternalObservation{}, err
	}

	if !reflect.DeepEqual(util.SortByKey(ghMToPermission), util.SortByKey(crMToPermission)) {
		return notUpToDate, nil
	}

	crTToPermission := getTeamPermissionMapFromCr(cr.Spec.ForProvider.Permissions.Teams)
	ghTToPermission, err := getRepoTeamsWithPermissions(ctx, c.github, cr.Spec.ForProvider.Org, name)
	if err != nil {
		return managed.ExternalObservation{}, err
	}

	if !reflect.DeepEqual(util.SortByKey(ghTToPermission), util.SortByKey(crTToPermission)) {
		return notUpToDate, nil
	}

	if cr.Spec.ForProvider.Webhooks != nil {
		ghRepoWebhooks, err := getRepoWebhooks(ctx, c.github, cr.Spec.ForProvider.Org, name)
		if err != nil {
			return managed.ExternalObservation{}, err
		}
		crWToConfig := getRepoWebhooksMapFromCr(cr.Spec.ForProvider.Webhooks)
		ghWToConfig := getRepoWebhooksWithConfig(ghRepoWebhooks)

		if !reflect.DeepEqual(ghWToConfig, crWToConfig) {
			return notUpToDate, nil
		}
	}

	archivedCr := pointer.BoolDeref(cr.Spec.ForProvider.Archived, false)
	if archivedCr != *repo.Archived {
		return notUpToDate, nil
	}

	privateCr := pointer.BoolDeref(cr.Spec.ForProvider.Private, true)
	if privateCr != *repo.Private {
		return notUpToDate, nil
	}

	cr.SetConditions(xpv1.Available())

	return managed.ExternalObservation{
		ResourceExists:   true,
		ResourceUpToDate: true,
	}, nil
}

func getTeamPermissionMapFromCr(teams []v1alpha1.RepositoryTeam) map[string]string {
	crTToPermission := make(map[string]string, len(teams))
	for _, team := range teams {
		teamSlug := slug.Make(team.Team)
		crTToPermission[teamSlug] = team.Role
	}

	return crTToPermission
}

func getUserPermissionMapFromCr(users []v1alpha1.RepositoryUser) map[string]string {
	crMToPermission := make(map[string]string, len(users))

	for _, user := range users {
		crMToPermission[user.User] = user.Role
	}

	return crMToPermission
}

func getRepoWebhooksMapFromCr(webhooks []v1alpha1.RepositoryWebhook) map[string]v1alpha1.RepositoryWebhook {
	crWToConfig := make(map[string]v1alpha1.RepositoryWebhook, len(webhooks))

	for _, webhook := range webhooks {
		sort.Strings(webhook.Events)
		crWToConfig[webhook.Url] = v1alpha1.RepositoryWebhook{
			Url:         webhook.Url,
			InsecureSsl: webhook.InsecureSsl,
			ContentType: webhook.ContentType,
			Events:      webhook.Events,
			Active:      webhook.Active,
		}
	}
	return crWToConfig
}

func getRepoWebhooks(ctx context.Context, gh *ghclient.Client, org, repoName string) ([]*github.Hook, error) {
	opt := &github.ListOptions{PerPage: 100}
	var allHooks []*github.Hook

	for {
		hooks, resp, err := gh.Repositories.ListHooks(ctx, org, repoName, opt)
		if err != nil {
			return nil, err
		}
		allHooks = append(allHooks, hooks...)

		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}

	return allHooks, nil
}

func getRepoWebhooksWithConfig(hooks []*github.Hook) map[string]v1alpha1.RepositoryWebhook {
	wToConfig := make(map[string]v1alpha1.RepositoryWebhook)

	for _, h := range hooks {
		url, _ := h.Config["url"].(string)
		insecureSslBool := false
		if h.Config["insecure_ssl"] == "1" {
			insecureSslBool = true
		}
		wToConfig[url] = v1alpha1.RepositoryWebhook{
			Url:         url,
			InsecureSsl: insecureSslBool,
			ContentType: h.Config["content_type"].(string),
			Events:      h.Events,
			Active:      *h.Active,
		}
	}

	return wToConfig
}

func getRepoWebhookId(hooks []*github.Hook, webhookUrl string) (*int64, error) {

	for _, h := range hooks {
		url, _ := h.Config["url"].(string)
		if url == webhookUrl {
			return h.ID, nil
		}
	}

	return nil, fmt.Errorf("cannot find repository webhook id for %s", webhookUrl)
}

func getRepoTeamsWithPermissions(ctx context.Context, gh *ghclient.Client, org, name string) (map[string]string, error) {
	tToPermission := make(map[string]string)

	opt := &github.ListOptions{PerPage: 100}

	for {
		repos, resp, err := gh.Repositories.ListTeams(ctx, org, name, opt)
		if err != nil {
			return nil, err
		}

		for _, m := range repos {
			tToPermission[*m.Slug] = *m.Permission
		}

		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}

	return tToPermission, nil
}

var permissionsOrdered = [...]string{"admin", "maintain", "push", "triage", "pull"}

func getRepoUsersWithPermissions(ctx context.Context, gh *ghclient.Client, org, name string) (map[string]string, error) {
	uToPermission := make(map[string]string)

	opt := &github.ListCollaboratorsOptions{
		Affiliation: "direct",
		ListOptions: github.ListOptions{PerPage: 100},
	}

	for {
		users, resp, err := gh.Repositories.ListCollaborators(ctx, org, name, opt)
		if err != nil {
			return nil, err
		}

		for _, m := range users {
			uToPermission[*m.Login] = "pull"

			for _, p := range permissionsOrdered {
				if m.Permissions[p] {
					uToPermission[*m.Login] = p
					break
				}
			}
		}

		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}

	return uToPermission, nil
}

//nolint:gocyclo
func (c *external) Create(ctx context.Context, mg resource.Managed) (managed.ExternalCreation, error) {
	cr, ok := mg.(*v1alpha1.Repository)
	if !ok {
		return managed.ExternalCreation{}, errors.New(errNotRepository)
	}

	name := meta.GetExternalName(cr)

	r := &github.Repository{
		Name:        &name,
		Description: &cr.Spec.ForProvider.Description,
		Private:     cr.Spec.ForProvider.Private,
	}

	_, _, err := c.github.Repositories.Create(ctx, cr.Spec.ForProvider.Org, r)
	if err != nil {
		return managed.ExternalCreation{}, err
	}

	if cr.Spec.ForProvider.Permissions.Users != nil {
		for _, user := range cr.Spec.ForProvider.Permissions.Users {
			opt := &github.RepositoryAddCollaboratorOptions{Permission: user.Role}
			_, _, err := c.github.Repositories.AddCollaborator(ctx, cr.Spec.ForProvider.Org, name, user.User, opt)
			if err != nil {
				return managed.ExternalCreation{}, err
			}
		}
	}

	if cr.Spec.ForProvider.Permissions.Teams != nil {
		for _, team := range cr.Spec.ForProvider.Permissions.Teams {
			teamSlug := slug.Make(team.Team)
			opt := &github.TeamAddTeamRepoOptions{Permission: team.Role}
			_, err := c.github.Teams.AddTeamRepoBySlug(ctx, cr.Spec.ForProvider.Org, teamSlug, cr.Spec.ForProvider.Org, name, opt)
			if err != nil {
				return managed.ExternalCreation{}, err
			}
		}
	}

	if cr.Spec.ForProvider.Webhooks != nil {
		for _, hookConfig := range cr.Spec.ForProvider.Webhooks {
			insecureSslInt := 0
			if hookConfig.InsecureSsl {
				insecureSslInt = 1
			}
			hook := &github.Hook{
				Config: map[string]interface{}{
					"url":          hookConfig.Url,
					"insecure_ssl": insecureSslInt,
					"content_type": hookConfig.ContentType,
				},
				Events: hookConfig.Events,
				Active: github.Bool(hookConfig.Active),
			}
			_, _, err := c.github.Repositories.CreateHook(ctx, cr.Spec.ForProvider.Org, *r.Name, hook)
			if err != nil {
				return managed.ExternalCreation{}, err
			}
		}
	}

	cr.SetConditions(xpv1.Available())

	return managed.ExternalCreation{}, nil
}

func updateRepoUsers(ctx context.Context, cr *v1alpha1.Repository, gh *ghclient.Client, repoName string) error {
	crMToPermission := getUserPermissionMapFromCr(cr.Spec.ForProvider.Permissions.Users)
	ghUToPermission, err := getRepoUsersWithPermissions(ctx, gh, cr.Spec.ForProvider.Org, repoName)

	if err != nil {
		return err
	}

	toDelete, toAdd, toUpdate := util.DiffPermissions(ghUToPermission, crMToPermission)

	for userName := range toDelete {
		_, err := gh.Repositories.RemoveCollaborator(ctx, cr.Spec.ForProvider.Org, repoName, userName)
		if err != nil {
			return err
		}
	}

	for userName, role := range util.MergeMaps(toAdd, toUpdate) {
		opt := &github.RepositoryAddCollaboratorOptions{Permission: role}
		_, _, err := gh.Repositories.AddCollaborator(ctx, cr.Spec.ForProvider.Org, repoName, userName, opt)
		if err != nil {
			return err
		}
	}

	return err
}

func updateRepoTeams(ctx context.Context, cr *v1alpha1.Repository, gh *ghclient.Client, repoName string) error {
	crTToPermission := getTeamPermissionMapFromCr(cr.Spec.ForProvider.Permissions.Teams)
	ghTToPermission, err := getRepoTeamsWithPermissions(ctx, gh, cr.Spec.ForProvider.Org, repoName)
	if err != nil {
		return err
	}

	toDelete, toAdd, toUpdate := util.DiffPermissions(ghTToPermission, crTToPermission)

	for teamSlug := range toDelete {
		_, err := gh.Teams.RemoveTeamRepoBySlug(ctx, cr.Spec.ForProvider.Org, teamSlug, cr.Spec.ForProvider.Org, repoName)
		if err != nil {
			return err
		}
	}

	for teamSlug, role := range util.MergeMaps(toAdd, toUpdate) {
		opt := &github.TeamAddTeamRepoOptions{Permission: role}
		_, err := gh.Teams.AddTeamRepoBySlug(ctx, cr.Spec.ForProvider.Org, teamSlug, cr.Spec.ForProvider.Org, repoName, opt)
		if err != nil {
			return err
		}
	}

	return nil
}

//nolint:gocyclo
func updateRepoWebhooks(ctx context.Context, cr *v1alpha1.Repository, gh *ghclient.Client, repoName string) error {
	ghRepoWebhooks, err := getRepoWebhooks(ctx, gh, cr.Spec.ForProvider.Org, repoName)
	if err != nil {
		return err
	}
	crWToConfig := getRepoWebhooksMapFromCr(cr.Spec.ForProvider.Webhooks)
	ghWToConfig := getRepoWebhooksWithConfig(ghRepoWebhooks)

	toDelete, toAdd, toUpdate := util.DiffRepoWebhooks(ghWToConfig, crWToConfig)

	for name := range toDelete {
		url := name
		id, err := getRepoWebhookId(ghRepoWebhooks, url)
		if err != nil {
			return err
		}
		_, err = gh.Repositories.DeleteHook(ctx, cr.Spec.ForProvider.Org, repoName, *id)
		if err != nil {
			return err
		}
	}

	for name, config := range toAdd {
		url := name
		insecureSslInt := 0
		if config.InsecureSsl {
			insecureSslInt = 1
		}
		hook := &github.Hook{
			Config: map[string]interface{}{
				"url":          url,
				"insecure_ssl": insecureSslInt,
				"content_type": config.ContentType,
			},
			Events: config.Events,
			Active: github.Bool(config.Active),
		}
		_, _, err := gh.Repositories.CreateHook(ctx, cr.Spec.ForProvider.Org, repoName, hook)
		if err != nil {
			return err
		}
	}

	for name, config := range toUpdate {
		url := name
		id, err := getRepoWebhookId(ghRepoWebhooks, url)
		if err != nil {
			return err
		}
		insecureSslInt := 0
		if config.InsecureSsl {
			insecureSslInt = 1
		}
		hook := &github.Hook{
			Config: map[string]interface{}{
				"url":          name,
				"insecure_ssl": insecureSslInt,
				"content_type": config.ContentType,
			},
			Events: config.Events,
			Active: github.Bool(config.Active),
		}
		_, _, err = gh.Repositories.EditHook(ctx, cr.Spec.ForProvider.Org, repoName, *id, hook)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *external) Update(ctx context.Context, mg resource.Managed) (managed.ExternalUpdate, error) {
	cr, ok := mg.(*v1alpha1.Repository)
	if !ok {
		return managed.ExternalUpdate{}, errors.New(errNotRepository)
	}

	name := meta.GetExternalName(cr)

	archivedCr := pointer.BoolDeref(cr.Spec.ForProvider.Archived, false)
	privateCr := pointer.BoolDeref(cr.Spec.ForProvider.Private, true)

	_, _, err := c.github.Repositories.Edit(ctx, cr.Spec.ForProvider.Org, name, &github.Repository{
		Name:        &name,
		Description: &cr.Spec.ForProvider.Description,
		Archived:    &archivedCr,
		Private:     &privateCr,
	})
	if err != nil {
		return managed.ExternalUpdate{}, err
	}

	err = updateRepoUsers(ctx, cr, c.github, name)
	if err != nil {
		return managed.ExternalUpdate{}, err
	}

	err = updateRepoTeams(ctx, cr, c.github, name)
	if err != nil {
		return managed.ExternalUpdate{}, err
	}

	if cr.Spec.ForProvider.Webhooks != nil {
		err = updateRepoWebhooks(ctx, cr, c.github, name)
		if err != nil {
			return managed.ExternalUpdate{}, err
		}
	}

	return managed.ExternalUpdate{}, nil
}

func (c *external) Delete(ctx context.Context, mg resource.Managed) error {
	cr, ok := mg.(*v1alpha1.Repository)
	if !ok {
		return errors.New(errNotRepository)
	}

	name := meta.GetExternalName(cr)

	forceDelete := pointer.BoolDeref(cr.Spec.ForProvider.ForceDelete, false)
	if !forceDelete {
		return errors.New("You can only delete repositories by setting `forceDelete: true`")
	}

	_, err := c.github.Repositories.Delete(ctx, cr.Spec.ForProvider.Org, name)
	if err != nil {
		return err
	}

	return nil
}
