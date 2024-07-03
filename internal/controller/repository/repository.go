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
	"encoding/json"
	"fmt"
	"reflect"
	"sort"

	"github.com/google/go-cmp/cmp"

	pointer "k8s.io/utils/ptr"

	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/google/go-github/v62/github"
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

	if cr.Spec.ForProvider.BranchProtectionRules != nil {
		protectedBranches, err := listProtectedBranches(ctx, c.github, cr.Spec.ForProvider.Org, name)
		if err != nil {
			return managed.ExternalObservation{}, err
		}
		crBPRToConfig := getBPRMapFromCr(cr.Spec.ForProvider.BranchProtectionRules)
		ghBPRToConfig, err := getBPRWithConfig(ctx, c.github, cr.Spec.ForProvider.Org, name, protectedBranches)
		if err != nil {
			return managed.ExternalObservation{}, err
		}

		if !cmp.Equal(crBPRToConfig, ghBPRToConfig) {
			return notUpToDate, nil
		}
	}

	if cr.Spec.ForProvider.RepositoryRules != nil {
		ghRepositoryRules, _ := getRepositoryRules(ctx, c.github, cr.Spec.ForProvider.Org, name)

		crRepositoryRulesToConfig := getRepositoryRulesMapFromCr(cr.Spec.ForProvider.RepositoryRules)
		ghRepositoryRulesToConfig, err := getRepositoryRulesWithConfig(ctx, c.github, cr.Spec.ForProvider.Org, name, ghRepositoryRules)
		if err != nil {
			return managed.ExternalObservation{}, err
		}

		if !cmp.Equal(crRepositoryRulesToConfig, ghRepositoryRulesToConfig) {
			return notUpToDate, nil
		}
	}

	archivedCr := pointer.Deref(cr.Spec.ForProvider.Archived, false)
	if archivedCr != *repo.Archived {
		return notUpToDate, nil
	}

	// repo visibility makes sense only when a repo is not a fork
	if !*repo.Fork {
		privateCr := pointer.Deref(cr.Spec.ForProvider.Private, true)
		if privateCr != *repo.Private {
			return notUpToDate, nil
		}
	}

	isTemplate := pointer.Deref(cr.Spec.ForProvider.IsTemplate, false)
	if isTemplate != *repo.IsTemplate {
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
		// handle optional *bool fields
		insecureSsl := util.BoolDerefToPointer(webhook.InsecureSsl, false)
		active := util.BoolDerefToPointer(webhook.Active, true)

		// sort events to aid comparison between desired and actual state
		sort.Strings(webhook.Events)

		crWToConfig[webhook.Url] = v1alpha1.RepositoryWebhook{
			Url:         webhook.Url,
			InsecureSsl: insecureSsl,
			ContentType: webhook.ContentType,
			Events:      webhook.Events,
			Active:      active,
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
		url := h.Config.GetURL()
		contentType := h.Config.GetContentType()
		insecureSslBool := false
		if h.Config.InsecureSSL != nil && *h.Config.InsecureSSL == "1" {
			insecureSslBool = true
		}
		wToConfig[url] = v1alpha1.RepositoryWebhook{
			Url:         url,
			InsecureSsl: &insecureSslBool,
			ContentType: contentType,
			Events:      h.Events,
			Active:      h.Active,
		}
	}

	return wToConfig
}

func getRepoWebhookId(hooks []*github.Hook, webhookUrl string) (*int64, error) {

	for _, h := range hooks {
		if h.Config.GetURL() == webhookUrl {
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

// listProtectedBranches retrieves all protected branches for a given GitHub repository.
// It uses pagination to handle large numbers of branches, fetching 100 branches per API call.
func listProtectedBranches(ctx context.Context, gh *ghclient.Client, org, repoName string) ([]*github.Branch, error) {
	opts := &github.BranchListOptions{
		Protected:   github.Bool(true),
		ListOptions: github.ListOptions{PerPage: 100},
	}
	var allBranches []*github.Branch

	for {
		branches, resp, err := gh.Repositories.ListBranches(ctx, org, repoName, opts)
		if err != nil {
			return nil, err
		}
		allBranches = append(allBranches, branches...)

		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	return allBranches, nil
}

// getBPRMapFromCr generates a map from a slice of BranchProtectionRules. Each rule is first processed:
// sorts the RequiredStatusChecks and any checks in various rule sub-structures, then the updated rule
// is added to the map with its branch name as the key. The function returns the resulting map.
//
//nolint:gocyclo
func getBPRMapFromCr(rules []v1alpha1.BranchProtectionRule) map[string]v1alpha1.BranchProtectionRule {
	crBPRToConfig := make(map[string]v1alpha1.BranchProtectionRule, len(rules))

	for i := range rules {
		// Use a copy to avoid changing passed []v1alpha1.BranchProtectionRule
		// This prevents the controller from changing the spec of the live CR
		// It can also prevent infinite reconciliation loops when managing the resources with ArgoCD
		orig := &rules[i]
		rCopy := orig.DeepCopy()

		// handle optional *bool fields
		rCopy.RequireLinearHistory = util.BoolDerefToPointer(rCopy.RequireLinearHistory, false)
		rCopy.AllowForcePushes = util.BoolDerefToPointer(rCopy.AllowForcePushes, false)
		rCopy.AllowDeletions = util.BoolDerefToPointer(rCopy.AllowDeletions, false)
		rCopy.RequiredConversationResolution = util.BoolDerefToPointer(rCopy.RequiredConversationResolution, false)
		rCopy.LockBranch = util.BoolDerefToPointer(rCopy.LockBranch, false)
		rCopy.AllowForkSyncing = util.BoolDerefToPointer(rCopy.AllowForkSyncing, false)
		rCopy.RequireSignedCommits = util.BoolDerefToPointer(rCopy.RequireSignedCommits, false)

		if rCopy.RequiredStatusChecks != nil && rCopy.RequiredStatusChecks.Checks != nil {
			copyOfStatusChecks := make([]*v1alpha1.RequiredStatusCheck, len(rCopy.RequiredStatusChecks.Checks))
			copy(copyOfStatusChecks, rCopy.RequiredStatusChecks.Checks)
			util.SortRequiredStatusChecks(copyOfStatusChecks)
			rCopy.RequiredStatusChecks.Checks = copyOfStatusChecks
		}

		restr := rCopy.BranchProtectionRestrictions
		if restr != nil {
			restr.BlockCreations = util.BoolDerefToPointer(restr.BlockCreations, false)
			if restr.Users != nil {
				restr.Users = util.SortAndReturn(restr.Users)
			}
			if restr.Teams != nil {
				restr.Teams = util.SortAndReturn(restr.Teams)
			}
			if restr.Apps != nil {
				restr.Apps = util.SortAndReturn(restr.Apps)
			}
		}

		rPRs := rCopy.RequiredPullRequestReviews
		if rPRs != nil {
			// handle optional *bool fields
			rPRs.RequireLastPushApproval = util.BoolDerefToPointer(rPRs.RequireLastPushApproval, false)

			allowances := rPRs.BypassPullRequestAllowances
			if allowances != nil {
				if allowances.Users != nil {
					allowances.Users = util.SortAndReturn(allowances.Users)
				}
				if allowances.Teams != nil {
					allowances.Teams = util.SortAndReturn(allowances.Teams)
				}
				if allowances.Apps != nil {
					allowances.Apps = util.SortAndReturn(allowances.Apps)
				}
			}
			dismissal := rPRs.DismissalRestrictions
			if dismissal != nil {
				if dismissal.Users != nil {
					dismissal.Users = util.SortAndReturnPointer(*dismissal.Users)
				}
				if dismissal.Teams != nil {
					dismissal.Teams = util.SortAndReturnPointer(*dismissal.Teams)
				}
				if dismissal.Apps != nil {
					dismissal.Apps = util.SortAndReturnPointer(*dismissal.Apps)
				}
			}
		}

		crBPRToConfig[rCopy.Branch] = *rCopy
	}

	return crBPRToConfig
}

// getBPRWithConfig creates a map of BranchProtectionRules for a GitHub repository based on its branches' current protection settings.
// It fetches each branch's protection settings from GitHub and maps them to BranchProtectionRule objects.
// Any lists of users, teams, or apps in the rules are sorted.
// It returns the BranchProtectionRules map, and any error encountered during the process.
//
//nolint:gocyclo
func getBPRWithConfig(ctx context.Context, gh *ghclient.Client, owner, repo string, branches []*github.Branch) (map[string]v1alpha1.BranchProtectionRule, error) {
	bprToConfig := make(map[string]v1alpha1.BranchProtectionRule, len(branches))

	for _, branch := range branches {
		protection, _, err := gh.Repositories.GetBranchProtection(ctx, owner, repo, branch.GetName())
		if err != nil {
			return nil, err
		}
		bpr := v1alpha1.BranchProtectionRule{
			Branch:                         branch.GetName(),
			EnforceAdmins:                  protection.GetEnforceAdmins().Enabled,
			RequireLinearHistory:           &protection.GetRequireLinearHistory().Enabled,
			AllowForcePushes:               &protection.GetAllowForcePushes().Enabled,
			AllowDeletions:                 &protection.GetAllowDeletions().Enabled,
			RequiredConversationResolution: &protection.GetRequiredConversationResolution().Enabled,
			LockBranch:                     util.ToBoolPtr(protection.GetLockBranch().GetEnabled()),
			AllowForkSyncing:               util.ToBoolPtr(protection.GetAllowForkSyncing().GetEnabled()),
			RequireSignedCommits:           util.ToBoolPtr(protection.GetRequiredSignatures().GetEnabled()),
		}

		rChecks := protection.GetRequiredStatusChecks()
		if rChecks != nil {
			bpr.RequiredStatusChecks = &v1alpha1.RequiredStatusChecks{
				Strict: rChecks.Strict,
			}
			if rChecks.Checks != nil && len(*rChecks.Checks) > 0 {
				checks := make([]*v1alpha1.RequiredStatusCheck, len(*rChecks.Checks))
				for i, check := range *rChecks.Checks {
					checks[i] = &v1alpha1.RequiredStatusCheck{
						Context: check.Context,
						AppID:   check.AppID,
					}
				}
				util.SortRequiredStatusChecks(checks)
				bpr.RequiredStatusChecks.Checks = checks
			}
		}

		rPRs := protection.GetRequiredPullRequestReviews()
		if rPRs != nil {
			bpr.RequiredPullRequestReviews = &v1alpha1.RequiredPullRequestReviews{
				DismissStaleReviews:          rPRs.DismissStaleReviews,
				RequireCodeOwnerReviews:      rPRs.RequireCodeOwnerReviews,
				RequiredApprovingReviewCount: rPRs.RequiredApprovingReviewCount,
				RequireLastPushApproval:      &rPRs.RequireLastPushApproval,
			}

			dismissal := rPRs.GetDismissalRestrictions()
			if dismissal != nil {
				bpr.RequiredPullRequestReviews.DismissalRestrictions = &v1alpha1.DismissalRestrictionsRequest{}
				if len(dismissal.Users) > 0 {
					users := make([]string, len(dismissal.Users))
					for i, user := range dismissal.Users {
						users[i] = user.GetLogin()
					}
					bpr.RequiredPullRequestReviews.DismissalRestrictions.Users = util.SortAndReturnPointer(users)
				}
				if len(dismissal.Teams) > 0 {
					teams := make([]string, len(dismissal.Teams))
					for i, team := range dismissal.Teams {
						teams[i] = team.GetSlug()
					}
					bpr.RequiredPullRequestReviews.DismissalRestrictions.Teams = util.SortAndReturnPointer(teams)
				}
				if len(dismissal.Apps) > 0 {
					apps := make([]string, len(dismissal.Apps))
					for i, app := range dismissal.Apps {
						apps[i] = app.GetSlug()
					}
					bpr.RequiredPullRequestReviews.DismissalRestrictions.Apps = util.SortAndReturnPointer(apps)
				}
			}

			allowances := rPRs.GetBypassPullRequestAllowances()
			if allowances != nil {
				bpr.RequiredPullRequestReviews.BypassPullRequestAllowances = &v1alpha1.BypassPullRequestAllowancesRequest{}
				if len(allowances.Users) > 0 {
					users := make([]string, len(allowances.Users))
					for i, user := range allowances.Users {
						users[i] = user.GetLogin()
					}
					bpr.RequiredPullRequestReviews.BypassPullRequestAllowances.Users = util.SortAndReturn(users)
				}
				if len(allowances.Teams) > 0 {
					teams := make([]string, len(allowances.Teams))
					for i, team := range allowances.Teams {
						teams[i] = team.GetSlug()
					}
					bpr.RequiredPullRequestReviews.BypassPullRequestAllowances.Teams = util.SortAndReturn(teams)
				}
				if len(allowances.Apps) > 0 {
					apps := make([]string, len(allowances.Apps))
					for i, app := range allowances.Apps {
						apps[i] = app.GetSlug()
					}
					bpr.RequiredPullRequestReviews.BypassPullRequestAllowances.Apps = util.SortAndReturn(apps)
				}
			}
		}

		restr := protection.GetRestrictions()
		if restr != nil {
			bpr.BranchProtectionRestrictions = &v1alpha1.BranchProtectionRestrictions{}
			bpr.BranchProtectionRestrictions.BlockCreations = util.ToBoolPtr(protection.GetBlockCreations().GetEnabled())
			if len(restr.Users) > 0 {
				users := make([]string, len(restr.Users))
				for i, user := range restr.Users {
					users[i] = user.GetLogin()
				}
				bpr.BranchProtectionRestrictions.Users = util.SortAndReturn(users)
			}
			if len(restr.Teams) > 0 {
				teams := make([]string, len(restr.Teams))
				for i, team := range restr.Teams {
					teams[i] = team.GetSlug()
				}
				bpr.BranchProtectionRestrictions.Teams = util.SortAndReturn(teams)
			}
			if len(restr.Apps) > 0 {
				apps := make([]string, len(restr.Apps))
				for i, app := range restr.Apps {
					apps[i] = app.GetSlug()
				}
				bpr.BranchProtectionRestrictions.Apps = util.SortAndReturn(apps)
			}
		}

		bprToConfig[branch.GetName()] = bpr
	}
	return bprToConfig, nil
}

//nolint:gocyclo
func (c *external) Create(ctx context.Context, mg resource.Managed) (managed.ExternalCreation, error) {
	cr, ok := mg.(*v1alpha1.Repository)
	if !ok {
		return managed.ExternalCreation{}, errors.New(errNotRepository)
	}

	name := meta.GetExternalName(cr)

	// handle optional *bool fields
	privateCr := pointer.Deref(cr.Spec.ForProvider.Private, true)

	var err error
	switch {
	case cr.Spec.ForProvider.CreateFork != nil:
		owner := cr.Spec.ForProvider.CreateFork.Owner
		repo := cr.Spec.ForProvider.CreateFork.Repo
		_, _, err = c.github.Repositories.CreateFork(ctx, owner, repo, &github.RepositoryCreateForkOptions{
			Organization:      cr.Spec.ForProvider.Org,
			Name:              name,
			DefaultBranchOnly: cr.Spec.ForProvider.CreateFork.DefaultBranchOnly,
		})
	case cr.Spec.ForProvider.CreateFromTemplate != nil:
		templateOwner := cr.Spec.ForProvider.CreateFromTemplate.Owner
		templateRepo := cr.Spec.ForProvider.CreateFromTemplate.Repo
		_, _, err = c.github.Repositories.CreateFromTemplate(ctx, templateOwner, templateRepo, &github.TemplateRepoRequest{
			Name:               &name,
			Owner:              &cr.Spec.ForProvider.Org,
			Description:        &cr.Spec.ForProvider.Description,
			IncludeAllBranches: &cr.Spec.ForProvider.CreateFromTemplate.IncludeAllBranches,
			Private:            &privateCr,
		})
	default:
		_, _, err = c.github.Repositories.Create(ctx, cr.Spec.ForProvider.Org, &github.Repository{
			Name:        &name,
			Description: &cr.Spec.ForProvider.Description,
			Private:     &privateCr,
		})
	}

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
		// getRepoWebhooksMapFromCr() provides defaults for optional *bool fields
		hooksMap := getRepoWebhooksMapFromCr(cr.Spec.ForProvider.Webhooks)
		for key := range hooksMap {
			// avoid "G601: Implicit memory aliasing in for loop"
			hook := hooksMap[key]
			_, _, err := c.github.Repositories.CreateHook(ctx, cr.Spec.ForProvider.Org, name, crRepoHookToHookConfig(hook))
			if err != nil {
				return managed.ExternalCreation{}, err
			}
		}
	}

	if cr.Spec.ForProvider.BranchProtectionRules != nil {
		// getBPRMapFromCr() provides defaults for optional *bool fields
		rulesMap := getBPRMapFromCr(cr.Spec.ForProvider.BranchProtectionRules)
		for key := range rulesMap {
			// avoid "G601: Implicit memory aliasing in for loop"
			rule := rulesMap[key]
			err = editProtectedBranch(ctx, &rule, c.github, cr.Spec.ForProvider.Org, name)
			if err != nil {
				return managed.ExternalCreation{}, err
			}
		}
	}
	if cr.Spec.ForProvider.RepositoryRules != nil {
		rulesMap := getRepositoryRulesMapFromCr(cr.Spec.ForProvider.RepositoryRules)
		for key := range rulesMap {
			// avoid "G601: Implicit memory aliasing in for loop"
			rule := rulesMap[key]
			_, _, err := c.github.Repositories.CreateRuleset(ctx, cr.Spec.ForProvider.Org, name, crRepoRulesToRulesConfig(rule))
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

// crRepoHookToHookConfig converts a RepositoryWebhook object to a *github.Hook object and returns it.
func crRepoHookToHookConfig(hook v1alpha1.RepositoryWebhook) *github.Hook {
	insecureSsl := "0"
	if hook.InsecureSsl != nil && *hook.InsecureSsl {
		insecureSsl = "1"
	}
	return &github.Hook{
		Config: &github.HookConfig{
			ContentType: &hook.ContentType,
			InsecureSSL: &insecureSsl,
			URL:         &hook.Url,
		},
		Events: hook.Events,
		Active: hook.Active,
	}
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

	for _, hook := range toAdd {
		_, _, err := gh.Repositories.CreateHook(ctx, cr.Spec.ForProvider.Org, repoName, crRepoHookToHookConfig(hook))
		if err != nil {
			return err
		}
	}

	for _, hook := range toUpdate {
		id, err := getRepoWebhookId(ghRepoWebhooks, hook.Url)
		if err != nil {
			return err
		}
		_, _, err = gh.Repositories.EditHook(ctx, cr.Spec.ForProvider.Org, repoName, *id, crRepoHookToHookConfig(hook))
		if err != nil {
			return err
		}
	}

	return nil
}

// editProtectedBranch updates the branch protection settings for a given GitHub repository
// based on a provided BranchProtectionRule. It returns an error if the update operation fails.
//
//nolint:gocyclo
func editProtectedBranch(ctx context.Context, rule *v1alpha1.BranchProtectionRule, gh *ghclient.Client, owner, repoName string) error {
	protectionRequest := &github.ProtectionRequest{
		EnforceAdmins:                  rule.EnforceAdmins,
		RequireLinearHistory:           rule.RequireLinearHistory,
		AllowForcePushes:               rule.AllowForcePushes,
		AllowDeletions:                 rule.AllowDeletions,
		RequiredConversationResolution: rule.RequiredConversationResolution,
		LockBranch:                     rule.LockBranch,
		AllowForkSyncing:               rule.AllowForkSyncing,
	}

	if rule.RequiredStatusChecks != nil {
		var checks []*github.RequiredStatusCheck
		for _, check := range rule.RequiredStatusChecks.Checks {
			// if nil, allow any app to set the status of a check
			appId := pointer.Deref(check.AppID, -1)
			checks = append(checks, &github.RequiredStatusCheck{
				Context: check.Context,
				AppID:   &appId,
			})
		}
		protectionRequest.RequiredStatusChecks = &github.RequiredStatusChecks{
			Strict: rule.RequiredStatusChecks.Strict,
			Checks: &checks,
		}
	}

	if rule.RequiredPullRequestReviews != nil {
		emptySlice := make([]string, 0)
		protectionRequest.RequiredPullRequestReviews = &github.PullRequestReviewsEnforcementRequest{
			// Avoid unmanaged bypass allowances when they're not set in the CR
			BypassPullRequestAllowancesRequest: &github.BypassPullRequestAllowancesRequest{
				Users: emptySlice, Teams: emptySlice, Apps: emptySlice,
			},
			// Avoid unmanaged dismissal restrictions when they're not set in the CR
			DismissalRestrictionsRequest: &github.DismissalRestrictionsRequest{Users: nil, Teams: nil, Apps: nil},
			DismissStaleReviews:          rule.RequiredPullRequestReviews.DismissStaleReviews,
			RequireCodeOwnerReviews:      rule.RequiredPullRequestReviews.RequireCodeOwnerReviews,
			RequiredApprovingReviewCount: rule.RequiredPullRequestReviews.RequiredApprovingReviewCount,
			RequireLastPushApproval:      rule.RequiredPullRequestReviews.RequireLastPushApproval,
		}
		if rule.RequiredPullRequestReviews.BypassPullRequestAllowances != nil {
			protectionRequest.RequiredPullRequestReviews.BypassPullRequestAllowancesRequest = &github.BypassPullRequestAllowancesRequest{
				Users: util.DefaultToStringSlice(rule.RequiredPullRequestReviews.BypassPullRequestAllowances.Users),
				Teams: util.DefaultToStringSlice(rule.RequiredPullRequestReviews.BypassPullRequestAllowances.Teams),
				Apps:  util.DefaultToStringSlice(rule.RequiredPullRequestReviews.BypassPullRequestAllowances.Apps),
			}
		}
		if rule.RequiredPullRequestReviews.DismissalRestrictions != nil {
			protectionRequest.RequiredPullRequestReviews.DismissalRestrictionsRequest = &github.DismissalRestrictionsRequest{
				Users: rule.RequiredPullRequestReviews.DismissalRestrictions.Users,
				Teams: rule.RequiredPullRequestReviews.DismissalRestrictions.Teams,
				Apps:  rule.RequiredPullRequestReviews.DismissalRestrictions.Apps,
			}
		}
	}

	if rule.BranchProtectionRestrictions != nil {
		protectionRequest.BlockCreations = rule.BranchProtectionRestrictions.BlockCreations
		protectionRequest.Restrictions = &github.BranchRestrictionsRequest{
			Users: util.DefaultToStringSlice(rule.BranchProtectionRestrictions.Users),
			Teams: util.DefaultToStringSlice(rule.BranchProtectionRestrictions.Teams),
			Apps:  util.DefaultToStringSlice(rule.BranchProtectionRestrictions.Apps),
		}
	}

	_, _, err := gh.Repositories.UpdateBranchProtection(ctx, owner, repoName, rule.Branch, protectionRequest)
	if err != nil {
		return err
	}

	err = handleBranchProtectionSignature(ctx, gh, owner, repoName, rule)
	if err != nil {
		return err
	}

	return nil
}

// updateProtectedBranches synchronizes the branch protection rules of a GitHub repository
// to match with those detailed in the repository resource object.
// It performs necessary additions, updates, or deletions based on the difference between
// the actual state on GitHub and the desired state in the resource object.
func updateProtectedBranches(ctx context.Context, cr *v1alpha1.Repository, gh *ghclient.Client, repoName string) error {
	protectedBranches, err := listProtectedBranches(ctx, gh, cr.Spec.ForProvider.Org, repoName)
	if err != nil {
		return err
	}
	crBPRToConfig := getBPRMapFromCr(cr.Spec.ForProvider.BranchProtectionRules)
	ghBPRToConfig, err := getBPRWithConfig(ctx, gh, cr.Spec.ForProvider.Org, repoName, protectedBranches)
	if err != nil {
		return err
	}

	toDelete, toAdd, toUpdate := util.DiffProtectedBranches(ghBPRToConfig, crBPRToConfig)

	for branchName := range toDelete {
		_, err = gh.Repositories.RemoveBranchProtection(ctx, cr.Spec.ForProvider.Org, repoName, branchName)
		if err != nil {
			return err
		}
	}

	for key := range toAdd {
		// avoid "G601: Implicit memory aliasing in for loop"
		config := toAdd[key]
		err = editProtectedBranch(ctx, &config, gh, cr.Spec.ForProvider.Org, repoName)
		if err != nil {
			return err
		}
	}

	for key := range toUpdate {
		// avoid "G601: Implicit memory aliasing in for loop"
		config := toUpdate[key]
		err = editProtectedBranch(ctx, &config, gh, cr.Spec.ForProvider.Org, repoName)
		if err != nil {
			return err
		}
	}

	return nil
}

// handleBranchProtectionSignature manages the requirement of signed commits for protected branches
// depending on the configuration. If RequireSignedCommits is set to true, it enforces signed commits,
// making them mandatory for all contributors. If it's false, signing commits is optional.
// It returns an error if any of the GitHub API calls fail.
func handleBranchProtectionSignature(ctx context.Context, gh *ghclient.Client, owner, repoName string, protectionRule *v1alpha1.BranchProtectionRule) error {
	if protectionRule.RequireSignedCommits != nil && *protectionRule.RequireSignedCommits {
		_, _, err := gh.Repositories.RequireSignaturesOnProtectedBranch(ctx, owner, repoName, protectionRule.Branch)
		if err != nil {
			return err
		}
	} else {
		_, err := gh.Repositories.OptionalSignaturesOnProtectedBranch(ctx, owner, repoName, protectionRule.Branch)
		if err != nil {
			return err
		}
	}
	return nil
}

// getRepositoryRules retrieves all the rules for a given GitHub repository.
// It uses pagination to handle large numbers of rules, fetching 100 rules per API call.
func getRepositoryRules(ctx context.Context, gh *ghclient.Client, org, repo string) ([]*github.Ruleset, error) {
	opt := &github.ListOptions{PerPage: 100}
	var allRules []*github.Ruleset

	for {
		rules, resp, err := gh.Repositories.GetAllRulesets(ctx, org, repo, true)
		if err != nil {
			return nil, err
		}

		allRules = append(allRules, rules...)

		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}

	return allRules, nil
}

// getRepositoryRulesMapFromCr generates a map from the RepositoryRules slice
// in the Crossplane resource.
//
//nolint:gocyclo
func getRepositoryRulesMapFromCr(rules []v1alpha1.RepositoryRuleset) map[string]v1alpha1.RepositoryRuleset {
	crRulesToConfig := make(map[string]v1alpha1.RepositoryRuleset, len(rules))

	for i := range rules {
		// Use a copy to avoid changing passed []v1alpha1.RepositoryRules
		// This prevents the controller from changing the spec of the live CR
		// It can also prevent infinite reconciliation loops when managing the resources with ArgoCD
		orig := &rules[i]
		rCopy := orig.DeepCopy()

		// handle optional fields
		rCopy.Target = util.StringDerefToPointer(rCopy.Target, "branch")
		rCopy.Enforcement = util.StringDerefToPointer(rCopy.Enforcement, "active")

		rConditions := rCopy.Conditions

		if rConditions != nil && rConditions.RefName != nil {
			if rConditions.RefName.Include != nil {
				rConditions.RefName.Include = util.SortAndReturn(rConditions.RefName.Include)
			}
			if rConditions.RefName.Exclude != nil {
				rConditions.RefName.Exclude = util.SortAndReturn(rConditions.RefName.Exclude)
			}
		}

		if rConditions == nil {
			rConditions = &v1alpha1.RulesetConditions{
				RefName: &v1alpha1.RulesetRefName{
					Include: []string{},
					Exclude: []string{},
				},
			}
			// Update the rConditions reference in rCopy
			rCopy.Conditions = rConditions
		}

		rBActors := rCopy.BypassActors
		if rBActors != nil {
			for a := range rBActors {
				actor := rBActors[a] // Make a copy of the actor

				// Set ActorId, ActorType, and BypassMode fields
				actor.ActorId = rBActors[a].ActorId
				actor.ActorType = rBActors[a].ActorType
				actor.BypassMode = rBActors[a].BypassMode

				// Update the actor in the slice
				rBActors[a] = actor
			}
			util.SortRulesBypassActors(rBActors)
		}
		rRules := rCopy.Rules
		if rRules != nil {
			rRules.RequiredSignatures = util.BoolDerefToPointer(rRules.RequiredSignatures, false)
			rRules.NonFastForward = util.BoolDerefToPointer(rRules.NonFastForward, false)
			rRules.Creation = util.BoolDerefToPointer(rRules.Creation, false)
			rRules.Deletion = util.BoolDerefToPointer(rRules.Deletion, false)
			rRules.RequiredLinearHistory = util.BoolDerefToPointer(rRules.RequiredLinearHistory, false)
			rRules.Update = util.BoolDerefToPointer(rRules.Update, false)

			if rRules.RequiredDeployments != nil {
				if rRules.RequiredDeployments.Environments != nil {
					rRules.RequiredDeployments.Environments = util.SortAndReturn(rRules.RequiredDeployments.Environments)
				}
			}
			if rRules.PullRequest != nil {
				rRules.PullRequest.DismissStaleReviewsOnPush = util.BoolDerefToPointer(rRules.PullRequest.DismissStaleReviewsOnPush, false)
				rRules.PullRequest.RequireCodeOwnerReview = util.BoolDerefToPointer(rRules.PullRequest.RequireCodeOwnerReview, false)
				rRules.PullRequest.RequireLastPushApproval = util.BoolDerefToPointer(rRules.PullRequest.RequireLastPushApproval, false)
				rRules.PullRequest.RequiredReviewThreadResolution = util.BoolDerefToPointer(rRules.PullRequest.RequiredReviewThreadResolution, false)
				rRules.PullRequest.RequiredApprovingReviewCount = util.IntDerefToPointer(rRules.PullRequest.RequiredApprovingReviewCount, 0)
			}
			if rRules.RequiredStatusChecks != nil {
				if rRules.RequiredStatusChecks.RequiredStatusChecks != nil {
					copyOfStatusChecks := make([]*v1alpha1.RulesRequiredStatusChecksParameters, len(rRules.RequiredStatusChecks.RequiredStatusChecks))
					copy(copyOfStatusChecks, rRules.RequiredStatusChecks.RequiredStatusChecks)
					util.SortRulesRequiredStatusChecks(copyOfStatusChecks)
					rRules.RequiredStatusChecks.RequiredStatusChecks = copyOfStatusChecks
				}
				rRules.RequiredStatusChecks.StrictRequiredStatusChecksPolicy = util.BoolDerefToPointer(rRules.RequiredStatusChecks.StrictRequiredStatusChecksPolicy, false)
			}
		}
		crRulesToConfig[rCopy.Name] = *rCopy
	}

	return crRulesToConfig
}

// getRepositoryRulesWithConfig creates a map of RepositoryRules based on the
// branch rules fetched from the GitHub API.
//
//nolint:gocyclo
func getRepositoryRulesWithConfig(ctx context.Context, gh *ghclient.Client, owner, repo string, ghRulesets []*github.Ruleset) (map[string]v1alpha1.RepositoryRuleset, error) {
	rulesToConfig := make(map[string]v1alpha1.RepositoryRuleset, len(ghRulesets))

	for _, rule := range ghRulesets {
		rRuleset, _, err := gh.Repositories.GetRuleset(ctx, owner, repo, *rule.ID, true)
		if err != nil {
			return nil, err
		}
		ruleset := v1alpha1.RepositoryRuleset{
			Target:      util.ToStringPtr(rule.GetTarget()),
			Enforcement: &rule.Enforcement,
			Name:        rule.Name,

			Conditions: &v1alpha1.RulesetConditions{
				RefName: &v1alpha1.RulesetRefName{
					Include: []string{},
					Exclude: []string{},
				},
			},
			BypassActors: nil,
			Rules: &v1alpha1.Rules{
				Creation:              util.ToBoolPtr(false),
				Update:                util.ToBoolPtr(false),
				Deletion:              util.ToBoolPtr(false),
				RequiredLinearHistory: util.ToBoolPtr(false),
				RequiredDeployments:   nil,
				RequiredSignatures:    util.ToBoolPtr(false),
				NonFastForward:        util.ToBoolPtr(false),
				PullRequest:           nil,
				RequiredStatusChecks:  nil,
			},
		}

		if rRuleset.Conditions != nil {
			if rRuleset.Conditions.RefName != nil {
				ruleset.Conditions.RefName = &v1alpha1.RulesetRefName{
					Include: util.SortAndReturn(rRuleset.Conditions.RefName.Include),
					Exclude: util.SortAndReturn(rRuleset.Conditions.RefName.Exclude),
				}
			}
		}

		if rRuleset.BypassActors != nil {
			if len(rRuleset.BypassActors) > 0 {
				ruleset.BypassActors = make([]*v1alpha1.RulesetByPassActors, len(rRuleset.BypassActors))
				for i, actor := range rRuleset.BypassActors {
					ruleset.BypassActors[i] = &v1alpha1.RulesetByPassActors{
						ActorType:  actor.ActorType,
						ActorId:    actor.ActorID,
						BypassMode: actor.BypassMode,
					}
				}
				util.SortRulesBypassActors(ruleset.BypassActors)
			}

		}
		if rRuleset != nil {
			for _, rule := range rRuleset.Rules {
				switch rule.Type {
				case "creation":
					ruleset.Rules.Creation = util.ToBoolPtr(true)
				case "deletion":
					ruleset.Rules.Deletion = util.ToBoolPtr(true)
				case "required_linear_history":
					ruleset.Rules.RequiredLinearHistory = util.ToBoolPtr(true)
				case "required_signatures":
					ruleset.Rules.RequiredSignatures = util.ToBoolPtr(true)
				case "non_fast_forward":
					ruleset.Rules.NonFastForward = util.ToBoolPtr(true)
				case "update":
					ruleset.Rules.Update = util.ToBoolPtr(true)
				case "pull_request":
					if rule.Parameters != nil {
						params := github.PullRequestRuleParameters{}
						if err := json.Unmarshal(*rule.Parameters, &params); err != nil {
							return nil, err
						}
						ruleset.Rules.PullRequest = &v1alpha1.RulesPullRequest{
							RequireCodeOwnerReview:         util.ToBoolPtr(params.RequireCodeOwnerReview),
							RequireLastPushApproval:        util.ToBoolPtr(params.RequireLastPushApproval),
							RequiredReviewThreadResolution: util.ToBoolPtr(params.RequiredReviewThreadResolution),
							RequiredApprovingReviewCount:   util.ToIntPtr(params.RequiredApprovingReviewCount),
							DismissStaleReviewsOnPush:      util.ToBoolPtr(params.DismissStaleReviewsOnPush),
						}
					}
				case "required_deployments":
					if rule.Parameters != nil {
						params := github.RequiredDeploymentEnvironmentsRuleParameters{}
						if err := json.Unmarshal(*rule.Parameters, &params); err != nil {
							return nil, err
						}
						ruleset.Rules.RequiredDeployments = &v1alpha1.RulesRequiredDeployments{
							Environments: util.SortAndReturn(params.RequiredDeploymentEnvironments),
						}
					}
				case "required_status_checks":
					if rule.Parameters != nil {
						params := github.RequiredStatusChecksRuleParameters{}
						if err := json.Unmarshal(*rule.Parameters, &params); err != nil {
							return nil, err
						}
						requiredStatusChecksParameters := make([]*v1alpha1.RulesRequiredStatusChecksParameters, len(params.RequiredStatusChecks))
						for i, statusCheck := range params.RequiredStatusChecks {
							requiredStatusChecksParameters[i] = &v1alpha1.RulesRequiredStatusChecksParameters{
								Context:       statusCheck.Context,
								IntegrationId: statusCheck.IntegrationID,
							}
						}
						util.SortRulesRequiredStatusChecks(requiredStatusChecksParameters)

						ruleset.Rules.RequiredStatusChecks = &v1alpha1.RulesRequiredStatusChecks{
							StrictRequiredStatusChecksPolicy: util.ToBoolPtr(params.StrictRequiredStatusChecksPolicy),
							RequiredStatusChecks:             requiredStatusChecksParameters,
						}
					}
				}

			}

		}

		rulesToConfig[rule.Name] = ruleset
	}

	return rulesToConfig, nil

}

// crRepoRulesToRulesConfig transforms a RepositoryRuleset object from the Crossplane resource
// into a Ruleset object that can be used with the GitHub API.
//
//nolint:gocyclo
func crRepoRulesToRulesConfig(rule v1alpha1.RepositoryRuleset) *github.Ruleset {
	githubRuleset := &github.Ruleset{
		Name:        rule.Name,
		Enforcement: *rule.Enforcement,
		Target:      rule.Target,
	}

	// If BypassActors is not nil, transform it into the github rule BypassActors
	if rule.BypassActors != nil {
		githubBypassActors := make([]*github.BypassActor, len(rule.BypassActors))
		for i, actor := range rule.BypassActors {
			githubBypassActors[i] = &github.BypassActor{
				ActorID:    actor.ActorId,
				ActorType:  actor.ActorType,
				BypassMode: actor.BypassMode,
			}
		}
		githubRuleset.BypassActors = githubBypassActors
	}

	// If Conditions is not nil, transform it into the github rule Conditions
	if rule.Conditions != nil {
		githubConditions := &github.RulesetConditions{
			RefName: &github.RulesetRefConditionParameters{
				Include: rule.Conditions.RefName.Include,
				Exclude: rule.Conditions.RefName.Exclude,
			},
		}
		githubRuleset.Conditions = githubConditions
	}
	// If Rules is not nil, transform it into the github rule Rules
	if rule.Rules != nil {
		githubRules := make([]*github.RepositoryRule, 0)
		if rule.Rules.RequiredStatusChecks != nil {
			params := github.RequiredStatusChecksRuleParameters{
				StrictRequiredStatusChecksPolicy: *rule.Rules.RequiredStatusChecks.StrictRequiredStatusChecksPolicy,
			}
			requiredStatusChecks := make([]github.RuleRequiredStatusChecks, len(rule.Rules.RequiredStatusChecks.RequiredStatusChecks))
			for i, statusCheck := range rule.Rules.RequiredStatusChecks.RequiredStatusChecks {
				requiredStatusChecks[i] = github.RuleRequiredStatusChecks{
					Context:       statusCheck.Context,
					IntegrationID: statusCheck.IntegrationId,
				}
			}
			params.RequiredStatusChecks = requiredStatusChecks
			paramsBytes, err := json.Marshal(params)
			if err != nil {
				return nil
			}
			rawParams := json.RawMessage(paramsBytes)
			githubRules = append(githubRules, &github.RepositoryRule{
				Type:       "required_status_checks",
				Parameters: &rawParams,
			})
		}

		if *rule.Rules.Creation {
			githubRules = append(githubRules, &github.RepositoryRule{
				Type: "creation",
			})
		}

		if *rule.Rules.Deletion {
			githubRules = append(githubRules, &github.RepositoryRule{
				Type: "deletion",
			})
		}

		if *rule.Rules.RequiredLinearHistory {
			githubRules = append(githubRules, &github.RepositoryRule{
				Type: "required_linear_history",
			})
		}

		if *rule.Rules.RequiredSignatures {
			githubRules = append(githubRules, &github.RepositoryRule{
				Type: "required_signatures",
			})
		}
		if *rule.Rules.NonFastForward {
			githubRules = append(githubRules, &github.RepositoryRule{
				Type: "non_fast_forward",
			})
		}
		if *rule.Rules.Update {
			githubRules = append(githubRules, &github.RepositoryRule{
				Type: "update",
			})
		}
		if rule.Rules.PullRequest != nil {
			params := github.PullRequestRuleParameters{
				DismissStaleReviewsOnPush:      *rule.Rules.PullRequest.DismissStaleReviewsOnPush,
				RequireCodeOwnerReview:         *rule.Rules.PullRequest.RequireCodeOwnerReview,
				RequireLastPushApproval:        *rule.Rules.PullRequest.RequireLastPushApproval,
				RequiredReviewThreadResolution: *rule.Rules.PullRequest.RequiredReviewThreadResolution,
				RequiredApprovingReviewCount:   *rule.Rules.PullRequest.RequiredApprovingReviewCount,
			}
			paramsBytes, err := json.Marshal(params)
			if err != nil {
				return nil
			}
			rawParams := json.RawMessage(paramsBytes)
			githubRules = append(githubRules, &github.RepositoryRule{
				Type:       "pull_request",
				Parameters: &rawParams,
			})
		}
		if rule.Rules.RequiredDeployments != nil {
			params := github.RequiredDeploymentEnvironmentsRuleParameters{
				RequiredDeploymentEnvironments: rule.Rules.RequiredDeployments.Environments,
			}
			paramsBytes, err := json.Marshal(params)
			if err != nil {
				return nil
			}
			rawParams := json.RawMessage(paramsBytes)
			githubRules = append(githubRules, &github.RepositoryRule{
				Type:       "required_deployments",
				Parameters: &rawParams,
			})
		}
		githubRuleset.Rules = githubRules

	}
	return githubRuleset
}

// updateRepositoryRules synchronizes the repository rules of a GitHub repository
// to match with those detailed in the repository resource object.
// It performs necessary additions, updates, or deletions based on the difference between
// the actual state on GitHub and the desired state in the resource object.
func updateRepositoryRules(ctx context.Context, cr *v1alpha1.Repository, gh *ghclient.Client, repoName string) error {
	// Fetch the current repository rules from GitHub
	ghRepoRules, err := getRepositoryRules(ctx, gh, cr.Spec.ForProvider.Org, repoName)
	if err != nil {
		return err
	}
	// Generate a map of the repository rules from the Crossplane resource
	crRToConfig := getRepositoryRulesMapFromCr(cr.Spec.ForProvider.RepositoryRules)
	// Generate a map of the repository rules from GitHub
	ghRToConfig, err := getRepositoryRulesWithConfig(ctx, gh, cr.Spec.ForProvider.Org, repoName, ghRepoRules)
	if err != nil {
		return err
	}
	// Determine which rules need to be deleted, added, or updated
	toDelete, toAdd, toUpdate := util.DiffRepositoryRulesets(ghRToConfig, crRToConfig)

	// Delete the rules that are no longer needed
	for name := range toDelete {
		rulesetID, _ := findRulesetIDByName(ghRepoRules, name)
		_, err = gh.Repositories.DeleteRuleset(ctx, cr.Spec.ForProvider.Org, repoName, rulesetID)
		if err != nil {
			return err
		}
	}
	// Add the new rules
	for _, rule := range toAdd {
		_, _, err := gh.Repositories.CreateRuleset(ctx, cr.Spec.ForProvider.Org, repoName, crRepoRulesToRulesConfig(rule))
		if err != nil {
			return err
		}
	}
	// Update the existing rules
	for name, rule := range toUpdate {
		rulesetID, _ := findRulesetIDByName(ghRepoRules, name)
		_, _, err := gh.Repositories.UpdateRuleset(ctx, cr.Spec.ForProvider.Org, repoName, rulesetID, crRepoRulesToRulesConfig(rule))
		if err != nil {
			return err
		}
	}
	return nil
}

// findRulesetIDByName iterates over a slice of GitHub Ruleset pointers and returns the ID of the ruleset
// that matches the provided name. If no match is found, it returns an error.
func findRulesetIDByName(rulesets []*github.Ruleset, name string) (int64, error) {
	for _, ruleset := range rulesets {
		if ruleset.Name == name {
			return *ruleset.ID, nil
		}
	}
	return 0, fmt.Errorf("ruleset with name %s not found", name)
}

//nolint:gocyclo
func (c *external) Update(ctx context.Context, mg resource.Managed) (managed.ExternalUpdate, error) {
	cr, ok := mg.(*v1alpha1.Repository)
	if !ok {
		return managed.ExternalUpdate{}, errors.New(errNotRepository)
	}

	name := meta.GetExternalName(cr)

	archivedCr := pointer.Deref(cr.Spec.ForProvider.Archived, false)

	// repo visibility makes sense only when a repo is not a fork
	var privateCr *bool

	repo, _, err := c.github.Repositories.Get(ctx, cr.Spec.ForProvider.Org, name)
	if err != nil {
		return managed.ExternalUpdate{}, err
	}
	if repo.Fork != nil && !*repo.Fork {
		val := pointer.Deref(cr.Spec.ForProvider.Private, true)
		privateCr = &val
	}

	isTemplate := pointer.Deref(cr.Spec.ForProvider.IsTemplate, false)

	_, _, err = c.github.Repositories.Edit(ctx, cr.Spec.ForProvider.Org, name, &github.Repository{
		Name:        &name,
		Description: &cr.Spec.ForProvider.Description,
		Archived:    &archivedCr,
		Private:     privateCr,
		IsTemplate:  &isTemplate,
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

	if cr.Spec.ForProvider.BranchProtectionRules != nil {
		err = updateProtectedBranches(ctx, cr, c.github, name)
		if err != nil {
			return managed.ExternalUpdate{}, err
		}
	}
	if cr.Spec.ForProvider.RepositoryRules != nil {
		err = updateRepositoryRules(ctx, cr, c.github, name)
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

	forceDelete := pointer.Deref(cr.Spec.ForProvider.ForceDelete, false)
	if !forceDelete {
		return errors.New("You can only delete repositories by setting `forceDelete: true`")
	}

	_, err := c.github.Repositories.Delete(ctx, cr.Spec.ForProvider.Org, name)
	if err != nil {
		return err
	}

	return nil
}
