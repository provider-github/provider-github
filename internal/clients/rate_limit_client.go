/*
Copyright 2024 The Crossplane Authors.

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

package clients

import (
	"context"

	"github.com/crossplane/provider-github/internal/telemetry"
	"github.com/google/go-github/v62/github"
)

// RateLimitClient wraps the GitHub client with rate limit tracking only
type RateLimitClient struct {
	*Client
	metrics *telemetry.RateLimitMetrics
}

// NewRateLimitClient creates a new rate limit tracking GitHub client
func NewRateLimitClient(client *Client, metrics *telemetry.RateLimitMetrics) *RateLimitClient {
	return &RateLimitClient{
		Client:  client,
		metrics: metrics,
	}
}

// WithRateLimitTracking returns a new RateLimitClient that tags every API
// response with the given identifiers:
//   - org is the GitHub organization for the Prometheus organization label;
//   - appID and installationID are the GitHub App ID and Installation ID,
//     used as the app_id and app_installation_id metric labels;
//   - cacheKey is the credential cache key, used internally by the per-app
//     quota pool to track 429s and steer future picks.
//
// appID/installationID and cacheKey are separate so that the metric labels
// stay human-meaningful while the pool keeps its stable internal identity.
func (rc *RateLimitClient) WithRateLimitTracking(org, appID, installationID, cacheKey string) *RateLimitClient {
	return &RateLimitClient{
		Client: &Client{
			Actions: &RateLimitActionsClient{
				ActionsClient:  rc.Actions,
				metrics:        rc.metrics,
				org:            org,
				appID:          appID,
				installationID: installationID,
				cacheKey:       cacheKey,
			},
			Dependabot: &RateLimitDependabotClient{
				DependabotClient: rc.Dependabot,
				metrics:          rc.metrics,
				org:              org,
				appID:            appID,
				installationID:   installationID,
				cacheKey:         cacheKey,
			},
			Organizations: &RateLimitOrganizationsClient{
				OrganizationsClient: rc.Organizations,
				metrics:             rc.metrics,
				org:                 org,
				appID:               appID,
				installationID:      installationID,
				cacheKey:            cacheKey,
			},
			Users: &RateLimitUsersClient{
				UsersClient:    rc.Users,
				metrics:        rc.metrics,
				org:            org,
				appID:          appID,
				installationID: installationID,
				cacheKey:       cacheKey,
			},
			Teams: &RateLimitTeamsClient{
				TeamsClient:    rc.Teams,
				metrics:        rc.metrics,
				org:            org,
				appID:          appID,
				installationID: installationID,
				cacheKey:       cacheKey,
			},
			Repositories: &RateLimitRepositoriesClient{
				RepositoriesClient: rc.Repositories,
				metrics:            rc.metrics,
				org:                org,
				appID:              appID,
				installationID:     installationID,
				cacheKey:           cacheKey,
			},
		},
		metrics: rc.metrics,
	}
}

// recordResponse fans the outcome of a GitHub call out to both Prometheus
// telemetry and the per-app quota pool. metrics may be nil (e.g. in unit
// tests); the pool is always updated so the picker stays accurate.
//
// Every call increments github_api_calls_total. When the call returns no
// HTTP response but an error (typically because ghinstallation failed to
// mint a token), github_app_unhealthy_total is also incremented and the
// pool records a short cooldown.
func recordResponse(metrics *telemetry.RateLimitMetrics, org, appID, installationID, cacheKey, method string, resp *github.Response, err error) {
	if metrics != nil {
		metrics.RecordAPICall(org, appID, installationID, method)
		metrics.RecordRateLimitInfo(resp, org, appID, installationID)
		if resp == nil && err != nil {
			metrics.RecordAppUnhealthy(org, appID, installationID)
		}
	}
	globalPool.recordResponse(cacheKey, resp, err)
}

// recordRateLimit wraps a value-returning GitHub call so the response's
// rate-limit information is recorded once it returns.
func recordRateLimit[T any](
	_ context.Context,
	metrics *telemetry.RateLimitMetrics,
	org, appID, installationID, cacheKey, method string,
	fn func() (T, *github.Response, error),
) (T, *github.Response, error) {
	result, resp, err := fn()
	recordResponse(metrics, org, appID, installationID, cacheKey, method, resp, err)
	return result, resp, err
}

// RateLimitActionsClient wraps the Actions client with rate limit tracking
type RateLimitActionsClient struct {
	ActionsClient
	metrics        *telemetry.RateLimitMetrics
	org            string
	appID          string
	installationID string
	cacheKey       string
}

// RateLimitOrganizationsClient wraps the Organizations client with rate limit tracking
type RateLimitOrganizationsClient struct {
	OrganizationsClient
	metrics        *telemetry.RateLimitMetrics
	org            string
	appID          string
	installationID string
	cacheKey       string
}

// RateLimitRepositoriesClient wraps the Repositories client with rate limit tracking
type RateLimitRepositoriesClient struct {
	RepositoriesClient
	metrics        *telemetry.RateLimitMetrics
	org            string
	appID          string
	installationID string
	cacheKey       string
}

// RateLimitTeamsClient wraps the Teams client with rate limit tracking
type RateLimitTeamsClient struct {
	TeamsClient
	metrics        *telemetry.RateLimitMetrics
	org            string
	appID          string
	installationID string
	cacheKey       string
}

// RateLimitUsersClient wraps the Users client with rate limit tracking
type RateLimitUsersClient struct {
	UsersClient
	metrics        *telemetry.RateLimitMetrics
	org            string
	appID          string
	installationID string
	cacheKey       string
}

// RateLimitDependabotClient wraps the Dependabot client with rate limit tracking
type RateLimitDependabotClient struct {
	DependabotClient
	metrics        *telemetry.RateLimitMetrics
	org            string
	appID          string
	installationID string
	cacheKey       string
}

// Sample implementations for key methods - only tracking rate limits

// RateLimitOrganizationsClient methods
func (roc *RateLimitOrganizationsClient) Get(ctx context.Context, org string) (*github.Organization, *github.Response, error) {
	return recordRateLimit(ctx, roc.metrics, roc.org, roc.appID, roc.installationID, roc.cacheKey, "Organizations.Get", func() (*github.Organization, *github.Response, error) {
		return roc.OrganizationsClient.Get(ctx, org)
	})
}

func (roc *RateLimitOrganizationsClient) Edit(ctx context.Context, name string, org *github.Organization) (*github.Organization, *github.Response, error) {
	return recordRateLimit(ctx, roc.metrics, roc.org, roc.appID, roc.installationID, roc.cacheKey, "Organizations.Edit", func() (*github.Organization, *github.Response, error) {
		return roc.OrganizationsClient.Edit(ctx, name, org)
	})
}

func (roc *RateLimitOrganizationsClient) GetOrgMembership(ctx context.Context, user, org string) (*github.Membership, *github.Response, error) {
	return recordRateLimit(ctx, roc.metrics, roc.org, roc.appID, roc.installationID, roc.cacheKey, "Organizations.GetOrgMembership", func() (*github.Membership, *github.Response, error) {
		return roc.OrganizationsClient.GetOrgMembership(ctx, user, org)
	})
}

func (roc *RateLimitOrganizationsClient) CreateOrgInvitation(ctx context.Context, org string, opts *github.CreateOrgInvitationOptions) (*github.Invitation, *github.Response, error) {
	return recordRateLimit(ctx, roc.metrics, roc.org, roc.appID, roc.installationID, roc.cacheKey, "Organizations.CreateOrgInvitation", func() (*github.Invitation, *github.Response, error) {
		return roc.OrganizationsClient.CreateOrgInvitation(ctx, org, opts)
	})
}

func (roc *RateLimitOrganizationsClient) EditOrgMembership(ctx context.Context, user, org string, membership *github.Membership) (*github.Membership, *github.Response, error) {
	return recordRateLimit(ctx, roc.metrics, roc.org, roc.appID, roc.installationID, roc.cacheKey, "Organizations.EditOrgMembership", func() (*github.Membership, *github.Response, error) {
		return roc.OrganizationsClient.EditOrgMembership(ctx, user, org, membership)
	})
}

func (roc *RateLimitOrganizationsClient) RemoveOrgMembership(ctx context.Context, user, org string) (*github.Response, error) {
	resp, err := roc.OrganizationsClient.RemoveOrgMembership(ctx, user, org)
	recordResponse(roc.metrics, roc.org, roc.appID, roc.installationID, roc.cacheKey, "Organizations.RemoveOrgMembership", resp, err)
	return resp, err
}

// RateLimitRepositoriesClient methods
func (rrc *RateLimitRepositoriesClient) Get(ctx context.Context, owner, repo string) (*github.Repository, *github.Response, error) {
	return recordRateLimit(ctx, rrc.metrics, rrc.org, rrc.appID, rrc.installationID, rrc.cacheKey, "Repositories.Get", func() (*github.Repository, *github.Response, error) {
		return rrc.RepositoriesClient.Get(ctx, owner, repo)
	})
}

func (rrc *RateLimitRepositoriesClient) Edit(ctx context.Context, owner, repo string, repository *github.Repository) (*github.Repository, *github.Response, error) {
	return recordRateLimit(ctx, rrc.metrics, rrc.org, rrc.appID, rrc.installationID, rrc.cacheKey, "Repositories.Edit", func() (*github.Repository, *github.Response, error) {
		return rrc.RepositoriesClient.Edit(ctx, owner, repo, repository)
	})
}

func (rrc *RateLimitRepositoriesClient) Create(ctx context.Context, org string, repo *github.Repository) (*github.Repository, *github.Response, error) {
	return recordRateLimit(ctx, rrc.metrics, rrc.org, rrc.appID, rrc.installationID, rrc.cacheKey, "Repositories.Create", func() (*github.Repository, *github.Response, error) {
		return rrc.RepositoriesClient.Create(ctx, org, repo)
	})
}

func (rrc *RateLimitRepositoriesClient) Delete(ctx context.Context, owner, repo string) (*github.Response, error) {
	resp, err := rrc.RepositoriesClient.Delete(ctx, owner, repo)
	recordResponse(rrc.metrics, rrc.org, rrc.appID, rrc.installationID, rrc.cacheKey, "Repositories.Delete", resp, err)
	return resp, err
}

func (rrc *RateLimitRepositoriesClient) ListTeams(ctx context.Context, owner, repo string, opts *github.ListOptions) ([]*github.Team, *github.Response, error) {
	return recordRateLimit(ctx, rrc.metrics, rrc.org, rrc.appID, rrc.installationID, rrc.cacheKey, "Repositories.ListTeams", func() ([]*github.Team, *github.Response, error) {
		return rrc.RepositoriesClient.ListTeams(ctx, owner, repo, opts)
	})
}

func (rrc *RateLimitRepositoriesClient) ListCollaborators(ctx context.Context, owner, repo string, opts *github.ListCollaboratorsOptions) ([]*github.User, *github.Response, error) {
	return recordRateLimit(ctx, rrc.metrics, rrc.org, rrc.appID, rrc.installationID, rrc.cacheKey, "Repositories.ListCollaborators", func() ([]*github.User, *github.Response, error) {
		return rrc.RepositoriesClient.ListCollaborators(ctx, owner, repo, opts)
	})
}

func (rrc *RateLimitRepositoriesClient) CreateFromTemplate(ctx context.Context, templateOwner, templateRepo string, templateRepoReq *github.TemplateRepoRequest) (*github.Repository, *github.Response, error) {
	return recordRateLimit(ctx, rrc.metrics, rrc.org, rrc.appID, rrc.installationID, rrc.cacheKey, "Repositories.CreateFromTemplate", func() (*github.Repository, *github.Response, error) {
		return rrc.RepositoriesClient.CreateFromTemplate(ctx, templateOwner, templateRepo, templateRepoReq)
	})
}

func (rrc *RateLimitRepositoriesClient) CreateFork(ctx context.Context, owner, repo string, opts *github.RepositoryCreateForkOptions) (*github.Repository, *github.Response, error) {
	return recordRateLimit(ctx, rrc.metrics, rrc.org, rrc.appID, rrc.installationID, rrc.cacheKey, "Repositories.CreateFork", func() (*github.Repository, *github.Response, error) {
		return rrc.RepositoriesClient.CreateFork(ctx, owner, repo, opts)
	})
}

func (rrc *RateLimitRepositoriesClient) AddCollaborator(ctx context.Context, owner, repo, user string, opts *github.RepositoryAddCollaboratorOptions) (*github.CollaboratorInvitation, *github.Response, error) {
	return recordRateLimit(ctx, rrc.metrics, rrc.org, rrc.appID, rrc.installationID, rrc.cacheKey, "Repositories.AddCollaborator", func() (*github.CollaboratorInvitation, *github.Response, error) {
		return rrc.RepositoriesClient.AddCollaborator(ctx, owner, repo, user, opts)
	})
}

func (rrc *RateLimitRepositoriesClient) RemoveCollaborator(ctx context.Context, owner, repo, user string) (*github.Response, error) {
	resp, err := rrc.RepositoriesClient.RemoveCollaborator(ctx, owner, repo, user)
	recordResponse(rrc.metrics, rrc.org, rrc.appID, rrc.installationID, rrc.cacheKey, "Repositories.RemoveCollaborator", resp, err)
	return resp, err
}

func (rrc *RateLimitRepositoriesClient) CreateHook(ctx context.Context, owner, repo string, hook *github.Hook) (*github.Hook, *github.Response, error) {
	return recordRateLimit(ctx, rrc.metrics, rrc.org, rrc.appID, rrc.installationID, rrc.cacheKey, "Repositories.CreateHook", func() (*github.Hook, *github.Response, error) {
		return rrc.RepositoriesClient.CreateHook(ctx, owner, repo, hook)
	})
}

func (rrc *RateLimitRepositoriesClient) EditHook(ctx context.Context, owner, repo string, id int64, hook *github.Hook) (*github.Hook, *github.Response, error) {
	return recordRateLimit(ctx, rrc.metrics, rrc.org, rrc.appID, rrc.installationID, rrc.cacheKey, "Repositories.EditHook", func() (*github.Hook, *github.Response, error) {
		return rrc.RepositoriesClient.EditHook(ctx, owner, repo, id, hook)
	})
}

func (rrc *RateLimitRepositoriesClient) DeleteHook(ctx context.Context, owner, repo string, id int64) (*github.Response, error) {
	resp, err := rrc.RepositoriesClient.DeleteHook(ctx, owner, repo, id)
	recordResponse(rrc.metrics, rrc.org, rrc.appID, rrc.installationID, rrc.cacheKey, "Repositories.DeleteHook", resp, err)
	return resp, err
}

func (rrc *RateLimitRepositoriesClient) ListHooks(ctx context.Context, owner, repo string, opts *github.ListOptions) ([]*github.Hook, *github.Response, error) {
	return recordRateLimit(ctx, rrc.metrics, rrc.org, rrc.appID, rrc.installationID, rrc.cacheKey, "Repositories.ListHooks", func() ([]*github.Hook, *github.Response, error) {
		return rrc.RepositoriesClient.ListHooks(ctx, owner, repo, opts)
	})
}

func (rrc *RateLimitRepositoriesClient) ListBranches(ctx context.Context, owner, repo string, opts *github.BranchListOptions) ([]*github.Branch, *github.Response, error) {
	return recordRateLimit(ctx, rrc.metrics, rrc.org, rrc.appID, rrc.installationID, rrc.cacheKey, "Repositories.ListBranches", func() ([]*github.Branch, *github.Response, error) {
		return rrc.RepositoriesClient.ListBranches(ctx, owner, repo, opts)
	})
}

func (rrc *RateLimitRepositoriesClient) GetBranchProtection(ctx context.Context, owner, repo, branch string) (*github.Protection, *github.Response, error) {
	return recordRateLimit(ctx, rrc.metrics, rrc.org, rrc.appID, rrc.installationID, rrc.cacheKey, "Repositories.GetBranchProtection", func() (*github.Protection, *github.Response, error) {
		return rrc.RepositoriesClient.GetBranchProtection(ctx, owner, repo, branch)
	})
}

func (rrc *RateLimitRepositoriesClient) UpdateBranchProtection(ctx context.Context, owner, repo, branch string, preq *github.ProtectionRequest) (*github.Protection, *github.Response, error) {
	return recordRateLimit(ctx, rrc.metrics, rrc.org, rrc.appID, rrc.installationID, rrc.cacheKey, "Repositories.UpdateBranchProtection", func() (*github.Protection, *github.Response, error) {
		return rrc.RepositoriesClient.UpdateBranchProtection(ctx, owner, repo, branch, preq)
	})
}

func (rrc *RateLimitRepositoriesClient) RemoveBranchProtection(ctx context.Context, owner, repo, branch string) (*github.Response, error) {
	resp, err := rrc.RepositoriesClient.RemoveBranchProtection(ctx, owner, repo, branch)
	recordResponse(rrc.metrics, rrc.org, rrc.appID, rrc.installationID, rrc.cacheKey, "Repositories.RemoveBranchProtection", resp, err)
	return resp, err
}

func (rrc *RateLimitRepositoriesClient) RequireSignaturesOnProtectedBranch(ctx context.Context, owner, repo, branch string) (*github.SignaturesProtectedBranch, *github.Response, error) {
	return recordRateLimit(ctx, rrc.metrics, rrc.org, rrc.appID, rrc.installationID, rrc.cacheKey, "Repositories.RequireSignaturesOnProtectedBranch", func() (*github.SignaturesProtectedBranch, *github.Response, error) {
		return rrc.RepositoriesClient.RequireSignaturesOnProtectedBranch(ctx, owner, repo, branch)
	})
}

func (rrc *RateLimitRepositoriesClient) OptionalSignaturesOnProtectedBranch(ctx context.Context, owner, repo, branch string) (*github.Response, error) {
	resp, err := rrc.RepositoriesClient.OptionalSignaturesOnProtectedBranch(ctx, owner, repo, branch)
	recordResponse(rrc.metrics, rrc.org, rrc.appID, rrc.installationID, rrc.cacheKey, "Repositories.OptionalSignaturesOnProtectedBranch", resp, err)
	return resp, err
}

func (rrc *RateLimitRepositoriesClient) GetAllRulesets(ctx context.Context, owner, repo string, includesParents bool) ([]*github.Ruleset, *github.Response, error) {
	return recordRateLimit(ctx, rrc.metrics, rrc.org, rrc.appID, rrc.installationID, rrc.cacheKey, "Repositories.GetAllRulesets", func() ([]*github.Ruleset, *github.Response, error) {
		return rrc.RepositoriesClient.GetAllRulesets(ctx, owner, repo, includesParents)
	})
}

func (rrc *RateLimitRepositoriesClient) GetRuleset(ctx context.Context, owner, repo string, rulesetID int64, includesParents bool) (*github.Ruleset, *github.Response, error) {
	return recordRateLimit(ctx, rrc.metrics, rrc.org, rrc.appID, rrc.installationID, rrc.cacheKey, "Repositories.GetRuleset", func() (*github.Ruleset, *github.Response, error) {
		return rrc.RepositoriesClient.GetRuleset(ctx, owner, repo, rulesetID, includesParents)
	})
}

func (rrc *RateLimitRepositoriesClient) CreateRuleset(ctx context.Context, owner, repo string, ruleset *github.Ruleset) (*github.Ruleset, *github.Response, error) {
	return recordRateLimit(ctx, rrc.metrics, rrc.org, rrc.appID, rrc.installationID, rrc.cacheKey, "Repositories.CreateRuleset", func() (*github.Ruleset, *github.Response, error) {
		return rrc.RepositoriesClient.CreateRuleset(ctx, owner, repo, ruleset)
	})
}

func (rrc *RateLimitRepositoriesClient) UpdateRuleset(ctx context.Context, owner, repo string, rulesetID int64, ruleset *github.Ruleset) (*github.Ruleset, *github.Response, error) {
	return recordRateLimit(ctx, rrc.metrics, rrc.org, rrc.appID, rrc.installationID, rrc.cacheKey, "Repositories.UpdateRuleset", func() (*github.Ruleset, *github.Response, error) {
		return rrc.RepositoriesClient.UpdateRuleset(ctx, owner, repo, rulesetID, ruleset)
	})
}

func (rrc *RateLimitRepositoriesClient) DeleteRuleset(ctx context.Context, owner, repo string, rulesetID int64) (*github.Response, error) {
	resp, err := rrc.RepositoriesClient.DeleteRuleset(ctx, owner, repo, rulesetID)
	recordResponse(rrc.metrics, rrc.org, rrc.appID, rrc.installationID, rrc.cacheKey, "Repositories.DeleteRuleset", resp, err)
	return resp, err
}

func (rrc *RateLimitRepositoriesClient) ReplaceAllTopics(ctx context.Context, owner, repo string, topics []string) ([]string, *github.Response, error) {
	return recordRateLimit(ctx, rrc.metrics, rrc.org, rrc.appID, rrc.installationID, rrc.cacheKey, "Repositories.ReplaceAllTopics", func() ([]string, *github.Response, error) {
		return rrc.RepositoriesClient.ReplaceAllTopics(ctx, owner, repo, topics)
	})
}

// RateLimitTeamsClient methods
func (rtc *RateLimitTeamsClient) GetTeamBySlug(ctx context.Context, org, slug string) (*github.Team, *github.Response, error) {
	return recordRateLimit(ctx, rtc.metrics, rtc.org, rtc.appID, rtc.installationID, rtc.cacheKey, "Teams.GetTeamBySlug", func() (*github.Team, *github.Response, error) {
		return rtc.TeamsClient.GetTeamBySlug(ctx, org, slug)
	})
}

func (rtc *RateLimitTeamsClient) CreateTeam(ctx context.Context, org string, team github.NewTeam) (*github.Team, *github.Response, error) {
	return recordRateLimit(ctx, rtc.metrics, rtc.org, rtc.appID, rtc.installationID, rtc.cacheKey, "Teams.CreateTeam", func() (*github.Team, *github.Response, error) {
		return rtc.TeamsClient.CreateTeam(ctx, org, team)
	})
}

func (rtc *RateLimitTeamsClient) EditTeamBySlug(ctx context.Context, org, slug string, team github.NewTeam, removeParent bool) (*github.Team, *github.Response, error) {
	return recordRateLimit(ctx, rtc.metrics, rtc.org, rtc.appID, rtc.installationID, rtc.cacheKey, "Teams.EditTeamBySlug", func() (*github.Team, *github.Response, error) {
		return rtc.TeamsClient.EditTeamBySlug(ctx, org, slug, team, removeParent)
	})
}

func (rtc *RateLimitTeamsClient) DeleteTeamBySlug(ctx context.Context, org, slug string) (*github.Response, error) {
	resp, err := rtc.TeamsClient.DeleteTeamBySlug(ctx, org, slug)
	recordResponse(rtc.metrics, rtc.org, rtc.appID, rtc.installationID, rtc.cacheKey, "Teams.DeleteTeamBySlug", resp, err)
	return resp, err
}

func (rtc *RateLimitTeamsClient) ListTeamMembersBySlug(ctx context.Context, org, slug string, opts *github.TeamListTeamMembersOptions) ([]*github.User, *github.Response, error) {
	return recordRateLimit(ctx, rtc.metrics, rtc.org, rtc.appID, rtc.installationID, rtc.cacheKey, "Teams.ListTeamMembersBySlug", func() ([]*github.User, *github.Response, error) {
		return rtc.TeamsClient.ListTeamMembersBySlug(ctx, org, slug, opts)
	})
}

func (rtc *RateLimitTeamsClient) AddTeamMembershipBySlug(ctx context.Context, org, slug, user string, opts *github.TeamAddTeamMembershipOptions) (*github.Membership, *github.Response, error) {
	return recordRateLimit(ctx, rtc.metrics, rtc.org, rtc.appID, rtc.installationID, rtc.cacheKey, "Teams.AddTeamMembershipBySlug", func() (*github.Membership, *github.Response, error) {
		return rtc.TeamsClient.AddTeamMembershipBySlug(ctx, org, slug, user, opts)
	})
}

func (rtc *RateLimitTeamsClient) RemoveTeamMembershipBySlug(ctx context.Context, org, slug, user string) (*github.Response, error) {
	resp, err := rtc.TeamsClient.RemoveTeamMembershipBySlug(ctx, org, slug, user)
	recordResponse(rtc.metrics, rtc.org, rtc.appID, rtc.installationID, rtc.cacheKey, "Teams.RemoveTeamMembershipBySlug", resp, err)
	return resp, err
}

func (rtc *RateLimitTeamsClient) AddTeamRepoBySlug(ctx context.Context, org, slug, owner, repo string, opts *github.TeamAddTeamRepoOptions) (*github.Response, error) {
	resp, err := rtc.TeamsClient.AddTeamRepoBySlug(ctx, org, slug, owner, repo, opts)
	recordResponse(rtc.metrics, rtc.org, rtc.appID, rtc.installationID, rtc.cacheKey, "Teams.AddTeamRepoBySlug", resp, err)
	return resp, err
}

func (rtc *RateLimitTeamsClient) RemoveTeamRepoBySlug(ctx context.Context, org, slug, owner, repo string) (*github.Response, error) {
	resp, err := rtc.TeamsClient.RemoveTeamRepoBySlug(ctx, org, slug, owner, repo)
	recordResponse(rtc.metrics, rtc.org, rtc.appID, rtc.installationID, rtc.cacheKey, "Teams.RemoveTeamRepoBySlug", resp, err)
	return resp, err
}

// RateLimitUsersClient methods
func (ruc *RateLimitUsersClient) Get(ctx context.Context, user string) (*github.User, *github.Response, error) {
	return recordRateLimit(ctx, ruc.metrics, ruc.org, ruc.appID, ruc.installationID, ruc.cacheKey, "Users.Get", func() (*github.User, *github.Response, error) {
		return ruc.UsersClient.Get(ctx, user)
	})
}

// RateLimitActionsClient methods
func (rac *RateLimitActionsClient) ListEnabledReposInOrg(ctx context.Context, owner string, opts *github.ListOptions) (*github.ActionsEnabledOnOrgRepos, *github.Response, error) {
	return recordRateLimit(ctx, rac.metrics, rac.org, rac.appID, rac.installationID, rac.cacheKey, "Actions.ListEnabledReposInOrg", func() (*github.ActionsEnabledOnOrgRepos, *github.Response, error) {
		return rac.ActionsClient.ListEnabledReposInOrg(ctx, owner, opts)
	})
}

func (rac *RateLimitActionsClient) SetEnabledReposInOrg(ctx context.Context, owner string, repositoryIDs []int64) (*github.Response, error) {
	resp, err := rac.ActionsClient.SetEnabledReposInOrg(ctx, owner, repositoryIDs)
	recordResponse(rac.metrics, rac.org, rac.appID, rac.installationID, rac.cacheKey, "Actions.SetEnabledReposInOrg", resp, err)
	return resp, err
}

func (rac *RateLimitActionsClient) GetOrgSecret(ctx context.Context, org, name string) (*github.Secret, *github.Response, error) {
	return recordRateLimit(ctx, rac.metrics, rac.org, rac.appID, rac.installationID, rac.cacheKey, "Actions.GetOrgSecret", func() (*github.Secret, *github.Response, error) {
		return rac.ActionsClient.GetOrgSecret(ctx, org, name)
	})
}

func (rac *RateLimitActionsClient) ListSelectedReposForOrgSecret(ctx context.Context, org, name string, opts *github.ListOptions) (*github.SelectedReposList, *github.Response, error) {
	return recordRateLimit(ctx, rac.metrics, rac.org, rac.appID, rac.installationID, rac.cacheKey, "Actions.ListSelectedReposForOrgSecret", func() (*github.SelectedReposList, *github.Response, error) {
		return rac.ActionsClient.ListSelectedReposForOrgSecret(ctx, org, name, opts)
	})
}

func (rac *RateLimitActionsClient) SetSelectedReposForOrgSecret(ctx context.Context, org, name string, ids github.SelectedRepoIDs) (*github.Response, error) {
	resp, err := rac.ActionsClient.SetSelectedReposForOrgSecret(ctx, org, name, ids)
	recordResponse(rac.metrics, rac.org, rac.appID, rac.installationID, rac.cacheKey, "Actions.SetSelectedReposForOrgSecret", resp, err)
	return resp, err
}

func (rac *RateLimitActionsClient) GetOrgVariable(ctx context.Context, org, name string) (*github.ActionsVariable, *github.Response, error) {
	return recordRateLimit(ctx, rac.metrics, rac.org, rac.appID, rac.installationID, rac.cacheKey, "Actions.GetOrgVariable", func() (*github.ActionsVariable, *github.Response, error) {
		return rac.ActionsClient.GetOrgVariable(ctx, org, name)
	})
}

func (rac *RateLimitActionsClient) CreateOrgVariable(ctx context.Context, org string, variable *github.ActionsVariable) (*github.Response, error) {
	resp, err := rac.ActionsClient.CreateOrgVariable(ctx, org, variable)
	recordResponse(rac.metrics, rac.org, rac.appID, rac.installationID, rac.cacheKey, "Actions.CreateOrgVariable", resp, err)
	return resp, err
}

func (rac *RateLimitActionsClient) UpdateOrgVariable(ctx context.Context, org string, variable *github.ActionsVariable) (*github.Response, error) {
	resp, err := rac.ActionsClient.UpdateOrgVariable(ctx, org, variable)
	recordResponse(rac.metrics, rac.org, rac.appID, rac.installationID, rac.cacheKey, "Actions.UpdateOrgVariable", resp, err)
	return resp, err
}

func (rac *RateLimitActionsClient) DeleteOrgVariable(ctx context.Context, org, name string) (*github.Response, error) {
	resp, err := rac.ActionsClient.DeleteOrgVariable(ctx, org, name)
	recordResponse(rac.metrics, rac.org, rac.appID, rac.installationID, rac.cacheKey, "Actions.DeleteOrgVariable", resp, err)
	return resp, err
}

func (rac *RateLimitActionsClient) ListSelectedReposForOrgVariable(ctx context.Context, org, name string, opts *github.ListOptions) (*github.SelectedReposList, *github.Response, error) {
	return recordRateLimit(ctx, rac.metrics, rac.org, rac.appID, rac.installationID, rac.cacheKey, "Actions.ListSelectedReposForOrgVariable", func() (*github.SelectedReposList, *github.Response, error) {
		return rac.ActionsClient.ListSelectedReposForOrgVariable(ctx, org, name, opts)
	})
}

func (rac *RateLimitActionsClient) SetSelectedReposForOrgVariable(ctx context.Context, org, name string, ids github.SelectedRepoIDs) (*github.Response, error) {
	resp, err := rac.ActionsClient.SetSelectedReposForOrgVariable(ctx, org, name, ids)
	recordResponse(rac.metrics, rac.org, rac.appID, rac.installationID, rac.cacheKey, "Actions.SetSelectedReposForOrgVariable", resp, err)
	return resp, err
}

// RateLimitDependabotClient methods
func (rdc *RateLimitDependabotClient) GetOrgSecret(ctx context.Context, org, name string) (*github.Secret, *github.Response, error) {
	return recordRateLimit(ctx, rdc.metrics, rdc.org, rdc.appID, rdc.installationID, rdc.cacheKey, "Dependabot.GetOrgSecret", func() (*github.Secret, *github.Response, error) {
		return rdc.DependabotClient.GetOrgSecret(ctx, org, name)
	})
}

func (rdc *RateLimitDependabotClient) ListSelectedReposForOrgSecret(ctx context.Context, org, name string, opts *github.ListOptions) (*github.SelectedReposList, *github.Response, error) {
	return recordRateLimit(ctx, rdc.metrics, rdc.org, rdc.appID, rdc.installationID, rdc.cacheKey, "Dependabot.ListSelectedReposForOrgSecret", func() (*github.SelectedReposList, *github.Response, error) {
		return rdc.DependabotClient.ListSelectedReposForOrgSecret(ctx, org, name, opts)
	})
}

func (rdc *RateLimitDependabotClient) SetSelectedReposForOrgSecret(ctx context.Context, org, name string, ids github.DependabotSecretsSelectedRepoIDs) (*github.Response, error) {
	resp, err := rdc.DependabotClient.SetSelectedReposForOrgSecret(ctx, org, name, ids)
	recordResponse(rdc.metrics, rdc.org, rdc.appID, rdc.installationID, rdc.cacheKey, "Dependabot.SetSelectedReposForOrgSecret", resp, err)
	return resp, err
}
