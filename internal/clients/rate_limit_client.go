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

func (rac *RateLimitActionsClient) AddEnabledReposInOrg(ctx context.Context, owner string, repositoryID int64) (*github.Response, error) {
	resp, err := rac.ActionsClient.AddEnabledReposInOrg(ctx, owner, repositoryID)
	recordResponse(rac.metrics, rac.org, rac.appID, rac.installationID, rac.cacheKey, "Actions.AddEnabledReposInOrg", resp, err)
	return resp, err
}

func (rac *RateLimitActionsClient) RemoveEnabledReposInOrg(ctx context.Context, owner string, repositoryID int64) (*github.Response, error) {
	resp, err := rac.ActionsClient.RemoveEnabledReposInOrg(ctx, owner, repositoryID)
	recordResponse(rac.metrics, rac.org, rac.appID, rac.installationID, rac.cacheKey, "Actions.RemoveEnabledReposInOrg", resp, err)
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
