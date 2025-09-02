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

// WithRateLimitTracking returns a new RateLimitClient with the specified organization
func (rc *RateLimitClient) WithRateLimitTracking(org string) *RateLimitClient {
	return &RateLimitClient{
		Client: &Client{
			Actions: &RateLimitActionsClient{
				ActionsClient: rc.Actions,
				metrics:       rc.metrics,
				org:           org,
			},
			Dependabot: &RateLimitDependabotClient{
				DependabotClient: rc.Dependabot,
				metrics:          rc.metrics,
				org:              org,
			},
			Organizations: &RateLimitOrganizationsClient{
				OrganizationsClient: rc.Organizations,
				metrics:             rc.metrics,
				org:                 org,
			},
			Users: &RateLimitUsersClient{
				UsersClient: rc.Users,
				metrics:     rc.metrics,
				org:         org,
			},
			Teams: &RateLimitTeamsClient{
				TeamsClient: rc.Teams,
				metrics:     rc.metrics,
				org:         org,
			},
			Repositories: &RateLimitRepositoriesClient{
				RepositoriesClient: rc.Repositories,
				metrics:            rc.metrics,
				org:                org,
			},
		},
		metrics: rc.metrics,
	}
}

// recordRateLimit is a helper function to record only rate limit metrics
func recordRateLimit[T any](
	ctx context.Context,
	metrics *telemetry.RateLimitMetrics,
	org string,
	fn func() (T, *github.Response, error),
) (T, *github.Response, error) {
	result, resp, err := fn()

	// Record only rate limit information
	metrics.RecordRateLimitInfo(resp, org)

	return result, resp, err
}

// RateLimitActionsClient wraps the Actions client with rate limit tracking
type RateLimitActionsClient struct {
	ActionsClient
	metrics *telemetry.RateLimitMetrics
	org     string
}

// RateLimitOrganizationsClient wraps the Organizations client with rate limit tracking
type RateLimitOrganizationsClient struct {
	OrganizationsClient
	metrics *telemetry.RateLimitMetrics
	org     string
}

// RateLimitRepositoriesClient wraps the Repositories client with rate limit tracking
type RateLimitRepositoriesClient struct {
	RepositoriesClient
	metrics *telemetry.RateLimitMetrics
	org     string
}

// RateLimitTeamsClient wraps the Teams client with rate limit tracking
type RateLimitTeamsClient struct {
	TeamsClient
	metrics *telemetry.RateLimitMetrics
	org     string
}

// RateLimitUsersClient wraps the Users client with rate limit tracking
type RateLimitUsersClient struct {
	UsersClient
	metrics *telemetry.RateLimitMetrics
	org     string
}

// RateLimitDependabotClient wraps the Dependabot client with rate limit tracking
type RateLimitDependabotClient struct {
	DependabotClient
	metrics *telemetry.RateLimitMetrics
	org     string
}

// Sample implementations for key methods - only tracking rate limits

// RateLimitOrganizationsClient methods
func (roc *RateLimitOrganizationsClient) Get(ctx context.Context, org string) (*github.Organization, *github.Response, error) {
	return recordRateLimit(ctx, roc.metrics, roc.org, func() (*github.Organization, *github.Response, error) {
		return roc.OrganizationsClient.Get(ctx, org)
	})
}

func (roc *RateLimitOrganizationsClient) Edit(ctx context.Context, name string, org *github.Organization) (*github.Organization, *github.Response, error) {
	return recordRateLimit(ctx, roc.metrics, roc.org, func() (*github.Organization, *github.Response, error) {
		return roc.OrganizationsClient.Edit(ctx, name, org)
	})
}

func (roc *RateLimitOrganizationsClient) GetOrgMembership(ctx context.Context, user, org string) (*github.Membership, *github.Response, error) {
	return recordRateLimit(ctx, roc.metrics, roc.org, func() (*github.Membership, *github.Response, error) {
		return roc.OrganizationsClient.GetOrgMembership(ctx, user, org)
	})
}

func (roc *RateLimitOrganizationsClient) CreateOrgInvitation(ctx context.Context, org string, opts *github.CreateOrgInvitationOptions) (*github.Invitation, *github.Response, error) {
	return recordRateLimit(ctx, roc.metrics, roc.org, func() (*github.Invitation, *github.Response, error) {
		return roc.OrganizationsClient.CreateOrgInvitation(ctx, org, opts)
	})
}

func (roc *RateLimitOrganizationsClient) EditOrgMembership(ctx context.Context, user, org string, membership *github.Membership) (*github.Membership, *github.Response, error) {
	return recordRateLimit(ctx, roc.metrics, roc.org, func() (*github.Membership, *github.Response, error) {
		return roc.OrganizationsClient.EditOrgMembership(ctx, user, org, membership)
	})
}

func (roc *RateLimitOrganizationsClient) RemoveOrgMembership(ctx context.Context, user, org string) (*github.Response, error) {
	resp, err := roc.OrganizationsClient.RemoveOrgMembership(ctx, user, org)
	roc.metrics.RecordRateLimitInfo(resp, roc.org)
	return resp, err
}

// RateLimitRepositoriesClient methods
func (rrc *RateLimitRepositoriesClient) Get(ctx context.Context, owner, repo string) (*github.Repository, *github.Response, error) {
	return recordRateLimit(ctx, rrc.metrics, rrc.org, func() (*github.Repository, *github.Response, error) {
		return rrc.RepositoriesClient.Get(ctx, owner, repo)
	})
}

func (rrc *RateLimitRepositoriesClient) Edit(ctx context.Context, owner, repo string, repository *github.Repository) (*github.Repository, *github.Response, error) {
	return recordRateLimit(ctx, rrc.metrics, rrc.org, func() (*github.Repository, *github.Response, error) {
		return rrc.RepositoriesClient.Edit(ctx, owner, repo, repository)
	})
}

func (rrc *RateLimitRepositoriesClient) Create(ctx context.Context, org string, repo *github.Repository) (*github.Repository, *github.Response, error) {
	return recordRateLimit(ctx, rrc.metrics, rrc.org, func() (*github.Repository, *github.Response, error) {
		return rrc.RepositoriesClient.Create(ctx, org, repo)
	})
}

func (rrc *RateLimitRepositoriesClient) Delete(ctx context.Context, owner, repo string) (*github.Response, error) {
	resp, err := rrc.RepositoriesClient.Delete(ctx, owner, repo)
	rrc.metrics.RecordRateLimitInfo(resp, rrc.org)
	return resp, err
}

// RateLimitTeamsClient methods
func (rtc *RateLimitTeamsClient) GetTeamBySlug(ctx context.Context, org, slug string) (*github.Team, *github.Response, error) {
	return recordRateLimit(ctx, rtc.metrics, rtc.org, func() (*github.Team, *github.Response, error) {
		return rtc.TeamsClient.GetTeamBySlug(ctx, org, slug)
	})
}

func (rtc *RateLimitTeamsClient) CreateTeam(ctx context.Context, org string, team github.NewTeam) (*github.Team, *github.Response, error) {
	return recordRateLimit(ctx, rtc.metrics, rtc.org, func() (*github.Team, *github.Response, error) {
		return rtc.TeamsClient.CreateTeam(ctx, org, team)
	})
}

func (rtc *RateLimitTeamsClient) EditTeamBySlug(ctx context.Context, org, slug string, team github.NewTeam, removeParent bool) (*github.Team, *github.Response, error) {
	return recordRateLimit(ctx, rtc.metrics, rtc.org, func() (*github.Team, *github.Response, error) {
		return rtc.TeamsClient.EditTeamBySlug(ctx, org, slug, team, removeParent)
	})
}

func (rtc *RateLimitTeamsClient) DeleteTeamBySlug(ctx context.Context, org, slug string) (*github.Response, error) {
	resp, err := rtc.TeamsClient.DeleteTeamBySlug(ctx, org, slug)
	rtc.metrics.RecordRateLimitInfo(resp, rtc.org)
	return resp, err
}

// RateLimitUsersClient methods
func (ruc *RateLimitUsersClient) Get(ctx context.Context, user string) (*github.User, *github.Response, error) {
	return recordRateLimit(ctx, ruc.metrics, ruc.org, func() (*github.User, *github.Response, error) {
		return ruc.UsersClient.Get(ctx, user)
	})
}

// RateLimitActionsClient methods
func (rac *RateLimitActionsClient) ListEnabledReposInOrg(ctx context.Context, owner string, opts *github.ListOptions) (*github.ActionsEnabledOnOrgRepos, *github.Response, error) {
	return recordRateLimit(ctx, rac.metrics, rac.org, func() (*github.ActionsEnabledOnOrgRepos, *github.Response, error) {
		return rac.ActionsClient.ListEnabledReposInOrg(ctx, owner, opts)
	})
}

func (rac *RateLimitActionsClient) AddEnabledReposInOrg(ctx context.Context, owner string, repositoryID int64) (*github.Response, error) {
	resp, err := rac.ActionsClient.AddEnabledReposInOrg(ctx, owner, repositoryID)
	rac.metrics.RecordRateLimitInfo(resp, rac.org)
	return resp, err
}

func (rac *RateLimitActionsClient) RemoveEnabledReposInOrg(ctx context.Context, owner string, repositoryID int64) (*github.Response, error) {
	resp, err := rac.ActionsClient.RemoveEnabledReposInOrg(ctx, owner, repositoryID)
	rac.metrics.RecordRateLimitInfo(resp, rac.org)
	return resp, err
}

func (rac *RateLimitActionsClient) GetOrgSecret(ctx context.Context, org, name string) (*github.Secret, *github.Response, error) {
	return recordRateLimit(ctx, rac.metrics, rac.org, func() (*github.Secret, *github.Response, error) {
		return rac.ActionsClient.GetOrgSecret(ctx, org, name)
	})
}

func (rac *RateLimitActionsClient) ListSelectedReposForOrgSecret(ctx context.Context, org, name string, opts *github.ListOptions) (*github.SelectedReposList, *github.Response, error) {
	return recordRateLimit(ctx, rac.metrics, rac.org, func() (*github.SelectedReposList, *github.Response, error) {
		return rac.ActionsClient.ListSelectedReposForOrgSecret(ctx, org, name, opts)
	})
}

func (rac *RateLimitActionsClient) SetSelectedReposForOrgSecret(ctx context.Context, org, name string, ids github.SelectedRepoIDs) (*github.Response, error) {
	resp, err := rac.ActionsClient.SetSelectedReposForOrgSecret(ctx, org, name, ids)
	rac.metrics.RecordRateLimitInfo(resp, rac.org)
	return resp, err
}

// RateLimitDependabotClient methods
func (rdc *RateLimitDependabotClient) GetOrgSecret(ctx context.Context, org, name string) (*github.Secret, *github.Response, error) {
	return recordRateLimit(ctx, rdc.metrics, rdc.org, func() (*github.Secret, *github.Response, error) {
		return rdc.DependabotClient.GetOrgSecret(ctx, org, name)
	})
}

func (rdc *RateLimitDependabotClient) ListSelectedReposForOrgSecret(ctx context.Context, org, name string, opts *github.ListOptions) (*github.SelectedReposList, *github.Response, error) {
	return recordRateLimit(ctx, rdc.metrics, rdc.org, func() (*github.SelectedReposList, *github.Response, error) {
		return rdc.DependabotClient.ListSelectedReposForOrgSecret(ctx, org, name, opts)
	})
}

func (rdc *RateLimitDependabotClient) SetSelectedReposForOrgSecret(ctx context.Context, org, name string, ids github.DependabotSecretsSelectedRepoIDs) (*github.Response, error) {
	resp, err := rdc.DependabotClient.SetSelectedReposForOrgSecret(ctx, org, name, ids)
	rdc.metrics.RecordRateLimitInfo(resp, rdc.org)
	return resp, err
}
