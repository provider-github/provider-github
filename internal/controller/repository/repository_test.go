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
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/crossplane/provider-github/apis/organizations/v1alpha1"
	ghclient "github.com/crossplane/provider-github/internal/clients"
	"github.com/crossplane/provider-github/internal/clients/fake"

	"github.com/crossplane/crossplane-runtime/pkg/meta"
	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/pkg/resource"
	"github.com/crossplane/crossplane-runtime/pkg/test"
	"github.com/google/go-github/v58/github"
)

// Unlike many Kubernetes projects Crossplane does not use third party testing
// libraries, per the common Go test review comments. Crossplane encourages the
// use of table driven unit tests. The tests of the crossplane-runtime project
// are representative of the testing style Crossplane encourages.
//
// https://github.com/golang/go/wiki/TestComments
// https://github.com/crossplane/crossplane/blob/master/CONTRIBUTING.md#contributing-code

type repositoryModifier func(*v1alpha1.Repository)

var (
	repo        = "test-repo"
	description = "desc"
	archived    = false
	private     = true

	user1     = "test-user-1"
	user1Role = "admin"
	user2     = "test-user-1"
	user2Role = "pull"

	team1     = "test-team-1"
	team1Role = "admin"
	team2     = "test-team-2"
	team2Role = "pull"

	webhook1url            = "https://example.org/webhook"
	webhook1active         = true
	webhook1InsecureSsl    = false
	webhook1InsecureSslStr = "0"
	webhook1ContentType    = "json"
	webhook1event1         = "push"
	webhook1event2         = "workflow_job"

	bpr1branch                         = "main"
	bpr1enforceAdmins                  = true
	bpr1requireLinearHistory           = true
	bpr1allowForcePushes               = false
	bpr1allowDeletions                 = false
	bpr1requiredConversationResolution = true
	bpr1blockCreations                 = true
	bpr1lockBranch                     = false
	bpr1allowForkSyncing               = false
	bpr1requireSignedCommits           = false
	bpr1requiredStatusCheck            = "terraform_validate"
)

func withTeamPermission() repositoryModifier {
	return func(r *v1alpha1.Repository) {
		r.Spec.ForProvider.Permissions.Teams[1].Role = team1Role
	}
}

func repository(m ...repositoryModifier) *v1alpha1.Repository {
	cr := &v1alpha1.Repository{}
	cr.Spec.ForProvider.Permissions = v1alpha1.RepositoryPermissions{
		Users: []v1alpha1.RepositoryUser{
			{
				User: user1,
				Role: user1Role,
			},
			{
				User: user2,
				Role: user2Role,
			},
		},
		Teams: []v1alpha1.RepositoryTeam{
			{
				Team: team1,
				Role: team1Role,
			},
			{
				Team: team2,
				Role: team2Role,
			},
		},
	}

	cr.Spec.ForProvider.Webhooks = []v1alpha1.RepositoryWebhook{
		{
			Url:         webhook1url,
			ContentType: webhook1ContentType,
			Events:      []string{webhook1event1, webhook1event2},
			InsecureSsl: webhook1InsecureSsl,
			Active:      webhook1active,
		},
	}

	cr.Spec.ForProvider.BranchProtectionRules = []v1alpha1.BranchProtectionRule{
		{
			Branch:                         bpr1branch,
			EnforceAdmins:                  bpr1enforceAdmins,
			RequireLinearHistory:           bpr1requireLinearHistory,
			AllowForcePushes:               bpr1allowForcePushes,
			AllowDeletions:                 bpr1allowDeletions,
			RequiredConversationResolution: bpr1requiredConversationResolution,
			BlockCreations:                 bpr1blockCreations,
			LockBranch:                     bpr1lockBranch,
			AllowForkSyncing:               bpr1allowForkSyncing,
			RequireSignedCommits:           bpr1requireSignedCommits,
			RequiredStatusChecks: &v1alpha1.RequiredStatusChecks{
				Strict: true,
				Checks: []*v1alpha1.RequiredStatusCheck{
					{
						Context: bpr1requiredStatusCheck,
					},
				},
			},
		},
	}

	meta.SetExternalName(cr, repo)

	for _, f := range m {
		f(cr)
	}
	return cr
}

func githubRepository() *github.Repository {
	return &github.Repository{
		Name:        &repo,
		Description: &description,
		Archived:    &archived,
		Private:     &private,
	}
}

func githubWebhooks() []*github.Hook {
	return []*github.Hook{
		{
			Config: map[string]interface{}{
				"url":          webhook1url,
				"content_type": webhook1ContentType,
				"insecure_ssl": webhook1InsecureSslStr,
			},
			Events: []string{webhook1event1, webhook1event2},
			Active: github.Bool(webhook1active),
		},
	}
}

func githubProtectedBranch() *github.Protection {
	return &github.Protection{
		RequiredStatusChecks: &github.RequiredStatusChecks{
			Strict: true,
			Checks: []*github.RequiredStatusCheck{
				{
					Context: bpr1requiredStatusCheck,
				},
			},
		},
		EnforceAdmins: &github.AdminEnforcement{
			Enabled: bpr1enforceAdmins,
		},
		RequireLinearHistory: &github.RequireLinearHistory{
			Enabled: bpr1requireLinearHistory,
		},
		AllowForcePushes: &github.AllowForcePushes{
			Enabled: bpr1allowForcePushes,
		},
		AllowDeletions: &github.AllowDeletions{
			Enabled: bpr1allowDeletions,
		},
		RequiredConversationResolution: &github.RequiredConversationResolution{
			Enabled: bpr1requiredConversationResolution,
		},
		BlockCreations: &github.BlockCreations{
			Enabled: &bpr1blockCreations,
		},
		LockBranch: &github.LockBranch{
			Enabled: &bpr1lockBranch,
		},
		AllowForkSyncing: &github.AllowForkSyncing{
			Enabled: &bpr1allowForkSyncing,
		},
		RequiredSignatures: &github.SignaturesProtectedBranch{
			Enabled: &bpr1requireSignedCommits,
		},
	}
}

func githubCollaborators() []*github.User {
	return []*github.User{
		{
			Login: &user1,
			Permissions: map[string]bool{
				user1Role: true,
			},
		},
		{
			Login: &user2,
			Permissions: map[string]bool{
				user2Role: true,
			},
		},
	}
}

func githubTeams() []*github.Team {
	return []*github.Team{
		{
			Slug:       &team1,
			Permission: &team1Role,
		},
		{
			Slug:       &team2,
			Permission: &team2Role,
		},
	}
}

func githubBranches() []*github.Branch {
	return []*github.Branch{
		{
			Name:      &bpr1branch,
			Protected: github.Bool(true),
		},
	}
}

func TestObserve(t *testing.T) {
	type fields struct {
		github *ghclient.Client
	}

	type args struct {
		ctx context.Context
		mg  resource.Managed
	}

	type want struct {
		o   managed.ExternalObservation
		err error
	}

	cases := map[string]struct {
		reason string
		fields fields
		args   args
		want   want
	}{
		"NotUpToDate": {
			fields: fields{
				github: &ghclient.Client{
					Repositories: &fake.MockRepositoriesClient{
						MockGet: func(ctx context.Context, owner, repo string) (*github.Repository, *github.Response, error) {
							return githubRepository(), nil, nil
						},
						MockEdit: func(ctx context.Context, owner, repo string, repository *github.Repository) (*github.Repository, *github.Response, error) {
							return nil, nil, nil
						},
						MockListCollaborators: func(ctx context.Context, owner, repo string, opts *github.ListCollaboratorsOptions) ([]*github.User, *github.Response, error) {
							return githubCollaborators(), fake.GenerateEmptyResponse(), nil
						},
						MockListTeams: func(ctx context.Context, owner string, repo string, opts *github.ListOptions) ([]*github.Team, *github.Response, error) {
							return githubTeams(), fake.GenerateEmptyResponse(), nil
						},
						MockListHooks: func(ctx context.Context, owner, repo string, opts *github.ListOptions) ([]*github.Hook, *github.Response, error) {
							return []*github.Hook{}, fake.GenerateEmptyResponse(), nil
						},
						MockListBranches: func(ctx context.Context, owner, repo string, opts *github.BranchListOptions) ([]*github.Branch, *github.Response, error) {
							return []*github.Branch{}, fake.GenerateEmptyResponse(), nil
						},
					},
				},
			},
			args: args{
				mg: repository(withTeamPermission()),
			},
			want: want{
				o: managed.ExternalObservation{
					ResourceExists:   true,
					ResourceUpToDate: false,
				},
				err: nil,
			},
		},
		"UpToDate": {
			fields: fields{
				github: &ghclient.Client{
					Repositories: &fake.MockRepositoriesClient{
						MockGet: func(ctx context.Context, owner, repo string) (*github.Repository, *github.Response, error) {
							return githubRepository(), nil, nil
						},
						MockEdit: func(ctx context.Context, owner, repo string, repository *github.Repository) (*github.Repository, *github.Response, error) {
							return nil, nil, nil
						},
						MockListCollaborators: func(ctx context.Context, owner, repo string, opts *github.ListCollaboratorsOptions) ([]*github.User, *github.Response, error) {
							return githubCollaborators(), fake.GenerateEmptyResponse(), nil
						},
						MockListTeams: func(ctx context.Context, owner string, repo string, opts *github.ListOptions) ([]*github.Team, *github.Response, error) {
							return githubTeams(), fake.GenerateEmptyResponse(), nil
						},
						MockListHooks: func(ctx context.Context, owner, repo string, opts *github.ListOptions) ([]*github.Hook, *github.Response, error) {
							return githubWebhooks(), fake.GenerateEmptyResponse(), nil
						},
						MockListBranches: func(ctx context.Context, owner, repo string, opts *github.BranchListOptions) ([]*github.Branch, *github.Response, error) {
							return githubBranches(), fake.GenerateEmptyResponse(), nil
						},
						MockGetBranchProtection: func(ctx context.Context, owner, repo, branch string) (*github.Protection, *github.Response, error) {
							return githubProtectedBranch(), fake.GenerateEmptyResponse(), nil
						},
					},
				},
			},
			args: args{
				mg: repository(),
			},
			want: want{
				o: managed.ExternalObservation{
					ResourceExists:   true,
					ResourceUpToDate: true,
				},
				err: nil,
			},
		},
		"DoesNotExist": {
			fields: fields{
				github: &ghclient.Client{
					Repositories: &fake.MockRepositoriesClient{
						MockGet: func(ctx context.Context, owner, repo string) (*github.Repository, *github.Response, error) {
							return nil, nil, fake.Generate404Response()
						},
					},
				},
			},
			args: args{
				mg: repository(),
			},
			want: want{
				o: managed.ExternalObservation{
					ResourceExists:   false,
					ResourceUpToDate: false,
				},
				err: nil,
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := external{github: tc.fields.github}
			got, err := e.Observe(tc.args.ctx, tc.args.mg)
			if diff := cmp.Diff(tc.want.err, err, test.EquateErrors()); diff != "" {
				t.Errorf("\n%s\ne.Observe(...): -want error, +got error:\n%s\n", tc.reason, diff)
			}
			if diff := cmp.Diff(tc.want.o, got); diff != "" {
				t.Errorf("\n%s\ne.Observe(...): -want, +got:\n%s\n", tc.reason, diff)
			}
		})
	}
}
