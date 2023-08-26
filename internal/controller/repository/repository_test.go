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
	"github.com/google/go-github/v54/github"
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
	repo = "test-repo"

	user1     = "test-user-1"
	user1Role = "admin"
	user2     = "test-user-1"
	user2Role = "pull"

	team1     = "test-team-1"
	team1Role = "admin"
	team2     = "test-team-2"
	team2Role = "pull"
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
	meta.SetExternalName(cr, repo)

	for _, f := range m {
		f(cr)
	}
	return cr
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
							return nil, nil, nil
						},
						MockListCollaborators: func(ctx context.Context, owner, repo string, opts *github.ListCollaboratorsOptions) ([]*github.User, *github.Response, error) {
							return githubCollaborators(), fake.GenerateEmptyResponse(), nil
						},
						MockListTeams: func(ctx context.Context, owner string, repo string, opts *github.ListOptions) ([]*github.Team, *github.Response, error) {
							return githubTeams(), fake.GenerateEmptyResponse(), nil
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
							return nil, nil, nil
						},
						MockListCollaborators: func(ctx context.Context, owner, repo string, opts *github.ListCollaboratorsOptions) ([]*github.User, *github.Response, error) {
							return githubCollaborators(), fake.GenerateEmptyResponse(), nil
						},
						MockListTeams: func(ctx context.Context, owner string, repo string, opts *github.ListOptions) ([]*github.Team, *github.Response, error) {
							return githubTeams(), fake.GenerateEmptyResponse(), nil
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
