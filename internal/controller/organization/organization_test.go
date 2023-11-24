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
	"testing"

	"github.com/crossplane/provider-github/apis/organizations/v1alpha1"
	ghclient "github.com/crossplane/provider-github/internal/clients"
	"github.com/crossplane/provider-github/internal/clients/fake"
	"github.com/google/go-cmp/cmp"

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

var (
	org              = "test-org"
	description      = "test description"
	otherDescription = "other description"
	repo             = "test-repo"
	repo2            = "test-repo2"
)

type organizationModifier func(*v1alpha1.Organization)

func withDescription() organizationModifier {
	return func(r *v1alpha1.Organization) {
		r.Spec.ForProvider.Description = otherDescription
	}
}

func organization(repos []string, m ...organizationModifier) *v1alpha1.Organization {
	cr := &v1alpha1.Organization{}

	cr.Spec.ForProvider.Description = description
	cr.Spec.ForProvider.Actions = v1alpha1.ActionsConfiguration{
		EnabledRepos: make([]v1alpha1.ActionEnabledRepo, len(repos)),
	}
	for i, repo := range repos {
		cr.Spec.ForProvider.Actions.EnabledRepos[i] = v1alpha1.ActionEnabledRepo{
			Repo: repo,
		}
	}

	meta.SetExternalName(cr, org)

	for _, f := range m {
		f(cr)
	}
	return cr
}

func githubOrganization() *github.Organization {
	return &github.Organization{
		Description: &description,
		Name:        &org,
	}
}

func githubOrgRepoActions() *github.ActionsEnabledOnOrgRepos {
	repos := []*github.Repository{
		{Name: &repo},
		{Name: &repo2},
	}
	return &github.ActionsEnabledOnOrgRepos{Repositories: repos}
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
					Organizations: &fake.MockOrganizationsClient{
						MockGet: func(ctx context.Context, org string) (*github.Organization, *github.Response, error) {
							return githubOrganization(), nil, nil
						},
					},
					Actions: &fake.MockActionsClient{
						MockListEnabledReposInOrg: func(ctx context.Context, owner string, opts *github.ListOptions) (*github.ActionsEnabledOnOrgRepos, *github.Response, error) {
							return githubOrgRepoActions(), nil, nil
						},
					},
				},
			},
			args: args{
				mg: organization([]string{repo, repo2}, withDescription()),
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
					Organizations: &fake.MockOrganizationsClient{
						MockGet: func(ctx context.Context, org string) (*github.Organization, *github.Response, error) {
							return githubOrganization(), nil, nil
						},
					},
					Actions: &fake.MockActionsClient{
						MockListEnabledReposInOrg: func(ctx context.Context, owner string, opts *github.ListOptions) (*github.ActionsEnabledOnOrgRepos, *github.Response, error) {
							return githubOrgRepoActions(), nil, nil
						},
					},
				},
			},
			args: args{
				mg: organization([]string{repo, repo2}),
			},
			want: want{
				o: managed.ExternalObservation{
					ResourceExists:   true,
					ResourceUpToDate: true,
				},
				err: nil,
			},
		},
		"DoesNotExists": {
			fields: fields{
				github: &ghclient.Client{
					Organizations: &fake.MockOrganizationsClient{
						MockGet: func(ctx context.Context, org string) (*github.Organization, *github.Response, error) {
							return nil, nil, fake.Generate404Response()
						},
					},
					Actions: &fake.MockActionsClient{
						MockListEnabledReposInOrg: func(ctx context.Context, owner string, opts *github.ListOptions) (*github.ActionsEnabledOnOrgRepos, *github.Response, error) {
							return nil, nil, fake.Generate404Response()
						},
					},
				},
			},
			args: args{
				mg: organization([]string{repo, repo2}),
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
