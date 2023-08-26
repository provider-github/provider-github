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

package team

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-github/v54/github"

	"github.com/crossplane/provider-github/apis/organizations/v1alpha1"
	ghclient "github.com/crossplane/provider-github/internal/clients"
	"github.com/crossplane/provider-github/internal/clients/fake"

	"github.com/crossplane/crossplane-runtime/pkg/meta"
	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/pkg/resource"
	"github.com/crossplane/crossplane-runtime/pkg/test"
)

// Unlike many Kubernetes projects Crossplane does not use third party testing
// libraries, per the common Go test review comments. Crossplane encourages the
// use of table driven unit tests. The tests of the crossplane-runtime project
// are representative of the testing style Crossplane encourages.
//
// https://github.com/golang/go/wiki/TestComments
// https://github.com/crossplane/crossplane/blob/master/CONTRIBUTING.md#contributing-code

var (
	teamPrivacy     = "secret"
	teamDescription = "description"

	member1     = "test-user-1"
	member1Role = "maintainer"
	member2     = "test-user-2"
	member2Role = "member"
)

type teamModifier func(*v1alpha1.Team)

// func withProperty() teamModifier {
// 	return func(r *v1alpha1.Team) {
// 		r.Spec.ForProvider.ConfigurableField = "value"
// 	}
// }

func team(m ...teamModifier) *v1alpha1.Team {
	cr := &v1alpha1.Team{}

	cr.Spec.ForProvider.Description = teamDescription
	cr.Spec.ForProvider.Members = []v1alpha1.TeamMemberUser{
		{
			User: member1,
			Role: member1Role,
		},
		{
			User: member2,
			Role: member2Role,
		},
	}

	meta.SetExternalName(cr, "")

	for _, f := range m {
		f(cr)
	}
	return cr
}

func githubTeam(role string) []*github.User {
	if role == "maintainer" {
		return []*github.User{
			{
				Login: &member1,
			},
		}
	}

	// Role is member here because there are only
	// member and maintainer
	return []*github.User{
		{
			Login: &member2,
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
		"UpToDate": {
			fields: fields{
				github: &ghclient.Client{
					Teams: &fake.MockTeamsClient{
						MockGetTeamBySlug: func(ctx context.Context, org, slug string) (*github.Team, *github.Response, error) {
							return &github.Team{
								Privacy:     &teamPrivacy,
								Description: &teamDescription,
							}, nil, nil
						},
						MockListTeamMembersBySlug: func(ctx context.Context, org, slug string, opts *github.TeamListTeamMembersOptions) ([]*github.User, *github.Response, error) {
							return githubTeam(opts.Role), fake.GenerateEmptyResponse(), nil
						},
					},
				},
			},
			args: args{
				mg: team(),
			},
			want: want{
				o: managed.ExternalObservation{
					ResourceExists:   true,
					ResourceUpToDate: true,
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
