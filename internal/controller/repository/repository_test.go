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
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/crossplane/provider-github/apis/organizations/v1alpha1"
	ghclient "github.com/crossplane/provider-github/internal/clients"
	"github.com/crossplane/provider-github/internal/clients/fake"

	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	"github.com/crossplane/crossplane-runtime/pkg/meta"
	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/pkg/resource"
	"github.com/crossplane/crossplane-runtime/pkg/test"
	"github.com/google/go-github/v62/github"
	corev1 "k8s.io/api/core/v1"
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
	isTemplate  = false

	user1     = "test-user-1"
	user1Role = "admin"
	user2     = "test-user-1"
	user2Role = "pull"

	team1     = "test-team-1"
	team1Role = "admin"
	team2     = "test-team-2"
	team2Role = "pull"

	githubApp1 = "my-awesome-app"

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
	bpr1lockBranch                     = false
	bpr1allowForkSyncing               = false
	bpr1requireSignedCommits           = false
	bpr1requiredStatusCheck            = "terraform_validate"

	rr1Id                         int64 = 123
	rr1name                             = "test-ruleset-1"
	rr1target                           = "branch"
	rr1enforcement                      = "active"
	rr1actorType                        = "Team"
	rr1bypassMode                       = "always"
	rr1rulesCreation                    = true
	rr1rulesDeletion                    = true
	rr1rulesUpdate                      = true
	rr1rulesRequiredLinearHistory       = true
	rr1rulesRequiredSignatures          = true
	rr1rulesNonFastForward              = true
	rr1actorId                    int64 = 123
	rr1Include                          = []string{"include"}
	rr1Exclude                          = []string{"exclude"}

	topic1 = "go"
	topic2 = "kubernetes"
	topic3 = "crossplane"
)

func withTeamPermission() repositoryModifier {
	return func(r *v1alpha1.Repository) {
		r.Spec.ForProvider.Permissions.Teams[1].Role = team1Role
	}
}

func withDifferentTopics() repositoryModifier {
	return func(r *v1alpha1.Repository) {
		r.Spec.ForProvider.Topics = []string{"different", "topics"}
	}
}

func withDifferentDescription() repositoryModifier {
	return func(r *v1alpha1.Repository) {
		r.Spec.ForProvider.Description = description + "-drift"
	}
}

func withDefaultBranch(b string) repositoryModifier {
	return func(r *v1alpha1.Repository) {
		r.Spec.ForProvider.DefaultBranch = &b
	}
}

func withAllowMergeCommit(b bool) repositoryModifier {
	return func(r *v1alpha1.Repository) {
		r.Spec.ForProvider.AllowMergeCommit = &b
	}
}

func withAllowSquashMerge(b bool) repositoryModifier {
	return func(r *v1alpha1.Repository) {
		r.Spec.ForProvider.AllowSquashMerge = &b
	}
}

func withAllowRebaseMerge(b bool) repositoryModifier {
	return func(r *v1alpha1.Repository) {
		r.Spec.ForProvider.AllowRebaseMerge = &b
	}
}

func withAllowAutoMerge(b bool) repositoryModifier {
	return func(r *v1alpha1.Repository) {
		r.Spec.ForProvider.AllowAutoMerge = &b
	}
}

func withAllowUpdateBranch(b bool) repositoryModifier {
	return func(r *v1alpha1.Repository) {
		r.Spec.ForProvider.AllowUpdateBranch = &b
	}
}

func withDeleteBranchOnMerge(b bool) repositoryModifier {
	return func(r *v1alpha1.Repository) {
		r.Spec.ForProvider.DeleteBranchOnMerge = &b
	}
}

func withHasIssues(b bool) repositoryModifier {
	return func(r *v1alpha1.Repository) {
		r.Spec.ForProvider.HasIssues = &b
	}
}

func withHasProjects(b bool) repositoryModifier {
	return func(r *v1alpha1.Repository) {
		r.Spec.ForProvider.HasProjects = &b
	}
}

func withHasWiki(b bool) repositoryModifier {
	return func(r *v1alpha1.Repository) {
		r.Spec.ForProvider.HasWiki = &b
	}
}

func withHasDiscussions(b bool) repositoryModifier {
	return func(r *v1alpha1.Repository) {
		r.Spec.ForProvider.HasDiscussions = &b
	}
}

func withMergeCommitTitle(s string) repositoryModifier {
	return func(r *v1alpha1.Repository) {
		r.Spec.ForProvider.MergeCommitTitle = &s
	}
}

func withMergeCommitMessage(s string) repositoryModifier {
	return func(r *v1alpha1.Repository) {
		r.Spec.ForProvider.MergeCommitMessage = &s
	}
}

func withSquashMergeCommitTitle(s string) repositoryModifier {
	return func(r *v1alpha1.Repository) {
		r.Spec.ForProvider.SquashMergeCommitTitle = &s
	}
}

func withSquashMergeCommitMessage(s string) repositoryModifier {
	return func(r *v1alpha1.Repository) {
		r.Spec.ForProvider.SquashMergeCommitMessage = &s
	}
}

func withArchived(b bool) repositoryModifier {
	return func(r *v1alpha1.Repository) {
		r.Spec.ForProvider.Archived = &b
	}
}

func withExtraUser(login, role string) repositoryModifier {
	return func(r *v1alpha1.Repository) {
		r.Spec.ForProvider.Permissions.Users = append(r.Spec.ForProvider.Permissions.Users, v1alpha1.RepositoryUser{User: login, Role: role})
	}
}

func repository(m ...repositoryModifier) *v1alpha1.Repository {
	cr := &v1alpha1.Repository{}
	cr.Spec.ForProvider.Permissions = v1alpha1.RepositoryPermissions{
		Users: []v1alpha1.RepositoryUser{
			{
				User: strings.ToUpper(user1),
				Role: user1Role,
			},
			{
				User: strings.ToUpper(user2),
				Role: user2Role,
			},
		},
		Teams: []v1alpha1.RepositoryTeam{
			{
				Team: strings.ToUpper(team1),
				Role: team1Role,
			},
			{
				Team: strings.ToUpper(team2),
				Role: team2Role,
			},
		},
	}

	cr.Spec.ForProvider.Webhooks = []v1alpha1.RepositoryWebhook{
		{
			Url:         webhook1url,
			ContentType: webhook1ContentType,
			Events:      []string{webhook1event1, webhook1event2},
			InsecureSsl: &webhook1InsecureSsl,
			Active:      &webhook1active,
		},
	}

	cr.Spec.ForProvider.BranchProtectionRules = []v1alpha1.BranchProtectionRule{
		{
			Branch:                         bpr1branch,
			EnforceAdmins:                  bpr1enforceAdmins,
			RequireLinearHistory:           &bpr1requireLinearHistory,
			AllowForcePushes:               &bpr1allowForcePushes,
			AllowDeletions:                 &bpr1allowDeletions,
			RequiredConversationResolution: &bpr1requiredConversationResolution,
			LockBranch:                     &bpr1lockBranch,
			AllowForkSyncing:               &bpr1allowForkSyncing,
			RequireSignedCommits:           &bpr1requireSignedCommits,
			RequiredStatusChecks: &v1alpha1.RequiredStatusChecks{
				Strict: true,
				Checks: []*v1alpha1.RequiredStatusCheck{
					{
						Context: bpr1requiredStatusCheck,
					},
				},
			},
			BranchProtectionRestrictions: &v1alpha1.BranchProtectionRestrictions{
				Users: []string{
					strings.ToUpper(user1),
				},
				Teams: []string{
					strings.ToUpper(team1),
				},
				Apps: []string{
					strings.ToUpper(githubApp1),
				},
			},
			RequiredPullRequestReviews: &v1alpha1.RequiredPullRequestReviews{
				BypassPullRequestAllowances: &v1alpha1.BypassPullRequestAllowancesRequest{
					Users: []string{
						strings.ToUpper(user1),
					},
					Teams: []string{
						strings.ToUpper(team1),
					},
					Apps: []string{
						strings.ToUpper(githubApp1),
					},
				},
				DismissalRestrictions: &v1alpha1.DismissalRestrictionsRequest{
					Users: &[]string{
						strings.ToUpper(user1),
					},
					Teams: &[]string{
						strings.ToUpper(team1),
					},
					Apps: &[]string{
						strings.ToUpper(githubApp1),
					},
				},
			},
		},
	}
	cr.Spec.ForProvider.RepositoryRules = []v1alpha1.RepositoryRuleset{
		{
			Name:        rr1name,
			Target:      &rr1target,
			Enforcement: &rr1enforcement,
			Conditions: &v1alpha1.RulesetConditions{
				RefName: &v1alpha1.RulesetRefName{
					Include: rr1Include,
					Exclude: rr1Exclude,
				},
			},
			BypassActors: []*v1alpha1.RulesetByPassActors{
				{
					ActorId:    &rr1actorId,
					ActorType:  &rr1actorType,
					BypassMode: &rr1bypassMode,
				},
			},
			Rules: &v1alpha1.Rules{
				Creation:              &rr1rulesCreation,
				Deletion:              &rr1rulesDeletion,
				Update:                &rr1rulesUpdate,
				RequiredLinearHistory: &rr1rulesRequiredLinearHistory,
				RequiredSignatures:    &rr1rulesRequiredSignatures,
				NonFastForward:        &rr1rulesNonFastForward,
			},
		},
	}

	cr.Spec.ForProvider.Topics = []string{topic1, topic2, topic3}
	cr.Spec.ForProvider.Description = description

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
		IsTemplate:  &isTemplate,
		Fork:        github.Bool(false),
		Topics:      []string{topic1, topic2, topic3},
	}
}

func githubWebhooks() []*github.Hook {
	return []*github.Hook{
		{
			Config: &github.HookConfig{
				URL:         &webhook1url,
				ContentType: &webhook1ContentType,
				InsecureSSL: &webhook1InsecureSslStr,
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
			Checks: &[]*github.RequiredStatusCheck{
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
		LockBranch: &github.LockBranch{
			Enabled: &bpr1lockBranch,
		},
		AllowForkSyncing: &github.AllowForkSyncing{
			Enabled: &bpr1allowForkSyncing,
		},
		RequiredSignatures: &github.SignaturesProtectedBranch{
			Enabled: &bpr1requireSignedCommits,
		},
		Restrictions: &github.BranchRestrictions{
			Users: []*github.User{
				{
					Login: &user1,
				},
			},
			Teams: []*github.Team{
				{
					Slug: &team1,
				},
			},
			Apps: []*github.App{
				{
					Slug: &githubApp1,
				},
			},
		},
		RequiredPullRequestReviews: &github.PullRequestReviewsEnforcement{
			BypassPullRequestAllowances: &github.BypassPullRequestAllowances{
				Users: []*github.User{
					{
						Login: &user1,
					},
				},
				Teams: []*github.Team{
					{
						Slug: &team1,
					},
				},
				Apps: []*github.App{
					{
						Slug: &githubApp1,
					},
				},
			},
			DismissalRestrictions: &github.DismissalRestrictions{
				Users: []*github.User{
					{
						Login: &user1,
					},
				},
				Teams: []*github.Team{
					{
						Slug: &team1,
					},
				},
				Apps: []*github.App{
					{
						Slug: &githubApp1,
					},
				},
			},
		},
	}
}

func githubRuleset() []*github.Ruleset {
	return []*github.Ruleset{
		{
			ID:          &rr1Id,
			Name:        rr1name,
			Target:      &rr1target,
			Enforcement: rr1enforcement,
			Conditions: &github.RulesetConditions{
				RefName: &github.RulesetRefConditionParameters{
					Include: rr1Include,
					Exclude: rr1Exclude,
				},
			},
			BypassActors: []*github.BypassActor{
				{
					ActorID:    &rr1actorId,
					ActorType:  &rr1actorType,
					BypassMode: &rr1bypassMode,
				},
			},
			Rules: []*github.RepositoryRule{
				{
					Type: "creation",
				},
				{
					Type: "deletion",
				},
				{
					Type: "update",
				},
				{
					Type: "required_linear_history",
				},
				{
					Type: "required_signatures",
				},
				{
					Type: "non_fast_forward",
				},
			},
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
			fields: fields{github: &ghclient.Client{
				Services: &ghclient.Services{
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
						MockGetAllRulesets: func(ctx context.Context, owner, repo string) ([]*github.Ruleset, *github.Response, error) {
							return githubRuleset(), fake.GenerateEmptyResponse(), nil
						},
						MockGetRuleset: func(ctx context.Context, owner, repo string, rulesetID int64, includesParents bool) (*github.Ruleset, *github.Response, error) {
							return githubRuleset()[0], fake.GenerateEmptyResponse(), nil
						},
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
			fields: fields{github: &ghclient.Client{
				Services: &ghclient.Services{
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
						MockGetAllRulesets: func(ctx context.Context, owner, repo string) ([]*github.Ruleset, *github.Response, error) {
							return githubRuleset(), fake.GenerateEmptyResponse(), nil
						},
						MockGetRuleset: func(ctx context.Context, owner, repo string, rulesetID int64, includesParents bool) (*github.Ruleset, *github.Response, error) {
							return githubRuleset()[0], fake.GenerateEmptyResponse(), nil
						},
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
		"NotUpToDateTopicsMismatch": {
			fields: fields{github: &ghclient.Client{
				Services: &ghclient.Services{
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
						MockGetAllRulesets: func(ctx context.Context, owner, repo string) ([]*github.Ruleset, *github.Response, error) {
							return githubRuleset(), fake.GenerateEmptyResponse(), nil
						},
						MockGetRuleset: func(ctx context.Context, owner, repo string, rulesetID int64, includesParents bool) (*github.Ruleset, *github.Response, error) {
							return githubRuleset()[0], fake.GenerateEmptyResponse(), nil
						},
					},
				},
			},
			},
			args: args{
				mg: repository(withDifferentTopics()),
			},
			want: want{
				o: managed.ExternalObservation{
					ResourceExists:   true,
					ResourceUpToDate: false,
				},
				err: nil,
			},
		},
		"DoesNotExist": {
			fields: fields{
				github: &ghclient.Client{
					Services: &ghclient.Services{
						Repositories: &fake.MockRepositoriesClient{
							MockGet: func(ctx context.Context, owner, repo string) (*github.Repository, *github.Response, error) {
								return nil, nil, fake.Generate404Response()
							},
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
		// A declared collaborator with an outstanding (unaccepted) invitation does
		// not register as drift: ListCollaborators(direct) omits them, but the
		// pending invitation is recognized, so Observe stays up to date instead of
		// re-inviting every reconcile.
		"PendingInvitationUpToDate": {
			fields: fields{github: &ghclient.Client{
				Services: &ghclient.Services{
					Repositories: &fake.MockRepositoriesClient{
						MockGet: func(ctx context.Context, owner, repo string) (*github.Repository, *github.Response, error) {
							return githubRepository(), nil, nil
						},
						MockListCollaborators: func(ctx context.Context, owner, repo string, opts *github.ListCollaboratorsOptions) ([]*github.User, *github.Response, error) {
							return githubCollaborators(), fake.GenerateEmptyResponse(), nil
						},
						MockListInvitations: func(ctx context.Context, owner, repo string, opts *github.ListOptions) ([]*github.RepositoryInvitation, *github.Response, error) {
							return []*github.RepositoryInvitation{{Invitee: &github.User{Login: github.String("pending-user")}}}, fake.GenerateEmptyResponse(), nil
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
						MockGetAllRulesets: func(ctx context.Context, owner, repo string) ([]*github.Ruleset, *github.Response, error) {
							return githubRuleset(), fake.GenerateEmptyResponse(), nil
						},
						MockGetRuleset: func(ctx context.Context, owner, repo string, rulesetID int64, includesParents bool) (*github.Ruleset, *github.Response, error) {
							return githubRuleset()[0], fake.GenerateEmptyResponse(), nil
						},
					},
				},
			}},
			args: args{
				mg: repository(withExtraUser("pending-user", "pull")),
			},
			want: want{
				o: managed.ExternalObservation{
					ResourceExists:   true,
					ResourceUpToDate: true,
				},
				err: nil,
			},
		},
		// An archived repo with matching teams, collaborators and topics is up to
		// date. Branch protection, rulesets and webhooks are frozen while archived,
		// so no mocks are wired for them — a call would be a nil-func panic, proving
		// Observe does not read the frozen dimensions.
		"ArchivedUpToDate": {
			fields: fields{github: &ghclient.Client{
				Services: &ghclient.Services{
					Repositories: &fake.MockRepositoriesClient{
						MockGet: func(ctx context.Context, owner, repo string) (*github.Repository, *github.Response, error) {
							r := githubRepository()
							r.Archived = github.Bool(true)
							return r, nil, nil
						},
						MockListCollaborators: func(ctx context.Context, owner, repo string, opts *github.ListCollaboratorsOptions) ([]*github.User, *github.Response, error) {
							return githubCollaborators(), fake.GenerateEmptyResponse(), nil
						},
						MockListTeams: func(ctx context.Context, owner string, repo string, opts *github.ListOptions) ([]*github.Team, *github.Response, error) {
							return githubTeams(), fake.GenerateEmptyResponse(), nil
						},
					},
				},
			}},
			args: args{
				mg: repository(withArchived(true)),
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

// TestUpdate pins archived-repo write partitioning. While archived GitHub permits
// team access, topics and collaborator removals but rejects settings/Edit, branch
// protection, rulesets, webhooks and collaborator additions with 403. Update must
// reconcile the permitted dimensions and never issue the frozen ones (which would
// loop). Archiving a live repo issues one Edit(archived=true); unarchiving issues
// Edit(archived=false) before the normal reconcile.
func TestUpdate(t *testing.T) {
	bareRepo := func(archived bool) *v1alpha1.Repository {
		cr := &v1alpha1.Repository{}
		cr.Spec.ForProvider.Archived = &archived
		meta.SetExternalName(cr, repo)
		return cr
	}
	ghRepo := func(arch bool) *github.Repository {
		return &github.Repository{Name: &repo, Archived: &arch, Fork: github.Bool(false), Topics: []string{topic1, topic2, topic3}}
	}

	type want struct {
		editArchived  []bool // archived value of each Edit call, in order
		frozenWrite   string // a frozen write reached while archived (empty = none)
		addTeamRepo   int
		removeCollab  int
		replaceTopics int
		err           error
	}
	cases := map[string]struct {
		reason  string
		gh      *github.Repository
		cr      *v1alpha1.Repository
		ghUsers []*github.User
		ghTeams []*github.Team
		want    want
	}{
		"AlreadyArchivedNoChanges": {
			reason: "Desired archived, already archived, nothing to change: no Edit and no writes.",
			gh:     ghRepo(true),
			cr:     bareRepo(true),
			want:   want{},
		},
		"TransitionToArchived": {
			reason: "Desired archived, currently live: exactly one Edit(archived=true), no frozen writes.",
			gh:     ghRepo(false),
			cr:     bareRepo(true),
			want:   want{editArchived: []bool{true}},
		},
		"UnarchiveThenReconcile": {
			reason: "Desired live, currently archived: Edit(archived=false) to unarchive, then the normal reconcile Edit.",
			gh:     ghRepo(true),
			cr:     bareRepo(false),
			want:   want{editArchived: []bool{false, false}},
		},
		"ArchivedReconcilesAllowedSkipsFrozen": {
			reason:  "Archived repo with a full spec: teams and topics reconcile; settings, branch protection, rulesets, webhooks and collaborator additions are frozen.",
			gh:      ghRepo(true),
			cr:      repository(withArchived(true)),
			ghUsers: githubCollaborators(), // matches CR users → no collaborator writes
			ghTeams: []*github.Team{},      // CR teams absent → AddTeamRepoBySlug fires
			want:    want{addTeamRepo: 2, replaceTopics: 1},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var editArchived []bool
			frozenWrite := ""
			addTeamRepo, removeCollab, replaceTopics := 0, 0, 0
			repoClient := &fake.MockRepositoriesClient{
				MockGet: func(ctx context.Context, owner, r string) (*github.Repository, *github.Response, error) {
					return tc.gh, nil, nil
				},
				MockEdit: func(ctx context.Context, owner, r string, rr *github.Repository) (*github.Repository, *github.Response, error) {
					editArchived = append(editArchived, rr.GetArchived())
					return rr, nil, nil
				},
				MockListCollaborators: func(ctx context.Context, owner, r string, opts *github.ListCollaboratorsOptions) ([]*github.User, *github.Response, error) {
					return tc.ghUsers, fake.GenerateEmptyResponse(), nil
				},
				MockListTeams: func(ctx context.Context, owner, r string, opts *github.ListOptions) ([]*github.Team, *github.Response, error) {
					return tc.ghTeams, fake.GenerateEmptyResponse(), nil
				},
				MockReplaceAllTopics: func(ctx context.Context, owner, r string, topics []string) ([]string, *github.Response, error) {
					replaceTopics++
					return topics, fake.GenerateEmptyResponse(), nil
				},
				MockRemoveCollaborator: func(ctx context.Context, owner, r, user string) (*github.Response, error) {
					removeCollab++
					return fake.GenerateEmptyResponse(), nil
				},
				// Frozen-while-archived writes: must not be reached.
				MockAddCollaborator: func(ctx context.Context, owner, r, user string, opts *github.RepositoryAddCollaboratorOptions) (*github.CollaboratorInvitation, *github.Response, error) {
					frozenWrite = "AddCollaborator"
					return nil, fake.GenerateEmptyResponse(), nil
				},
				MockUpdateBranchProtection: func(ctx context.Context, owner, r, branch string, preq *github.ProtectionRequest) (*github.Protection, *github.Response, error) {
					frozenWrite = "UpdateBranchProtection"
					return githubProtectedBranch(), fake.GenerateEmptyResponse(), nil
				},
				MockCreateRuleset: func(ctx context.Context, owner, r string, rs *github.Ruleset) (*github.Ruleset, *github.Response, error) {
					frozenWrite = "CreateRuleset"
					return rs, fake.GenerateEmptyResponse(), nil
				},
				MockCreateHook: func(ctx context.Context, owner, r string, hook *github.Hook) (*github.Hook, *github.Response, error) {
					frozenWrite = "CreateHook"
					return hook, fake.GenerateEmptyResponse(), nil
				},
			}
			teamsClient := &fake.MockTeamsClient{
				MockAddTeamRepoBySlug: func(ctx context.Context, org, slug, owner, r string, opts *github.TeamAddTeamRepoOptions) (*github.Response, error) {
					addTeamRepo++
					return fake.GenerateEmptyResponse(), nil
				},
				MockRemoveTeamRepoBySlug: func(ctx context.Context, org, slug, owner, r string) (*github.Response, error) {
					return fake.GenerateEmptyResponse(), nil
				},
			}
			e := external{github: &ghclient.Client{Services: &ghclient.Services{Repositories: repoClient, Teams: teamsClient}}}
			_, err := e.Update(context.Background(), tc.cr)
			if diff := cmp.Diff(tc.want.err, err, test.EquateErrors()); diff != "" {
				t.Errorf("\n%s\nUpdate(): -want error, +got error:\n%s", tc.reason, diff)
			}
			if diff := cmp.Diff(tc.want.editArchived, editArchived); diff != "" {
				t.Errorf("\n%s\nUpdate() Edit archived values: -want, +got:\n%s", tc.reason, diff)
			}
			if frozenWrite != tc.want.frozenWrite {
				t.Errorf("\n%s\nUpdate() frozen write reached = %q, want %q", tc.reason, frozenWrite, tc.want.frozenWrite)
			}
			if addTeamRepo != tc.want.addTeamRepo {
				t.Errorf("\n%s\nUpdate() AddTeamRepoBySlug calls = %d, want %d", tc.reason, addTeamRepo, tc.want.addTeamRepo)
			}
			if removeCollab != tc.want.removeCollab {
				t.Errorf("\n%s\nUpdate() RemoveCollaborator calls = %d, want %d", tc.reason, removeCollab, tc.want.removeCollab)
			}
			if replaceTopics != tc.want.replaceTopics {
				t.Errorf("\n%s\nUpdate() ReplaceAllTopics calls = %d, want %d", tc.reason, replaceTopics, tc.want.replaceTopics)
			}
		})
	}
}

func ghUserWithPerm(login, perm string) *github.User {
	return &github.User{Login: github.String(login), Permissions: map[string]bool{perm: true}}
}

// TestCategorizeCollaborators pins the collaborator buckets. The key invariant is
// that a declared collaborator with an outstanding invitation lands in pendingInvite
// (in flight) rather than toUpsert, so the controller does not re-invite them on
// every reconcile — the loop the prod repos were stuck in.
func TestCategorizeCollaborators(t *testing.T) {
	u := func(login, role string) v1alpha1.RepositoryUser {
		return v1alpha1.RepositoryUser{User: login, Role: role}
	}
	type want struct {
		toRemove     map[string]string
		toUpsert     map[string]string
		pending      []string
		roleEnforced []string
	}
	cases := map[string]struct {
		reason    string
		crUsers   []v1alpha1.RepositoryUser
		ghUsers   []*github.User
		invites   []*github.RepositoryInvitation
		orgAdmins map[string]bool
		want      want
	}{
		"AllPresentMatching": {
			reason:  "Declared users all active at the declared role: no drift.",
			crUsers: []v1alpha1.RepositoryUser{u("alice", "push")},
			ghUsers: []*github.User{ghUserWithPerm("alice", "push")},
			want:    want{toRemove: map[string]string{}, toUpsert: map[string]string{}},
		},
		"PendingInviteNotReAdded": {
			reason:  "A declared user with an outstanding invitation is pending, not an add.",
			crUsers: []v1alpha1.RepositoryUser{u("alice", "push"), u("bob", "pull")},
			ghUsers: []*github.User{ghUserWithPerm("alice", "push")},
			invites: []*github.RepositoryInvitation{{Invitee: &github.User{Login: github.String("bob")}}},
			want:    want{toRemove: map[string]string{}, toUpsert: map[string]string{}, pending: []string{"bob"}},
		},
		"GenuineAdd": {
			reason:  "A declared user who is neither active nor invited is a real add.",
			crUsers: []v1alpha1.RepositoryUser{u("alice", "push"), u("carol", "pull")},
			ghUsers: []*github.User{ghUserWithPerm("alice", "push")},
			want:    want{toRemove: map[string]string{}, toUpsert: map[string]string{"carol": "pull"}},
		},
		"RoleChange": {
			reason:  "A declared user active at a different role is an upsert.",
			crUsers: []v1alpha1.RepositoryUser{u("alice", "admin")},
			ghUsers: []*github.User{ghUserWithPerm("alice", "push")},
			want:    want{toRemove: map[string]string{}, toUpsert: map[string]string{"alice": "admin"}},
		},
		"Remove": {
			reason:  "An active collaborator absent from the CR is removed.",
			crUsers: nil,
			ghUsers: []*github.User{ghUserWithPerm("alice", "push")},
			want:    want{toRemove: map[string]string{"alice": "push"}, toUpsert: map[string]string{}},
		},
		"OrgAdminRoleEnforced": {
			reason:    "An org owner declared below admin shows as admin on GitHub and can't be downgraded: enforced, not an upsert.",
			crUsers:   []v1alpha1.RepositoryUser{u("owner1", "push")},
			ghUsers:   []*github.User{ghUserWithPerm("owner1", "admin")},
			orgAdmins: map[string]bool{"owner1": true},
			want:      want{toRemove: map[string]string{}, toUpsert: map[string]string{}, roleEnforced: []string{"owner1"}},
		},
		"NonOwnerGhAdminDowngradeIsUpsert": {
			reason:    "A non-owner showing admin on GitHub but declared lower is a real role change, not enforced.",
			crUsers:   []v1alpha1.RepositoryUser{u("dave", "push")},
			ghUsers:   []*github.User{ghUserWithPerm("dave", "admin")},
			orgAdmins: map[string]bool{}, // dave is not an org owner
			want:      want{toRemove: map[string]string{}, toUpsert: map[string]string{"dave": "push"}},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			gh := &ghclient.Client{Services: &ghclient.Services{
				Repositories: &fake.MockRepositoriesClient{
					MockListCollaborators: func(ctx context.Context, owner, r string, opts *github.ListCollaboratorsOptions) ([]*github.User, *github.Response, error) {
						return tc.ghUsers, fake.GenerateEmptyResponse(), nil
					},
					MockListInvitations: func(ctx context.Context, owner, r string, opts *github.ListOptions) ([]*github.RepositoryInvitation, *github.Response, error) {
						return tc.invites, fake.GenerateEmptyResponse(), nil
					},
				},
				Organizations: &fake.MockOrganizationsClient{
					MockGetOrgMembership: func(ctx context.Context, user, org string) (*github.Membership, *github.Response, error) {
						role := "member"
						if tc.orgAdmins[user] {
							role = "admin"
						}
						return &github.Membership{Role: github.String(role)}, fake.GenerateEmptyResponse(), nil
					},
				},
			}}
			got, err := categorizeCollaborators(context.Background(), gh, "org", "repo", tc.crUsers)
			if err != nil {
				t.Fatalf("%s\nunexpected error: %v", tc.reason, err)
			}
			if diff := cmp.Diff(tc.want.toRemove, got.toRemove); diff != "" {
				t.Errorf("%s\ntoRemove: -want, +got:\n%s", tc.reason, diff)
			}
			if diff := cmp.Diff(tc.want.toUpsert, got.toUpsert); diff != "" {
				t.Errorf("%s\ntoUpsert: -want, +got:\n%s", tc.reason, diff)
			}
			if diff := cmp.Diff(tc.want.pending, got.pendingInvite); diff != "" {
				t.Errorf("%s\npendingInvite: -want, +got:\n%s", tc.reason, diff)
			}
			if diff := cmp.Diff(tc.want.roleEnforced, got.roleEnforced); diff != "" {
				t.Errorf("%s\nroleEnforced: -want, +got:\n%s", tc.reason, diff)
			}
		})
	}
}

// TestSetCollaboratorPartialCondition checks the condition surfaces pending invitees
// (True) and reports a clean state otherwise (False), so the skip is never silent.
func TestSetCollaboratorPartialCondition(t *testing.T) {
	cases := map[string]struct {
		pending      []string
		roleEnforced []string
		wantStatus   corev1.ConditionStatus
		wantReason   xpv1.ConditionReason
	}{
		"None":         {wantStatus: corev1.ConditionFalse, wantReason: reasonAllCollaboratorsPresent},
		"Pending":      {pending: []string{"bob", "alice"}, wantStatus: corev1.ConditionTrue, wantReason: reasonPendingInvitation},
		"RoleEnforced": {roleEnforced: []string{"owner1"}, wantStatus: corev1.ConditionTrue, wantReason: reasonRoleEnforcedByOrg},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cr := &v1alpha1.Repository{}
			setCollaboratorPartialCondition(cr, tc.pending, tc.roleEnforced)
			got := cr.GetCondition(typeCollaboratorPartial)
			if got.Status != tc.wantStatus {
				t.Errorf("status = %v, want %v", got.Status, tc.wantStatus)
			}
			if got.Reason != tc.wantReason {
				t.Errorf("reason = %v, want %v", got.Reason, tc.wantReason)
			}
		})
	}
}

// TestObserveMainSettingsDrift pins drift detection for the repo main-settings
// fields. Each case flips a single spec field; Observe must report not-up-to-date.
func TestObserveMainSettingsDrift(t *testing.T) {
	upToDateClient := func() *ghclient.Client {
		return &ghclient.Client{
			Services: &ghclient.Services{
				Repositories: &fake.MockRepositoriesClient{
					MockGet: func(ctx context.Context, owner, repo string) (*github.Repository, *github.Response, error) {
						return githubRepository(), nil, nil
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
					MockGetAllRulesets: func(ctx context.Context, owner, repo string) ([]*github.Ruleset, *github.Response, error) {
						return githubRuleset(), fake.GenerateEmptyResponse(), nil
					},
					MockGetRuleset: func(ctx context.Context, owner, repo string, rulesetID int64, includesParents bool) (*github.Ruleset, *github.Response, error) {
						return githubRuleset()[0], fake.GenerateEmptyResponse(), nil
					},
				},
			},
		}
	}

	cases := map[string]repositoryModifier{
		"DescriptionDrift":              withDifferentDescription(),
		"DefaultBranchDrift":            withDefaultBranch("main"),
		"AllowMergeCommitDrift":         withAllowMergeCommit(true),
		"AllowSquashMergeDrift":         withAllowSquashMerge(true),
		"AllowRebaseMergeDrift":         withAllowRebaseMerge(true),
		"AllowAutoMergeDrift":           withAllowAutoMerge(true),
		"AllowUpdateBranchDrift":        withAllowUpdateBranch(true),
		"DeleteBranchOnMergeDrift":      withDeleteBranchOnMerge(true),
		"HasIssuesDrift":                withHasIssues(true),
		"HasProjectsDrift":              withHasProjects(true),
		"HasWikiDrift":                  withHasWiki(true),
		"HasDiscussionsDrift":           withHasDiscussions(true),
		"MergeCommitTitleDrift":         withMergeCommitTitle("PR_TITLE"),
		"MergeCommitMessageDrift":       withMergeCommitMessage("PR_BODY"),
		"SquashMergeCommitTitleDrift":   withSquashMergeCommitTitle("PR_TITLE"),
		"SquashMergeCommitMessageDrift": withSquashMergeCommitMessage("PR_BODY"),
	}

	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			e := external{github: upToDateClient()}
			got, err := e.Observe(context.Background(), repository(mod))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !got.ResourceExists {
				t.Errorf("Observe(): want ResourceExists=true, got false")
			}
			if got.ResourceUpToDate {
				t.Errorf("Observe(): want ResourceUpToDate=false (drift), got true")
			}
		})
	}
}

// filterMissingBranchProtectionRules is what stops the controller from
// calling UpdateBranchProtection on branches that don't exist. Asserts:
// rules for missing branches are removed from the map, rules for existing
// branches are kept untouched, and the skipped list is returned sorted so
// the condition message is stable across reconciles.
// filterMissingBranchProtectionRules has two responsibilities:
//
//   - Short-circuit branches already in protectedSet without calling
//     GetBranch (they exist by construction — you can't protect a
//     missing branch).
//   - For the rest, hit Repositories.GetBranch: 404 means the branch
//     is missing and the rule is dropped; 2xx means the branch exists
//     but is unprotected (the rule will be applied by Update); any
//     other error propagates.
//
// The wantCalls assertion pins the short-circuit — if a future change
// stops respecting protectedSet, every reconcile would emit an extra
// GetBranch per already-protected branch, which is the whole API-cost
// reason the protectedSet path exists.
func TestFilterMissingBranchProtectionRules(t *testing.T) {
	ctx := context.Background()
	const org = "test-org"
	const repo = "test-repo"

	type mockBranches struct {
		exists  map[string]bool   // GetBranch returns 200 with name == requested
		missing map[string]bool   // GetBranch returns 404
		renamed map[string]string // GetBranch returns 200 but with a different name (key → value mapping)
		errFor  string            // GetBranch returns a non-404 error for this branch
	}

	cases := map[string]struct {
		rules        map[string]v1alpha1.BranchProtectionRule
		protectedSet map[string]bool
		mock         mockBranches
		wantRules    map[string]v1alpha1.BranchProtectionRule
		wantSkipped  []string
		wantCalls    []string
		wantErr      bool
	}{
		"AllAlreadyProtected_NoGetBranchCalls": {
			rules: map[string]v1alpha1.BranchProtectionRule{
				"main":    {Branch: "main"},
				"develop": {Branch: "develop"},
			},
			protectedSet: map[string]bool{"main": true, "develop": true},
			wantRules: map[string]v1alpha1.BranchProtectionRule{
				"main":    {Branch: "main"},
				"develop": {Branch: "develop"},
			},
			wantSkipped: nil,
			wantCalls:   nil,
		},
		"UnprotectedButExisting_CheckedAndKept": {
			rules: map[string]v1alpha1.BranchProtectionRule{
				"main":    {Branch: "main"},
				"develop": {Branch: "develop"},
			},
			protectedSet: map[string]bool{"main": true},
			mock:         mockBranches{exists: map[string]bool{"develop": true}},
			wantRules: map[string]v1alpha1.BranchProtectionRule{
				"main":    {Branch: "main"},
				"develop": {Branch: "develop"},
			},
			wantSkipped: nil,
			wantCalls:   []string{"develop"},
		},
		"MissingBranches_Skipped": {
			rules: map[string]v1alpha1.BranchProtectionRule{
				"main":    {Branch: "main"},
				"release": {Branch: "release"},
				"ghost":   {Branch: "ghost"},
			},
			protectedSet: map[string]bool{"main": true},
			mock: mockBranches{
				missing: map[string]bool{"release": true, "ghost": true},
			},
			wantRules:   map[string]v1alpha1.BranchProtectionRule{"main": {Branch: "main"}},
			wantSkipped: []string{"ghost", "release"},
			wantCalls:   []string{"ghost", "release"},
		},
		"MixedExistingAndMissing": {
			rules: map[string]v1alpha1.BranchProtectionRule{
				"main":    {Branch: "main"},
				"develop": {Branch: "develop"},
				"ghost":   {Branch: "ghost"},
			},
			protectedSet: map[string]bool{"main": true},
			mock: mockBranches{
				exists:  map[string]bool{"develop": true},
				missing: map[string]bool{"ghost": true},
			},
			wantRules: map[string]v1alpha1.BranchProtectionRule{
				"main":    {Branch: "main"},
				"develop": {Branch: "develop"},
			},
			wantSkipped: []string{"ghost"},
			wantCalls:   []string{"develop", "ghost"},
		},
		"EmptyInput_NoCallsNoSkipped": {
			rules:        map[string]v1alpha1.BranchProtectionRule{},
			protectedSet: map[string]bool{"main": true},
			wantRules:    map[string]v1alpha1.BranchProtectionRule{},
			wantSkipped:  nil,
			wantCalls:    nil,
		},
		"Non404Error_Propagates": {
			rules:        map[string]v1alpha1.BranchProtectionRule{"feature": {Branch: "feature"}},
			protectedSet: map[string]bool{},
			mock:         mockBranches{errFor: "feature"},
			wantErr:      true,
		},
		// Renamed branches must not be silently accepted as existing — the rule
		// will 404 on the actual UpdateBranchProtection call because PUT doesn't
		// follow the rename redirect. Surface the new name in the skipped entry
		// so the operator knows what to put in the CR.
		"RenamedBranch_DroppedAndNameSurfaced": {
			rules: map[string]v1alpha1.BranchProtectionRule{
				"main":    {Branch: "main"},
				"develop": {Branch: "develop"},
			},
			protectedSet: map[string]bool{},
			mock: mockBranches{
				renamed: map[string]string{"main": "trunk"},
				exists:  map[string]bool{"develop": true},
			},
			wantRules:   map[string]v1alpha1.BranchProtectionRule{"develop": {Branch: "develop"}},
			wantSkipped: []string{"main (was renamed to trunk)"},
			wantCalls:   []string{"develop", "main"},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var calls []string
			gh := &ghclient.Client{
				Services: &ghclient.Services{
					Repositories: &fake.MockRepositoriesClient{
						MockGetBranch: func(_ context.Context, _, _, branch string, _ int) (*github.Branch, *github.Response, error) {
							calls = append(calls, branch)
							switch {
							case branch == tc.mock.errFor:
								return nil, &github.Response{Response: &http.Response{StatusCode: http.StatusInternalServerError}}, errors.New("boom")
							case tc.mock.missing[branch]:
								// Real GetBranch returns a bare fmt.Errorf + non-nil resp.StatusCode=404, not a *github.ErrorResponse.
								return nil, &github.Response{Response: &http.Response{StatusCode: http.StatusNotFound}}, fmt.Errorf("unexpected status code: 404 Not Found")
							case tc.mock.renamed[branch] != "":
								// 200 with a different name — GetBranch followed a rename redirect.
								return &github.Branch{Name: github.String(tc.mock.renamed[branch])}, fake.GenerateEmptyResponse(), nil
							case tc.mock.exists[branch]:
								return &github.Branch{Name: github.String(branch)}, fake.GenerateEmptyResponse(), nil
							default:
								return nil, nil, errors.New("unexpected branch in mock: " + branch)
							}
						},
					},
				},
			}

			gotSkipped, err := filterMissingBranchProtectionRules(ctx, gh, org, repo, tc.rules, tc.protectedSet)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if diff := cmp.Diff(tc.wantSkipped, gotSkipped); diff != "" {
				t.Errorf("skipped: -want, +got:\n%s", diff)
			}
			if diff := cmp.Diff(tc.wantRules, tc.rules); diff != "" {
				t.Errorf("rules after filter: -want, +got:\n%s", diff)
			}
			sort.Strings(calls)
			if diff := cmp.Diff(tc.wantCalls, calls); diff != "" {
				t.Errorf("GetBranch calls: -want, +got:\n%s", diff)
			}
		})
	}
}

// setBranchProtectionPartialCondition is the operator-facing signal for
// "some desired BPRs can't apply right now". Asserts: non-empty skipped →
// status True with sorted branch names in the message; empty skipped →
// status False (resource is fully converged on this dimension). Crossplane's
// SetConditions dedupes identical writes, so steady-state reconciles don't
// thrash the status — this test pins the (Status, Reason, Message) shape
// that dedup depends on.
func TestSetBranchProtectionPartialCondition(t *testing.T) {
	cases := map[string]struct {
		skipped     []string
		wantStatus  corev1.ConditionStatus
		wantReason  xpv1.ConditionReason
		wantInMsg   []string
		wantMsgZero bool
	}{
		"Empty_FalseAndAllBranchesPresentReason": {
			skipped:     nil,
			wantStatus:  corev1.ConditionFalse,
			wantReason:  "AllBranchesPresent",
			wantMsgZero: true,
		},
		"NonEmpty_TrueAndNamesBranchesInMessage": {
			skipped:    []string{"develop", "release"},
			wantStatus: corev1.ConditionTrue,
			wantReason: "BranchesMissing",
			wantInMsg:  []string{"develop", "release"},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cr := &v1alpha1.Repository{}
			setBranchProtectionPartialCondition(context.Background(), cr, tc.skipped)

			c := cr.GetCondition("BranchProtectionPartial")
			if c.Status != tc.wantStatus {
				t.Errorf("Status = %q, want %q", c.Status, tc.wantStatus)
			}
			if c.Reason != tc.wantReason {
				t.Errorf("Reason = %q, want %q", c.Reason, tc.wantReason)
			}
			if tc.wantMsgZero && c.Message != "" {
				t.Errorf("Message = %q, want empty", c.Message)
			}
			for _, want := range tc.wantInMsg {
				if !strings.Contains(c.Message, want) {
					t.Errorf("Message %q missing %q", c.Message, want)
				}
			}
		})
	}
}

// SetConditions on identical content is idempotent. Calling
// setBranchProtectionPartialCondition twice with the same skipped set
// must not append a duplicate to status.conditions — otherwise every
// reconcile would grow the slice and produce K8s status writes.
func TestSetBranchProtectionPartialCondition_Idempotent(t *testing.T) {
	cr := &v1alpha1.Repository{}
	setBranchProtectionPartialCondition(context.Background(), cr, []string{"develop"})
	setBranchProtectionPartialCondition(context.Background(), cr, []string{"develop"})

	count := 0
	for _, c := range cr.Status.Conditions {
		if c.Type == "BranchProtectionPartial" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("BranchProtectionPartial conditions = %d, want 1", count)
	}
}

func TestRecordForcePushNotApplied(t *testing.T) {
	bpr := func(branch string, afp bool) v1alpha1.BranchProtectionRule {
		return v1alpha1.BranchProtectionRule{Branch: branch, AllowForcePushes: &afp}
	}

	cases := map[string]struct {
		reason     string
		cr         map[string]v1alpha1.BranchProtectionRule
		gh         map[string]v1alpha1.BranchProtectionRule
		wantStatus corev1.ConditionStatus
		wantReason xpv1.ConditionReason
	}{
		"NotHonored": {
			reason:     "CR wants force pushes off but GitHub keeps them on: condition True",
			cr:         map[string]v1alpha1.BranchProtectionRule{"main": bpr("main", false)},
			gh:         map[string]v1alpha1.BranchProtectionRule{"main": bpr("main", true)},
			wantStatus: corev1.ConditionTrue,
			wantReason: reasonForcePushNotApplied,
		},
		"Honored": {
			reason:     "GitHub stored what the CR wanted: condition False",
			cr:         map[string]v1alpha1.BranchProtectionRule{"main": bpr("main", false)},
			gh:         map[string]v1alpha1.BranchProtectionRule{"main": bpr("main", false)},
			wantStatus: corev1.ConditionFalse,
			wantReason: reasonProtectionApplied,
		},
		"CrWantsForcePushOn": {
			reason:     "CR explicitly wants force pushes on and GitHub agrees: not a violation",
			cr:         map[string]v1alpha1.BranchProtectionRule{"main": bpr("main", true)},
			gh:         map[string]v1alpha1.BranchProtectionRule{"main": bpr("main", true)},
			wantStatus: corev1.ConditionFalse,
			wantReason: reasonProtectionApplied,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cr := repository()
			recordForcePushNotApplied(cr, tc.cr, tc.gh)

			got := cr.GetCondition(typeBranchProtectionNotApplied)
			if got.Status != tc.wantStatus {
				t.Errorf("%s: status = %v, want %v", tc.reason, got.Status, tc.wantStatus)
			}
			if got.Reason != tc.wantReason {
				t.Errorf("%s: reason = %v, want %v", tc.reason, got.Reason, tc.wantReason)
			}
		})
	}
}

// Declared actors absent from GitHub's stored rule are reported as "branch/field:actor",
// and the message prefix names only the kinds actually dropped. Failure means an unapplied
// actor goes unreported, a stored one is flagged, or the prefix misstates the kinds.
func TestDetectUnappliedBranchProtectionActors(t *testing.T) {
	rule := func(bypass, dismissal, restriction []string) map[string]v1alpha1.BranchProtectionRule {
		return map[string]v1alpha1.BranchProtectionRule{
			"main": {
				Branch: "main",
				RequiredPullRequestReviews: &v1alpha1.RequiredPullRequestReviews{
					BypassPullRequestAllowances: &v1alpha1.BypassPullRequestAllowancesRequest{Users: bypass},
					DismissalRestrictions:       &v1alpha1.DismissalRestrictionsRequest{Users: &dismissal},
				},
				BranchProtectionRestrictions: &v1alpha1.BranchProtectionRestrictions{Users: restriction},
			},
		}
	}

	cases := map[string]struct {
		reason      string
		declared    map[string]v1alpha1.BranchProtectionRule
		stored      map[string]v1alpha1.BranchProtectionRule
		wantStatus  corev1.ConditionStatus
		wantReason  xpv1.ConditionReason
		wantMessage string
	}{
		"DismissalOnly": {
			reason:      "only a dismissal actor dropped: prefix names dismissal alone",
			declared:    rule(nil, []string{"alice"}, nil),
			stored:      rule(nil, nil, nil),
			wantStatus:  corev1.ConditionTrue,
			wantReason:  reasonActorsNotApplied,
			wantMessage: "dismissal actors not applied by GitHub: main/dismissalUsers:alice",
		},
		"BypassAndRestriction": {
			reason:      "bypass + restriction dropped: prefix names both, omits dismissal; entries sorted",
			declared:    rule([]string{"bob"}, nil, []string{"carol"}),
			stored:      rule(nil, nil, nil),
			wantStatus:  corev1.ConditionTrue,
			wantReason:  reasonActorsNotApplied,
			wantMessage: "bypass/restriction actors not applied by GitHub: main/bypassUsers:bob, main/restrictionUsers:carol",
		},
		"AllApplied": {
			reason:      "every declared actor stored: condition False, no message",
			declared:    rule([]string{"bob"}, []string{"alice"}, nil),
			stored:      rule([]string{"bob"}, []string{"alice"}, nil),
			wantStatus:  corev1.ConditionFalse,
			wantReason:  reasonAllActorsApplied,
			wantMessage: "",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cr := &v1alpha1.Repository{}
			setBranchProtectionActorPartialCondition(cr, detectUnappliedBranchProtectionActors(tc.declared, tc.stored))
			cond := cr.GetCondition(typeBranchProtectionActorPartial)
			if cond.Status != tc.wantStatus || cond.Reason != tc.wantReason {
				t.Errorf("%s: condition = (%v,%v), want (%v,%v)", tc.reason, cond.Status, cond.Reason, tc.wantStatus, tc.wantReason)
			}
			if cond.Message != tc.wantMessage {
				t.Errorf("%s: message = %q, want %q", tc.reason, cond.Message, tc.wantMessage)
			}
		})
	}
}

func withBypassUser(login string) repositoryModifier {
	return func(r *v1alpha1.Repository) {
		a := r.Spec.ForProvider.BranchProtectionRules[0].RequiredPullRequestReviews.BypassPullRequestAllowances
		a.Users = append(a.Users, login)
	}
}

func withDismissalUser(login string) repositoryModifier {
	return func(r *v1alpha1.Repository) {
		d := r.Spec.ForProvider.BranchProtectionRules[0].RequiredPullRequestReviews.DismissalRestrictions
		users := append(*d.Users, login)
		d.Users = &users
	}
}

// withSecondBranchRule copies the main rule to branch and adds bypassUser to the copy only.
func withSecondBranchRule(branch, bypassUser string) repositoryModifier {
	return func(r *v1alpha1.Repository) {
		rule := r.Spec.ForProvider.BranchProtectionRules[0].DeepCopy()
		rule.Branch = branch
		allowances := rule.RequiredPullRequestReviews.BypassPullRequestAllowances
		allowances.Users = append(allowances.Users, bypassUser)
		r.Spec.ForProvider.BranchProtectionRules = append(r.Spec.ForProvider.BranchProtectionRules, *rule)
	}
}

func withRestrictionTeam(slug, role string) repositoryModifier {
	return func(r *v1alpha1.Repository) {
		restr := r.Spec.ForProvider.BranchProtectionRules[0].BranchProtectionRestrictions
		restr.Teams = append(restr.Teams, slug)
		r.Spec.ForProvider.Permissions.Teams = append(r.Spec.ForProvider.Permissions.Teams, v1alpha1.RepositoryTeam{Team: slug, Role: role})
	}
}

func withRequiredApprovingReviewCount(n int) repositoryModifier {
	return func(r *v1alpha1.Repository) {
		r.Spec.ForProvider.BranchProtectionRules[0].RequiredPullRequestReviews.RequiredApprovingReviewCount = n
	}
}

// A no-write actor must not count as drift; a with-write one must.
func TestObserveBranchProtectionEnforcedActors(t *testing.T) {
	errBoom := errors.New("boom")

	cases := map[string]struct {
		reason       string
		mods         []repositoryModifier
		repoTeams    []*github.Team
		extraBranch  string
		permission   string
		userPerms    map[string]string
		probeErr     error
		wantUpToDate bool
		wantErr      error
		wantStatus   corev1.ConditionStatus
		wantMessage  string
		wantProbes   int
	}{
		"UserReadOnlyEnforced": {
			reason:       "a read-only bypass user is dropped by GitHub: up to date, condition names it",
			mods:         []repositoryModifier{withBypassUser("alice")},
			permission:   "read",
			wantUpToDate: true,
			wantStatus:   corev1.ConditionTrue,
			wantMessage:  "bypass actors not applied by GitHub: main/bypassUsers:alice",
			wantProbes:   1,
		},
		"UserWithWriteIsDrift": {
			reason:       "a bypass user with write would be stored: not up to date, not reported as enforced",
			mods:         []repositoryModifier{withBypassUser("alice")},
			permission:   "write",
			wantUpToDate: false,
			wantStatus:   corev1.ConditionFalse,
			wantProbes:   1,
		},
		"UserNotCollaboratorEnforced": {
			reason:       "a user with no repo access (404) is dropped by GitHub: up to date",
			mods:         []repositoryModifier{withBypassUser("alice")},
			probeErr:     fake.Generate404Response(),
			wantUpToDate: true,
			wantStatus:   corev1.ConditionTrue,
			wantMessage:  "bypass actors not applied by GitHub: main/bypassUsers:alice",
			wantProbes:   1,
		},
		"UserProbeErrorPropagates": {
			reason:     "a non-404 probe failure must surface, not be read as enforced",
			mods:       []repositoryModifier{withBypassUser("alice")},
			probeErr:   errBoom,
			wantErr:    errBoom,
			wantProbes: 1,
		},
		"UserProbedOncePerObserve": {
			reason:       "the same user missing from two fields is probed once",
			mods:         []repositoryModifier{withBypassUser("alice"), withDismissalUser("alice")},
			permission:   "read",
			wantUpToDate: true,
			wantStatus:   corev1.ConditionTrue,
			wantMessage:  "bypass/dismissal actors not applied by GitHub: main/bypassUsers:alice, main/dismissalUsers:alice",
			wantProbes:   1,
		},
		"ReadAndWriteUserMissing": {
			reason:       "an enforced user must not mask a with-write user missing from the same rule",
			mods:         []repositoryModifier{withBypassUser("alice"), withBypassUser("bob")},
			userPerms:    map[string]string{"alice": "read", "bob": "write"},
			wantUpToDate: false,
			wantStatus:   corev1.ConditionTrue,
			wantMessage:  "bypass actors not applied by GitHub: main/bypassUsers:alice",
			wantProbes:   2,
		},
		"EnforcedOnOneBranchDoesNotMaskOther": {
			reason:       "an enforced user on main must not mask a with-write user missing on another branch",
			mods:         []repositoryModifier{withSecondBranchRule("develop", "bob"), withBypassUser("alice")},
			extraBranch:  "develop",
			userPerms:    map[string]string{"alice": "read", "bob": "write"},
			wantUpToDate: false,
			wantStatus:   corev1.ConditionTrue,
			wantMessage:  "bypass actors not applied by GitHub: main/bypassUsers:alice",
			wantProbes:   2,
		},
		"TeamPullEnforced": {
			reason:       "a restriction team with pull is dropped by GitHub: up to date, condition names it",
			mods:         []repositoryModifier{withRestrictionTeam("some-team", "pull")},
			repoTeams:    []*github.Team{{Slug: github.String("some-team"), Permission: github.String("pull")}},
			wantUpToDate: true,
			wantStatus:   corev1.ConditionTrue,
			wantMessage:  "restriction actors not applied by GitHub: main/restrictionTeams:some-team",
		},
		"TeamPushIsDrift": {
			reason:       "a restriction team with push would be stored: not up to date",
			mods:         []repositoryModifier{withRestrictionTeam("some-team", "push")},
			repoTeams:    []*github.Team{{Slug: github.String("some-team"), Permission: github.String("push")}},
			wantUpToDate: false,
			wantStatus:   corev1.ConditionFalse,
		},
		"EnforcedDoesNotMaskOtherDrift": {
			reason:       "stripping an enforced actor must leave unrelated rule drift visible",
			mods:         []repositoryModifier{withBypassUser("alice"), withRequiredApprovingReviewCount(2)},
			permission:   "read",
			wantUpToDate: false,
			wantStatus:   corev1.ConditionTrue,
			wantMessage:  "bypass actors not applied by GitHub: main/bypassUsers:alice",
			wantProbes:   1,
		},
		"NoMissingActorsNoProbe": {
			reason:       "every declared actor stored: no permission probe at steady state",
			wantUpToDate: true,
			wantStatus:   corev1.ConditionFalse,
			wantProbes:   0,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			probes := 0
			gh := &ghclient.Client{
				Services: &ghclient.Services{
					Repositories: &fake.MockRepositoriesClient{
						MockGet: func(ctx context.Context, owner, repo string) (*github.Repository, *github.Response, error) {
							return githubRepository(), nil, nil
						},
						MockListCollaborators: func(ctx context.Context, owner, repo string, opts *github.ListCollaboratorsOptions) ([]*github.User, *github.Response, error) {
							return githubCollaborators(), fake.GenerateEmptyResponse(), nil
						},
						MockListTeams: func(ctx context.Context, owner string, repo string, opts *github.ListOptions) ([]*github.Team, *github.Response, error) {
							return append(githubTeams(), tc.repoTeams...), fake.GenerateEmptyResponse(), nil
						},
						MockListHooks: func(ctx context.Context, owner, repo string, opts *github.ListOptions) ([]*github.Hook, *github.Response, error) {
							return githubWebhooks(), fake.GenerateEmptyResponse(), nil
						},
						MockListBranches: func(ctx context.Context, owner, repo string, opts *github.BranchListOptions) ([]*github.Branch, *github.Response, error) {
							branches := githubBranches()
							if tc.extraBranch != "" {
								branches = append(branches, &github.Branch{Name: github.String(tc.extraBranch), Protected: github.Bool(true)})
							}
							return branches, fake.GenerateEmptyResponse(), nil
						},
						MockGetBranchProtection: func(ctx context.Context, owner, repo, branch string) (*github.Protection, *github.Response, error) {
							return githubProtectedBranch(), fake.GenerateEmptyResponse(), nil
						},
						MockGetPermissionLevel: func(ctx context.Context, owner, repo, user string) (*github.RepositoryPermissionLevel, *github.Response, error) {
							probes++
							if tc.probeErr != nil {
								return nil, fake.GenerateEmptyResponse(), tc.probeErr
							}
							permission := tc.permission
							if p, ok := tc.userPerms[user]; ok {
								permission = p
							}
							return &github.RepositoryPermissionLevel{Permission: github.String(permission)}, fake.GenerateEmptyResponse(), nil
						},
						MockGetAllRulesets: func(ctx context.Context, owner, repo string) ([]*github.Ruleset, *github.Response, error) {
							return githubRuleset(), fake.GenerateEmptyResponse(), nil
						},
						MockGetRuleset: func(ctx context.Context, owner, repo string, rulesetID int64, includesParents bool) (*github.Ruleset, *github.Response, error) {
							return githubRuleset()[0], fake.GenerateEmptyResponse(), nil
						},
					},
				},
			}

			cr := repository(tc.mods...)
			got, err := (&external{github: gh}).Observe(context.Background(), cr)
			if diff := cmp.Diff(tc.wantErr, err, test.EquateErrors()); diff != "" {
				t.Fatalf("%s: Observe(...): -want error, +got error:\n%s", tc.reason, diff)
			}
			if probes != tc.wantProbes {
				t.Errorf("%s: GetPermissionLevel calls = %d, want %d", tc.reason, probes, tc.wantProbes)
			}
			if tc.wantErr != nil {
				return
			}
			if got.ResourceUpToDate != tc.wantUpToDate {
				t.Errorf("%s: ResourceUpToDate = %v, want %v", tc.reason, got.ResourceUpToDate, tc.wantUpToDate)
			}
			cond := cr.GetCondition(typeBranchProtectionActorPartial)
			if cond.Status != tc.wantStatus || cond.Message != tc.wantMessage {
				t.Errorf("%s: condition = (%v, %q), want (%v, %q)", tc.reason, cond.Status, cond.Message, tc.wantStatus, tc.wantMessage)
			}
		})
	}
}

// Stripping must copy, not mutate, and an emptied list must equal GitHub's nil.
func TestWithoutBranchProtectionActors(t *testing.T) {
	declared := func() map[string]v1alpha1.BranchProtectionRule {
		return map[string]v1alpha1.BranchProtectionRule{
			"main": {
				Branch: "main",
				RequiredPullRequestReviews: &v1alpha1.RequiredPullRequestReviews{
					BypassPullRequestAllowances: &v1alpha1.BypassPullRequestAllowancesRequest{Users: []string{"alice", "bob"}},
					DismissalRestrictions:       &v1alpha1.DismissalRestrictionsRequest{Users: &[]string{"alice"}},
				},
				BranchProtectionRestrictions: &v1alpha1.BranchProtectionRestrictions{Teams: []string{"some-team"}},
			},
		}
	}
	stored := map[string]v1alpha1.BranchProtectionRule{
		"main": {
			Branch: "main",
			RequiredPullRequestReviews: &v1alpha1.RequiredPullRequestReviews{
				BypassPullRequestAllowances: &v1alpha1.BypassPullRequestAllowancesRequest{Users: []string{"bob"}},
				DismissalRestrictions:       &v1alpha1.DismissalRestrictionsRequest{},
			},
			BranchProtectionRestrictions: &v1alpha1.BranchProtectionRestrictions{},
		},
	}
	enforced := []branchProtectionActorRef{
		{branch: "main", field: fieldBypassUsers, actor: "alice"},
		{branch: "main", field: fieldDismissalUsers, actor: "alice"},
		{branch: "main", field: fieldRestrictionTeams, actor: "some-team"},
	}

	in := declared()
	got := withoutBranchProtectionActors(in, enforced)

	if diff := cmp.Diff(stored, got); diff != "" {
		t.Errorf("stripped declared rules must equal the stored rules: -want, +got:\n%s", diff)
	}
	if diff := cmp.Diff(declared(), in); diff != "" {
		t.Errorf("declared rules must not be mutated: -want, +got:\n%s", diff)
	}
}
