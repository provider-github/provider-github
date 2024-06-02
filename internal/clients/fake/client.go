package fake

import (
	"context"
	"net/http"

	"github.com/google/go-github/v62/github"
)

type MockActionsClient struct {
	MockListEnabledReposInOrg   func(ctx context.Context, owner string, opts *github.ListOptions) (*github.ActionsEnabledOnOrgRepos, *github.Response, error)
	MockAddEnabledReposInOrg    func(ctx context.Context, owner string, repositoryID int64) (*github.Response, error)
	MockRemoveEnabledReposInOrg func(ctx context.Context, owner string, repositoryID int64) (*github.Response, error)
}

func (m *MockActionsClient) ListEnabledReposInOrg(ctx context.Context, owner string, opts *github.ListOptions) (*github.ActionsEnabledOnOrgRepos, *github.Response, error) {
	return m.MockListEnabledReposInOrg(ctx, owner, opts)
}

func (m *MockActionsClient) AddEnabledReposInOrg(ctx context.Context, owner string, repositoryID int64) (*github.Response, error) {
	return m.MockAddEnabledReposInOrg(ctx, owner, repositoryID)
}

func (m *MockActionsClient) RemoveEnabledReposInOrg(ctx context.Context, owner string, repositoryID int64) (*github.Response, error) {
	return m.MockRemoveEnabledReposInOrg(ctx, owner, repositoryID)
}

type MockOrganizationsClient struct {
	MockGet                 func(ctx context.Context, org string) (*github.Organization, *github.Response, error)
	MockEdit                func(ctx context.Context, name string, org *github.Organization) (*github.Organization, *github.Response, error)
	MockGetOrgMembership    func(ctx context.Context, user, org string) (*github.Membership, *github.Response, error)
	MockCreateOrgInvitation func(ctx context.Context, org string, opts *github.CreateOrgInvitationOptions) (*github.Invitation, *github.Response, error)
	MockEditOrgMembership   func(ctx context.Context, user, org string, membership *github.Membership) (*github.Membership, *github.Response, error)
	MockRemoveOrgMembership func(ctx context.Context, user, org string) (*github.Response, error)
}

func (m *MockOrganizationsClient) Get(ctx context.Context, org string) (*github.Organization, *github.Response, error) {
	return m.MockGet(ctx, org)
}

func (m *MockOrganizationsClient) Edit(ctx context.Context, name string, org *github.Organization) (*github.Organization, *github.Response, error) {
	return m.MockEdit(ctx, name, org)
}

func (m *MockOrganizationsClient) GetOrgMembership(ctx context.Context, user, org string) (*github.Membership, *github.Response, error) {
	return m.MockGetOrgMembership(ctx, user, org)
}

func (m *MockOrganizationsClient) CreateOrgInvitation(ctx context.Context, org string, opts *github.CreateOrgInvitationOptions) (*github.Invitation, *github.Response, error) {
	return m.MockCreateOrgInvitation(ctx, org, opts)
}

func (m *MockOrganizationsClient) EditOrgMembership(ctx context.Context, user, org string, membership *github.Membership) (*github.Membership, *github.Response, error) {
	return m.MockEditOrgMembership(ctx, user, org, membership)
}

func (m *MockOrganizationsClient) RemoveOrgMembership(ctx context.Context, user, org string) (*github.Response, error) {
	return m.MockRemoveOrgMembership(ctx, user, org)
}

type MockUsersClient struct {
	MockGet func(ctx context.Context, user string) (*github.User, *github.Response, error)
}

func (m *MockUsersClient) Get(ctx context.Context, user string) (*github.User, *github.Response, error) {
	return m.MockGet(ctx, user)
}

type MockRepositoriesClient struct {
	MockGet                                 func(ctx context.Context, owner, repo string) (*github.Repository, *github.Response, error)
	MockEdit                                func(ctx context.Context, owner, repo string, repository *github.Repository) (*github.Repository, *github.Response, error)
	MockListTeams                           func(ctx context.Context, owner string, repo string, opts *github.ListOptions) ([]*github.Team, *github.Response, error)
	MockListCollaborators                   func(ctx context.Context, owner, repo string, opts *github.ListCollaboratorsOptions) ([]*github.User, *github.Response, error)
	MockCreate                              func(ctx context.Context, org string, repo *github.Repository) (*github.Repository, *github.Response, error)
	MockCreateFromTemplate                  func(ctx context.Context, templateOwner, templateRepo string, templateRepoReq *github.TemplateRepoRequest) (*github.Repository, *github.Response, error)
	MockCreateFork                          func(ctx context.Context, owner, repo string, opts *github.RepositoryCreateForkOptions) (*github.Repository, *github.Response, error)
	MockAddCollaborator                     func(ctx context.Context, owner, repo, user string, opts *github.RepositoryAddCollaboratorOptions) (*github.CollaboratorInvitation, *github.Response, error)
	MockRemoveCollaborator                  func(ctx context.Context, owner, repo, user string) (*github.Response, error)
	MockDelete                              func(ctx context.Context, owner, repo string) (*github.Response, error)
	MockCreateHook                          func(ctx context.Context, owner, repo string, hook *github.Hook) (*github.Hook, *github.Response, error)
	MockEditHook                            func(ctx context.Context, owner, repo string, id int64, hook *github.Hook) (*github.Hook, *github.Response, error)
	MockDeleteHook                          func(ctx context.Context, owner, repo string, id int64) (*github.Response, error)
	MockListHooks                           func(ctx context.Context, owner, repo string, opts *github.ListOptions) ([]*github.Hook, *github.Response, error)
	MockListBranches                        func(ctx context.Context, owner, repo string, opts *github.BranchListOptions) ([]*github.Branch, *github.Response, error)
	MockGetBranchProtection                 func(ctx context.Context, owner, repo, branch string) (*github.Protection, *github.Response, error)
	MockUpdateBranchProtection              func(ctx context.Context, owner, repo, branch string, preq *github.ProtectionRequest) (*github.Protection, *github.Response, error)
	MockRemoveBranchProtection              func(ctx context.Context, owner, repo, branch string) (*github.Response, error)
	MockRequireSignaturesOnProtectedBranch  func(ctx context.Context, owner, repo, branch string) (*github.SignaturesProtectedBranch, *github.Response, error)
	MockOptionalSignaturesOnProtectedBranch func(ctx context.Context, owner, repo, branch string) (*github.Response, error)
	MockGetAllRulesets                      func(ctx context.Context, owner, repo string) ([]*github.Ruleset, *github.Response, error)
	MockGetRuleset                          func(ctx context.Context, owner, repo string, rulesetID int64, includesParents bool) (*github.Ruleset, *github.Response, error)
	MockCreateRuleset                       func(ctx context.Context, owner, repo string, ruleset *github.Ruleset) (*github.Ruleset, *github.Response, error)
	MockUpdateRuleset                       func(ctx context.Context, owner, repo string, rulesetID int64, ruleset *github.Ruleset) (*github.Ruleset, *github.Response, error)
	MockDeleteRuleset                       func(ctx context.Context, owner, repo string, rulesetID int64) (*github.Response, error)
}

func (m *MockRepositoriesClient) Get(ctx context.Context, owner, repo string) (*github.Repository, *github.Response, error) {
	return m.MockGet(ctx, owner, repo)
}

func (m *MockRepositoriesClient) Edit(ctx context.Context, owner, repo string, repository *github.Repository) (*github.Repository, *github.Response, error) {
	return m.MockEdit(ctx, owner, repo, repository)
}

func (m *MockRepositoriesClient) AddCollaborator(ctx context.Context, owner, repo, user string, opts *github.RepositoryAddCollaboratorOptions) (*github.CollaboratorInvitation, *github.Response, error) {
	return m.MockAddCollaborator(ctx, owner, repo, user, opts)
}

func (m *MockRepositoriesClient) Create(ctx context.Context, org string, repo *github.Repository) (*github.Repository, *github.Response, error) {
	return m.MockCreate(ctx, org, repo)
}

func (m *MockRepositoriesClient) CreateFromTemplate(ctx context.Context, templateOwner, templateRepo string, templateRepoReq *github.TemplateRepoRequest) (*github.Repository, *github.Response, error) {
	return m.MockCreateFromTemplate(ctx, templateOwner, templateRepo, templateRepoReq)
}

func (m *MockRepositoriesClient) CreateFork(ctx context.Context, owner, repo string, opts *github.RepositoryCreateForkOptions) (*github.Repository, *github.Response, error) {
	return m.MockCreateFork(ctx, owner, repo, opts)
}

func (m *MockRepositoriesClient) Delete(ctx context.Context, owner, repo string) (*github.Response, error) {
	return m.MockDelete(ctx, owner, repo)
}

func (m *MockRepositoriesClient) ListCollaborators(ctx context.Context, owner, repo string, opts *github.ListCollaboratorsOptions) ([]*github.User, *github.Response, error) {
	return m.MockListCollaborators(ctx, owner, repo, opts)
}

func (m *MockRepositoriesClient) ListTeams(ctx context.Context, owner string, repo string, opts *github.ListOptions) ([]*github.Team, *github.Response, error) {
	return m.MockListTeams(ctx, owner, repo, opts)
}

func (m *MockRepositoriesClient) RemoveCollaborator(ctx context.Context, owner, repo, user string) (*github.Response, error) {
	return m.MockRemoveCollaborator(ctx, owner, repo, user)
}

func (m *MockRepositoriesClient) CreateHook(ctx context.Context, owner, repo string, hook *github.Hook) (*github.Hook, *github.Response, error) {
	return m.MockCreateHook(ctx, owner, repo, hook)
}

func (m *MockRepositoriesClient) EditHook(ctx context.Context, owner, repo string, id int64, hook *github.Hook) (*github.Hook, *github.Response, error) {
	return m.MockEditHook(ctx, owner, repo, id, hook)
}

func (m *MockRepositoriesClient) DeleteHook(ctx context.Context, owner, repo string, id int64) (*github.Response, error) {
	return m.MockDeleteHook(ctx, owner, repo, id)
}

func (m *MockRepositoriesClient) ListHooks(ctx context.Context, owner, repo string, opts *github.ListOptions) ([]*github.Hook, *github.Response, error) {
	return m.MockListHooks(ctx, owner, repo, opts)
}

func (m *MockRepositoriesClient) ListBranches(ctx context.Context, owner, repo string, opts *github.BranchListOptions) ([]*github.Branch, *github.Response, error) {
	return m.MockListBranches(ctx, owner, repo, opts)
}

func (m *MockRepositoriesClient) GetBranchProtection(ctx context.Context, owner, repo, branch string) (*github.Protection, *github.Response, error) {
	return m.MockGetBranchProtection(ctx, owner, repo, branch)
}

func (m *MockRepositoriesClient) UpdateBranchProtection(ctx context.Context, owner, repo, branch string, preq *github.ProtectionRequest) (*github.Protection, *github.Response, error) {
	return m.MockUpdateBranchProtection(ctx, owner, repo, branch, preq)
}

func (m *MockRepositoriesClient) RemoveBranchProtection(ctx context.Context, owner, repo, branch string) (*github.Response, error) {
	return m.MockRemoveBranchProtection(ctx, owner, repo, branch)
}

func (m *MockRepositoriesClient) RequireSignaturesOnProtectedBranch(ctx context.Context, owner, repo, branch string) (*github.SignaturesProtectedBranch, *github.Response, error) {
	return m.MockRequireSignaturesOnProtectedBranch(ctx, owner, repo, branch)
}

func (m *MockRepositoriesClient) OptionalSignaturesOnProtectedBranch(ctx context.Context, owner, repo, branch string) (*github.Response, error) {
	return m.MockOptionalSignaturesOnProtectedBranch(ctx, owner, repo, branch)
}

func (m *MockRepositoriesClient) GetAllRulesets(ctx context.Context, owner, repo string, includesParents bool) ([]*github.Ruleset, *github.Response, error) {
	return m.MockGetAllRulesets(ctx, owner, repo)
}

func (m *MockRepositoriesClient) GetRuleset(ctx context.Context, owner, repo string, rulesetID int64, includesParents bool) (*github.Ruleset, *github.Response, error) {
	return m.MockGetRuleset(ctx, owner, repo, rulesetID, includesParents)
}

func (m *MockRepositoriesClient) CreateRuleset(ctx context.Context, owner, repo string, ruleset *github.Ruleset) (*github.Ruleset, *github.Response, error) {
	return m.MockCreateRuleset(ctx, owner, repo, ruleset)
}

func (m *MockRepositoriesClient) UpdateRuleset(ctx context.Context, owner, repo string, rulesetID int64, ruleset *github.Ruleset) (*github.Ruleset, *github.Response, error) {
	return m.MockUpdateRuleset(ctx, owner, repo, rulesetID, ruleset)
}

func (m *MockRepositoriesClient) DeleteRuleset(ctx context.Context, owner, repo string, rulesetID int64) (*github.Response, error) {
	return m.MockDeleteRuleset(ctx, owner, repo, rulesetID)
}

type MockTeamsClient struct {
	MockGetTeamBySlug              func(ctx context.Context, org, slug string) (*github.Team, *github.Response, error)
	MockListTeamMembersBySlug      func(ctx context.Context, org, slug string, opts *github.TeamListTeamMembersOptions) ([]*github.User, *github.Response, error)
	MockCreateTeam                 func(ctx context.Context, org string, team github.NewTeam) (*github.Team, *github.Response, error)
	MockAddTeamMembershipBySlug    func(ctx context.Context, org, slug, user string, opts *github.TeamAddTeamMembershipOptions) (*github.Membership, *github.Response, error)
	MockRemoveTeamMembershipBySlug func(ctx context.Context, org, slug, user string) (*github.Response, error)
	MockEditTeamBySlug             func(ctx context.Context, org, slug string, team github.NewTeam, removeParent bool) (*github.Team, *github.Response, error)
	MockDeleteTeamBySlug           func(ctx context.Context, org, slug string) (*github.Response, error)
	MockAddTeamRepoBySlug          func(ctx context.Context, org, slug, owner, repo string, opts *github.TeamAddTeamRepoOptions) (*github.Response, error)
	MockRemoveTeamRepoBySlug       func(ctx context.Context, org, slug, owner, repo string) (*github.Response, error)
}

func (m *MockTeamsClient) RemoveTeamRepoBySlug(ctx context.Context, org, slug, owner, repo string) (*github.Response, error) {
	return m.MockRemoveTeamRepoBySlug(ctx, org, slug, owner, repo)
}

func (m *MockTeamsClient) RemoveTeamMembershipBySlug(ctx context.Context, org, slug, user string) (*github.Response, error) {
	return m.MockRemoveTeamMembershipBySlug(ctx, org, slug, user)
}

func (m *MockTeamsClient) ListTeamMembersBySlug(ctx context.Context, org, slug string, opts *github.TeamListTeamMembersOptions) ([]*github.User, *github.Response, error) {
	return m.MockListTeamMembersBySlug(ctx, org, slug, opts)
}

func (m *MockTeamsClient) EditTeamBySlug(ctx context.Context, org, slug string, team github.NewTeam, removeParent bool) (*github.Team, *github.Response, error) {
	return m.MockEditTeamBySlug(ctx, org, slug, team, removeParent)
}

func (m *MockTeamsClient) DeleteTeamBySlug(ctx context.Context, org, slug string) (*github.Response, error) {
	return m.MockDeleteTeamBySlug(ctx, org, slug)
}

func (m *MockTeamsClient) CreateTeam(ctx context.Context, org string, team github.NewTeam) (*github.Team, *github.Response, error) {
	return m.MockCreateTeam(ctx, org, team)
}

func (m *MockTeamsClient) GetTeamBySlug(ctx context.Context, org, slug string) (*github.Team, *github.Response, error) {
	return m.MockGetTeamBySlug(ctx, org, slug)
}

func (m *MockTeamsClient) AddTeamMembershipBySlug(ctx context.Context, org, slug, user string, opts *github.TeamAddTeamMembershipOptions) (*github.Membership, *github.Response, error) {
	return m.MockAddTeamMembershipBySlug(ctx, org, slug, user, opts)
}

func (m *MockTeamsClient) AddTeamRepoBySlug(ctx context.Context, org, slug, owner, repo string, opts *github.TeamAddTeamRepoOptions) (*github.Response, error) {
	return m.MockAddTeamRepoBySlug(ctx, org, slug, owner, repo, opts)
}

func Generate404Response() *github.ErrorResponse {
	return &github.ErrorResponse{
		Response: &http.Response{
			StatusCode: 404,
		},
	}
}

func GenerateEmptyResponse() *github.Response {
	return &github.Response{
		NextPage: 0,
	}
}
