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

package v1alpha1

import (
	"reflect"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
)

// RepositoryParameters are the configurable fields of a Repository.
type RepositoryParameters struct {
	Description string                `json:"description,omitempty"`
	Permissions RepositoryPermissions `json:"permissions,omitempty"`

	Webhooks []RepositoryWebhook `json:"webhooks,omitempty"`

	BranchProtectionRules []BranchProtectionRule `json:"branchProtectionRules,omitempty"`

	// RepositoryRules are the rulesets of the repository. When set, the list is
	// authoritative: the repository ends up with exactly the rulesets it names, and
	// an empty list ([]) deletes them all. When the field is absent, the rulesets
	// on GitHub stay as they are. GitHub allows at most 75 rulesets per repository.
	// +kubebuilder:validation:MaxItems=75
	// +kubebuilder:validation:XValidation:rule="self.all(x, self.exists_one(y, y.name == x.name))",message="each ruleset name may appear once in repositoryRules"
	RepositoryRules *[]RepositoryRuleset `json:"repositoryRules,omitempty"`

	// Creates a new repository using a repository template
	CreateFromTemplate *TemplateRepo `json:"createFromTemplate,omitempty"`

	// Creates a repository fork, it takes precedence over "CreateFromTemplate" setting.
	CreateFork *RepoFork `json:"createFork,omitempty"`

	// Org is the Organization for the Membership
	// +immutable
	// +crossplane:generate:reference:type=Organization
	Org string `json:"org,omitempty"`

	// OrgRef is a reference to an Organization
	// +optional
	OrgRef *xpv1.Reference `json:"orgRef,omitempty"`

	// OrgSlector selects a reference to an Organization
	// +optional
	OrgSelector *xpv1.Selector `json:"orgSelector,omitempty"`

	// Archived sets if a repository should be archived on delete
	// +optional
	Archived *bool `json:"archived,omitempty"`

	// Safeguard for accidental deletion
	ForceDelete *bool `json:"forceDelete,omitempty"`

	// Private sets the repository to private, if false it will be public
	Private *bool `json:"private,omitempty"`

	// Set to true to make this repo available as a template repository.
	// Default: false
	// +optional
	IsTemplate *bool `json:"isTemplate,omitempty"`

	// Topics is the list of topics for the repository.
	// Topics help categorize and discover repositories.
	// +optional
	// +kubebuilder:validation:MaxItems=20
	Topics []string `json:"topics,omitempty"`

	// DefaultBranch is the name of the default branch.
	// +optional
	DefaultBranch *string `json:"defaultBranch,omitempty"`

	// AllowMergeCommit allows merge commits on the repository.
	// +optional
	AllowMergeCommit *bool `json:"allowMergeCommit,omitempty"`

	// AllowSquashMerge allows squash merging on the repository.
	// +optional
	AllowSquashMerge *bool `json:"allowSquashMerge,omitempty"`

	// AllowRebaseMerge allows rebase merging on the repository.
	// +optional
	AllowRebaseMerge *bool `json:"allowRebaseMerge,omitempty"`

	// AllowAutoMerge allows auto-merge on the repository.
	// Requires GitHub Pro/Team/Enterprise or a public repository; on a free-tier
	// org's private repo, GitHub silently rejects setting this to true, which
	// causes a reconcile loop.
	// +optional
	AllowAutoMerge *bool `json:"allowAutoMerge,omitempty"`

	// AllowUpdateBranch allows users to update pull request branches from the base branch.
	// +optional
	AllowUpdateBranch *bool `json:"allowUpdateBranch,omitempty"`

	// DeleteBranchOnMerge deletes head branches automatically when pull requests merge.
	// +optional
	DeleteBranchOnMerge *bool `json:"deleteBranchOnMerge,omitempty"`

	// HasIssues enables the Issues feature on the repository.
	// +optional
	HasIssues *bool `json:"hasIssues,omitempty"`

	// HasProjects enables the Projects feature on the repository.
	// +optional
	HasProjects *bool `json:"hasProjects,omitempty"`

	// HasWiki enables the Wiki feature on the repository.
	// +optional
	HasWiki *bool `json:"hasWiki,omitempty"`

	// HasDiscussions enables the Discussions feature on the repository.
	// +optional
	HasDiscussions *bool `json:"hasDiscussions,omitempty"`

	// MergeCommitTitle sets the default title format for merge commits.
	// Requires AllowMergeCommit to be true; GitHub rejects the request otherwise.
	// +optional
	// +kubebuilder:validation:Enum=PR_TITLE;MERGE_MESSAGE
	MergeCommitTitle *string `json:"mergeCommitTitle,omitempty"`

	// MergeCommitMessage sets the default body format for merge commits.
	// Requires AllowMergeCommit to be true; GitHub rejects the request otherwise.
	// +optional
	// +kubebuilder:validation:Enum=PR_BODY;PR_TITLE;BLANK
	MergeCommitMessage *string `json:"mergeCommitMessage,omitempty"`

	// SquashMergeCommitTitle sets the default title format for squash-merge commits.
	// Requires AllowSquashMerge to be true; GitHub rejects the request otherwise.
	// +optional
	// +kubebuilder:validation:Enum=PR_TITLE;COMMIT_OR_PR_TITLE
	SquashMergeCommitTitle *string `json:"squashMergeCommitTitle,omitempty"`

	// SquashMergeCommitMessage sets the default body format for squash-merge commits.
	// Requires AllowSquashMerge to be true; GitHub rejects the request otherwise.
	// +optional
	// +kubebuilder:validation:Enum=PR_BODY;COMMIT_MESSAGES;BLANK
	SquashMergeCommitMessage *string `json:"squashMergeCommitMessage,omitempty"`
}

// RepositoryParameters are the configurable fields of a Repository.
type RepositoryPermissions struct {
	Users []RepositoryUser `json:"users,omitempty"`
	Teams []RepositoryTeam `json:"teams,omitempty"`
}

type RepositoryUser struct {
	// Name is the name of the user
	// +crossplane:generate:reference:type=Membership
	User string `json:"user,omitempty"`

	// Name is a reference to an Membership
	// +optional
	UserRef *xpv1.Reference `json:"userRef,omitempty"`

	// NameSelector selects a reference to an Organization
	// +optional
	UserSelector *xpv1.Selector `json:"userSelector,omitempty"`

	// Role is the role of the user
	Role string `json:"role"`
}

type RepositoryTeam struct {
	// Team is the name of the team
	// +crossplane:generate:reference:type=Team
	Team string `json:"team,omitempty"`

	// TeamRef is a reference to a Team
	// +optional
	TeamRef *xpv1.Reference `json:"teamRef,omitempty"`

	// TeamSelector selects a reference to a Team
	// +optional
	TeamSelector *xpv1.Selector `json:"teamSelector,omitempty"`

	// Role is the role of the team
	Role string `json:"role"`
}

// Repository webhook
// https://docs.github.com/en/webhooks/types-of-webhooks#repository-webhooks
type RepositoryWebhook struct {
	// The URL to which the payloads will be delivered.
	Url string `json:"url"`

	// Determines whether the SSL certificate of the host for url will be verified when delivering payloads.
	// We strongly recommend not setting this to true as you are subject to man-in-the-middle and other attacks.
	// Default: false
	// +optional
	InsecureSsl *bool `json:"insecureSsl,omitempty"`

	// The media type used to serialize the payloads. Supported values include json and form.
	// +kubebuilder:validation:Enum=json;form
	ContentType string `json:"contentType"`

	// Webhook secret, see https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries
	// Internal field not exposed to Kubernetes API
	Secret *string `json:"-"`

	// Reference to a secret key containing the webhook secret.
	// You can use the webhook secret to limit incoming requests to only those originating from GitHub.
	// For more information, see https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries
	// +optional
	SecretKeyRef *xpv1.SecretKeySelector `json:"secretKeyRef,omitempty"`

	// Determines what events the hook is triggered for. See https://docs.github.com/en/webhooks/webhook-events-and-payloads
	Events []string `json:"events"`

	// Determines if notifications are sent when the webhook is triggered.
	// Default: true
	// +optional
	Active *bool `json:"active,omitempty"`
}

// BranchProtectionRule represents a rule for protecting a branch in a repository.
// It includes various parameters for enforcing code quality and access control.
type BranchProtectionRule struct {
	// The branch name to apply the protection rule to.
	Branch string `json:"branch"`

	// Require status checks to pass before merging.
	// When enabled, commits must first be pushed to another branch,
	// then merged or pushed directly to a branch that matches this rule after status checks have passed.
	// +optional
	RequiredStatusChecks *RequiredStatusChecks `json:"requiredStatusChecks,omitempty"`

	// Require a pull request before merging.
	// When enabled, all commits must be made to a non-protected branch and submitted via a pull request
	// before they can be merged into a branch that matches this rule.
	// +optional
	RequiredPullRequestReviews *RequiredPullRequestReviews `json:"requiredPullRequestReviews,omitempty"`

	// Restrict who can push to matching branches.
	// Specify people, teams, or apps allowed to push to matching branches.
	// Required status checks will still prevent these people, teams, and apps from merging if the checks fail.
	// +optional
	BranchProtectionRestrictions *BranchProtectionRestrictions `json:"branchProtectionRestrictions,omitempty"`

	// Enforce settings even for administrators and custom roles with the "bypass branch protections" permission.
	EnforceAdmins bool `json:"enforceAdmins"`

	// Prevent merge commits from being pushed to matching branches.
	// Default: false
	// +optional
	RequireLinearHistory *bool `json:"requireLinearHistory,omitempty"`

	// Permit force pushes for all users with push access.
	// Default: false
	// +optional
	AllowForcePushes *bool `json:"allowForcePushes,omitempty"`

	// Allow users with push access to delete matching branches.
	// Default: false
	// +optional
	AllowDeletions *bool `json:"allowDeletions,omitempty"`

	// When enabled, all conversations on code must be resolved before a pull request can be merged into a branch that matches this rule.
	// Default: false
	// +optional
	RequiredConversationResolution *bool `json:"requiredConversationResolution,omitempty"`

	// Branch is read-only. Users cannot push to the branch.
	// Default: false
	// +optional
	LockBranch *bool `json:"lockBranch,omitempty"`

	// Will allow users to pull changes from upstream when the branch is locked.
	// Default: false
	// +optional
	AllowForkSyncing *bool `json:"allowForkSyncing,omitempty"`

	// Commits pushed to matching branches must have verified signatures.
	// Default: false
	// +optional
	RequireSignedCommits *bool `json:"requireSignedCommits,omitempty"`
}

// RequiredStatusChecks represents the configuration for required status checks to apply to a branch protection rule.
type RequiredStatusChecks struct {
	// Require branches to be up-to-date before merging.
	Strict bool `json:"strict"`

	// The list of status checks to require in order to merge into this branch.
	Checks []*RequiredStatusCheck `json:"checks"`
}

// RequiredStatusCheck represents the configuration for a single check
type RequiredStatusCheck struct {
	// The name of the required check.
	Context string `json:"context"`

	// The ID of the GitHub App that must provide this check.
	// Omit this field to explicitly allow any app to set the status.
	// +kubebuilder:validation:Minimum=2
	// +optional
	AppID *int64 `json:"appId,omitempty"`
}

// RequiredPullRequestReviews represents the required reviews for a pull request before merging.
type RequiredPullRequestReviews struct {
	// Set to true if you want to automatically dismiss approving reviews when someone pushes a new commit.
	DismissStaleReviews bool `json:"dismissStaleReviews"`

	// Blocks merging pull requests until code owners review them.
	RequireCodeOwnerReviews bool `json:"requireCodeOwnerReviews"`

	// Specify the number of reviewers required to approve pull requests. Use a number between 1 and 6 or 0 to not require reviewers.
	RequiredApprovingReviewCount int `json:"requiredApprovingReviewCount"`

	// Whether the most recent push must be approved by someone other than the person who pushed it.
	// Default: false
	// +optional
	RequireLastPushApproval *bool `json:"requireLastPushApproval,omitempty"`

	// Allow specific users, teams, or apps to bypass pull request requirements.
	// +optional
	BypassPullRequestAllowances *BypassPullRequestAllowancesRequest `json:"bypassPullRequestAllowances,omitempty"`

	// Specify which users, teams, and apps can dismiss pull request reviews.
	// +optional
	DismissalRestrictions *DismissalRestrictionsRequest `json:"dismissalRestrictions,omitempty"`
}

type BypassPullRequestAllowancesRequest struct {
	// The list of user logins allowed to bypass pull request requirements.
	// +optional
	Users []string `json:"users,omitempty"`

	// The list of team slugs allowed to bypass pull request requirements.
	// +optional
	Teams []string `json:"teams,omitempty"`

	// The list of app slugs allowed to bypass pull request requirements.
	// +optional
	Apps []string `json:"apps,omitempty"`
}

type DismissalRestrictionsRequest struct {
	// The list of user logins with dismissal access.
	// +optional
	Users *[]string `json:"users,omitempty"`

	// The list of team slugs with dismissal access.
	// +optional
	Teams *[]string `json:"teams,omitempty"`

	// The list of app slugs with dismissal access.
	// +optional
	Apps *[]string `json:"apps,omitempty"`
}

// BranchProtectionRestrictions defines the restrictions to apply to a branch protection rule.
type BranchProtectionRestrictions struct {
	// If set to true, will cause the restrictions setting to also block pushes which create new branches
	// unless initiated by a user, team, app with the ability to push.
	// Default: false
	// +optional
	BlockCreations *bool `json:"blockCreations,omitempty"`

	// Only people allowed to push will be able to create new branches matching this rule.
	// +optional
	Users []string `json:"users,omitempty"`

	// Only teams allowed to push will be able to create new branches matching this rule.
	// +optional
	Teams []string `json:"teams,omitempty"`

	// Only apps allowed to push will be able to create new branches matching this rule.
	// +optional
	Apps []string `json:"apps,omitempty"`
}

// RepositoryRuleset represents the rules for a repository
type RepositoryRuleset struct {
	// Name is the name of the ruleset
	// +kubebuilder:validation:MaxLength=255
	Name string `json:"name"`
	// Enforcement is the enforcement level of the ruleset, one of "disabled", "active" or
	// "evaluate" (GitHub Enterprise only). Defaults to "active".
	// +kubebuilder:validation:Enum=disabled;active;evaluate
	// +optional
	Enforcement *string `json:"enforcement,omitempty"`
	// Target is what the ruleset applies to, one of "branch", "tag" or "push". Defaults to "branch".
	// +kubebuilder:validation:Enum=branch;tag;push
	// +optional
	Target *string `json:"target,omitempty"`
	// BypassActors is the list of actors that can bypass the ruleset. An empty list
	// makes the ruleset apply to everyone. Each actor is listed once: an unset BypassMode
	// counts as "always", and OrganizationAdmin and DeployKey match on ActorType and BypassMode.
	// +optional
	BypassActors []*RulesetByPassActors `json:"bypassActors"`
	// Conditions is the conditions for the ruleset, which branches or tags are included or excluded from the ruleset.
	// Branch and tag rulesets only. A push ruleset applies to every push.
	// +optional
	Conditions *RulesetConditions `json:"conditions,omitempty"`
	// Rules is the rules for the ruleset
	// +optional
	Rules *Rules `json:"rules,omitempty"`
}

type RulesetByPassActors struct {
	// ActorId is the ID of the actor: the App ID for Integration, the role ID for
	// RepositoryRole, the team ID for Team and the user ID for User. OrganizationAdmin
	// and DeployKey are identified by their type alone, so ActorId is optional for them.
	// +optional
	ActorId *int64 `json:"actorId,omitempty"`
	// ActorType is the type of the actor, one of: Integration, OrganizationAdmin, RepositoryRole, Team, DeployKey, User
	// +optional
	ActorType *string `json:"actorType,omitempty"`
	// BypassMode is the bypass mode of the actor, one of: "always", "pull_request", "exempt"
	// +kubebuilder:validation:Enum=always;pull_request;exempt
	// +optional
	BypassMode *string `json:"bypassMode,omitempty"`
}

type RulesetConditions struct {
	// RefName selects the refs the ruleset applies to. Unset selects an empty set of refs.
	// +optional
	RefName *RulesetRefName `json:"refName,omitempty"`
}

type RulesetRefName struct {
	// Include is the list of refs to include: full ref patterns such as
	// "refs/heads/main" or "refs/tags/v*", or "~DEFAULT_BRANCH" or "~ALL". Each pattern is listed once.
	Include []string `json:"include"`
	// Exclude is the list of refs to exclude, in the same form as Include. Each pattern is listed once.
	Exclude []string `json:"exclude"`
}

type Rules struct {
	// Creation restricts the creation of matching branches or tags that are set in Conditions
	// +optional
	Creation *bool `json:"creation,omitempty"`
	// Deletion restricts the deletion of matching branches or tags that are set in Conditions
	// +optional
	Deletion *bool `json:"deletion,omitempty"`
	// Update restricts the update of matching branches or tags that are set in Conditions
	// +optional
	Update *bool `json:"update,omitempty"`
	// UpdateAllowsFetchAndMerge lets the branch pull changes from its upstream repository
	// while Update is on. Defaults to false. It takes effect on forks only.
	// +optional
	UpdateAllowsFetchAndMerge *bool `json:"updateAllowsFetchAndMerge,omitempty"`
	// RequiredLinearHistory requires a linear commit history, which prevents merge commits.
	// +optional
	RequiredLinearHistory *bool `json:"requiredLinearHistory,omitempty"`
	// RequiredDeployments requires that deployment to specific environments are successful before merging.
	// +optional
	RequiredDeployments *RulesRequiredDeployments `json:"requiredDeployments,omitempty"`
	// RequiredSignatures requires signed commits.
	// +optional
	RequiredSignatures *bool `json:"requiredSignatures,omitempty"`
	// PullRequest is the rules for pull requests
	// +optional
	PullRequest *RulesPullRequest `json:"pullRequest,omitempty"`
	// RequiredStatusChecks requires status checks to pass before merging.
	// +optional
	RequiredStatusChecks *RulesRequiredStatusChecks `json:"requiredStatusChecks,omitempty"`
	// NonFastForward restricts force pushes to matching branches or tags that are set in Conditions
	// +optional
	NonFastForward *bool `json:"nonFastForward,omitempty"`
	// MergeQueue requires merges to go through a merge queue.
	// +optional
	MergeQueue *RulesMergeQueue `json:"mergeQueue,omitempty"`
	// CommitMessagePattern requires commit messages to match a pattern.
	// +optional
	CommitMessagePattern *RulesPattern `json:"commitMessagePattern,omitempty"`
	// CommitAuthorEmailPattern requires commit author emails to match a pattern.
	// +optional
	CommitAuthorEmailPattern *RulesPattern `json:"commitAuthorEmailPattern,omitempty"`
	// CommitterEmailPattern requires committer emails to match a pattern.
	// +optional
	CommitterEmailPattern *RulesPattern `json:"committerEmailPattern,omitempty"`
	// BranchNamePattern requires branch names to match a pattern.
	// +optional
	BranchNamePattern *RulesPattern `json:"branchNamePattern,omitempty"`
	// TagNamePattern requires tag names to match a pattern.
	// +optional
	TagNamePattern *RulesPattern `json:"tagNamePattern,omitempty"`
	// CodeScanning requires code scanning results before merging.
	// +optional
	CodeScanning *RulesCodeScanning `json:"codeScanning,omitempty"`
	// CodeQuality requires code quality results before merging.
	// +optional
	CodeQuality *RulesCodeQuality `json:"codeQuality,omitempty"`
	// CodeCoverage requires code coverage results before merging.
	// +optional
	CodeCoverage *RulesCodeCoverage `json:"codeCoverage,omitempty"`
	// LicenseComplianceScanning requires license compliance scanning results before merging.
	// It needs license compliance scanning enabled on GitHub, or GitHub answers 422.
	// +optional
	LicenseComplianceScanning *bool `json:"licenseComplianceScanning,omitempty"`
	// RequireSecretScanningAlertResolution blocks merging pull requests with unresolved secret
	// scanning alerts. {} turns it on for GitHub's default secret types. It needs GitHub Secret
	// Protection or Advanced Security enabled, or GitHub answers 422.
	// +optional
	RequireSecretScanningAlertResolution *RulesSecretScanningAlertResolution `json:"requireSecretScanningAlertResolution,omitempty"`
	// CopilotCodeReview requests a Copilot code review for new pull requests.
	// +optional
	CopilotCodeReview *RulesCopilotCodeReview `json:"copilotCodeReview,omitempty"`
	// FileExtensionRestriction prevents pushing files with the listed extensions. Push rulesets only.
	// +optional
	FileExtensionRestriction *RulesFileExtensionRestriction `json:"fileExtensionRestriction,omitempty"`
	// FilePathRestriction prevents pushing changes to the listed file paths. Push rulesets only.
	// +optional
	FilePathRestriction *RulesFilePathRestriction `json:"filePathRestriction,omitempty"`
	// MaxFilePathLength prevents pushing files with longer paths. Push rulesets only.
	// +optional
	MaxFilePathLength *RulesMaxFilePathLength `json:"maxFilePathLength,omitempty"`
	// MaxFileSize prevents pushing files larger than the limit. Push rulesets only.
	// +optional
	MaxFileSize *RulesMaxFileSize `json:"maxFileSize,omitempty"`
}

type RulesMergeQueue struct {
	// CheckResponseTimeoutMinutes is the maximum time, in minutes, for a required status check to report a conclusion.
	CheckResponseTimeoutMinutes int `json:"checkResponseTimeoutMinutes"`
	// GroupingStrategy decides which pull requests' checks must pass: all of them (ALLGREEN) or the head of the group (HEADGREEN).
	// +kubebuilder:validation:Enum=ALLGREEN;HEADGREEN
	GroupingStrategy string `json:"groupingStrategy"`
	// MaxEntriesToBuild is the maximum number of queued pull requests requesting checks and workflow runs at the same time.
	MaxEntriesToBuild int `json:"maxEntriesToBuild"`
	// MaxEntriesToMerge is the maximum number of pull requests merged together in a group.
	MaxEntriesToMerge int `json:"maxEntriesToMerge"`
	// MergeMethod is the method used to merge changes in queued pull requests.
	// +kubebuilder:validation:Enum=MERGE;SQUASH;REBASE
	MergeMethod string `json:"mergeMethod"`
	// MinEntriesToMerge is the minimum number of pull requests merged together in a group.
	MinEntriesToMerge int `json:"minEntriesToMerge"`
	// MinEntriesToMergeWaitMinutes is the time, in minutes, the merge queue waits for MinEntriesToMerge pull requests.
	MinEntriesToMergeWaitMinutes int `json:"minEntriesToMergeWaitMinutes"`
}

type RulesPattern struct {
	// Name is how this rule appears to users.
	// +optional
	Name *string `json:"name,omitempty"`
	// Negate inverts the rule: matching the pattern fails it.
	// +optional
	Negate *bool `json:"negate,omitempty"`
	// Operator is how the pattern is matched.
	// +kubebuilder:validation:Enum=starts_with;ends_with;contains;regex
	Operator string `json:"operator"`
	// Pattern is the pattern to match with.
	Pattern string `json:"pattern"`
}

type RulesCodeScanning struct {
	// CodeScanningTools is the list of tools that must provide code scanning results.
	CodeScanningTools []*RulesCodeScanningTool `json:"codeScanningTools"`
}

type RulesCodeScanningTool struct {
	// Tool is the name of a code scanning tool.
	Tool string `json:"tool"`
	// AlertsThreshold is the severity level at which code scanning results that raise alerts block a reference update.
	// +kubebuilder:validation:Enum=none;errors;errors_and_warnings;all
	AlertsThreshold string `json:"alertsThreshold"`
	// SecurityAlertsThreshold is the severity level at which code scanning results that raise security alerts block a reference update.
	// +kubebuilder:validation:Enum=none;critical;high_or_higher;medium_or_higher;all
	SecurityAlertsThreshold string `json:"securityAlertsThreshold"`
}

type RulesCodeQuality struct {
	// Severity is the lowest severity of code quality results that blocks a pull request.
	// +kubebuilder:validation:Enum=errors;warnings;notes;all
	Severity string `json:"severity"`
}

type RulesCodeCoverage struct {
	// MinimumCoverage is the lowest coverage percentage allowed, a decimal number from 0 to 100 such as "80" or "72.5".
	// Unset leaves the minimum open.
	// +kubebuilder:validation:Pattern=`^(100(\.0+)?|[0-9]{1,2}(\.[0-9]+)?)$`
	// +optional
	MinimumCoverage *string `json:"minimumCoverage,omitempty"`
	// MaxCoverageDrop is the largest drop in coverage percentage allowed, a decimal number from 0 to 100 such as "5" or "0.5".
	// Unset leaves the drop open.
	// +kubebuilder:validation:Pattern=`^(100(\.0+)?|[0-9]{1,2}(\.[0-9]+)?)$`
	// +optional
	MaxCoverageDrop *string `json:"maxCoverageDrop,omitempty"`
}

// RulesSecretType is a kind of secret scanning alert.
// +kubebuilder:validation:Enum=provider_patterns;custom_patterns;generic_patterns
type RulesSecretType string

type RulesSecretScanningAlertResolution struct {
	// SecretTypes are the kinds of alerts that must be resolved, each listed once. Unset or
	// empty means provider_patterns, GitHub's default.
	// +kubebuilder:validation:MaxItems=3
	// +kubebuilder:validation:XValidation:rule="self.all(x, self.exists_one(y, y == x))",message="each secret type may appear once in secretTypes"
	// +optional
	SecretTypes []RulesSecretType `json:"secretTypes,omitempty"`
}

type RulesCopilotCodeReview struct {
	// ReviewOnPush requests a new review on each push to the pull request.
	// +optional
	ReviewOnPush *bool `json:"reviewOnPush,omitempty"`
	// ReviewDraftPullRequests requests reviews on draft pull requests too.
	// +optional
	ReviewDraftPullRequests *bool `json:"reviewDraftPullRequests,omitempty"`
}

type RulesFileExtensionRestriction struct {
	// RestrictedFileExtensions is the list of file extensions GitHub rejects in a push, each starting with "*.", such as "*.exe".
	RestrictedFileExtensions []string `json:"restrictedFileExtensions"`
}

type RulesFilePathRestriction struct {
	// RestrictedFilePaths is the list of file paths GitHub rejects changes to.
	RestrictedFilePaths []string `json:"restrictedFilePaths"`
	// IgnoredFilePaths are paths exempt from the rule. Unset means an empty list.
	// +optional
	IgnoredFilePaths []string `json:"ignoredFilePaths,omitempty"`
}

type RulesMaxFilePathLength struct {
	// MaxFilePathLength is the maximum number of characters allowed in file paths.
	MaxFilePathLength int `json:"maxFilePathLength"`
}

type RulesMaxFileSize struct {
	// MaxFileSize is the maximum file size allowed, in megabytes.
	MaxFileSize int64 `json:"maxFileSize"`
	// IgnoredFilePaths are paths exempt from the rule. Unset means an empty list.
	// +optional
	IgnoredFilePaths []string `json:"ignoredFilePaths,omitempty"`
}

type RulesRequiredDeployments struct {
	// Environments is the list of environments that are required to be deployed to before merging
	// +optional
	Environments []string `json:"environments,omitempty"`
}

// RulesMergeMethod is a method a pull request may be merged with.
// +kubebuilder:validation:Enum=merge;squash;rebase
type RulesMergeMethod string

type RulesPullRequest struct {
	// AllowedMergeMethods are the methods pull requests may be merged with, each listed once. Unset allows all three.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=3
	// +kubebuilder:validation:XValidation:rule="self.all(x, self.exists_one(y, y == x))",message="each merge method may appear once in allowedMergeMethods"
	// +optional
	AllowedMergeMethods []RulesMergeMethod `json:"allowedMergeMethods,omitempty"`
	// DismissalRestriction limits who can dismiss reviews. Unset lets everyone with write access dismiss them.
	// +optional
	DismissalRestriction *RulesDismissalRestriction `json:"dismissalRestriction,omitempty"`
	// DismissStaleReviewsOnPush automatically dismiss approving reviews when someone pushes a new commit.
	// +optional
	DismissStaleReviewsOnPush *bool `json:"dismissStaleReviewsOnPush,omitempty"`
	// RequireExtraApprovalForUnattributedChanges requires an additional approval for
	// pull requests containing unattributed changes, such as those Copilot makes. Defaults to true, as on GitHub.
	// +optional
	RequireExtraApprovalForUnattributedChanges *bool `json:"requireExtraApprovalForUnattributedChanges,omitempty"`
	// RequiredReviewers requires approvals from specific teams for changes to matching files. Unset means an empty list.
	// +optional
	RequiredReviewers []*RulesRequiredReviewer `json:"requiredReviewers,omitempty"`
	// RequireCodeOwnerReview requires the pull request to be approved by a code owner.
	// +optional
	RequireCodeOwnerReview *bool `json:"requireCodeOwnerReview,omitempty"`
	// RequireLastPushApproval requires the most recent push to be approved by someone other than the person who pushed it.
	// +optional
	RequireLastPushApproval *bool `json:"requireLastPushApproval,omitempty"`
	// RequiredApprovingReviewCount specifies the number of reviewers required to approve pull requests.
	// +optional
	RequiredApprovingReviewCount *int `json:"requiredApprovingReviewCount,omitempty"`
	// RequiredReviewThreadResolution requires all conversations on code to be resolved before a pull request can be merged.
	// +optional
	RequiredReviewThreadResolution *bool `json:"requiredReviewThreadResolution,omitempty"`
}

type RulesDismissalRestriction struct {
	// Enabled limits review dismissal to AllowedActors.
	Enabled bool `json:"enabled"`
	// AllowedActors are the actors who may dismiss reviews. Each must have write access
	// to the repository; of the repository roles, only admin is accepted.
	// +optional
	AllowedActors []*RulesDismissalActor `json:"allowedActors,omitempty"`
}

type RulesDismissalActor struct {
	// Id is the ID of the actor: the user ID, the team ID, the App's installation ID
	// for IntegrationInstallation, or the repository role ID.
	Id int64 `json:"id"`
	// Type is the type of the actor.
	// +kubebuilder:validation:Enum=User;Team;IntegrationInstallation;RepositoryRole
	Type string `json:"type"`
}

type RulesRequiredReviewer struct {
	// FilePatterns are the file patterns whose changes need the reviewer's approval.
	FilePatterns []string `json:"filePatterns"`
	// MinimumApprovals is how many approvals the reviewer must give.
	MinimumApprovals int `json:"minimumApprovals"`
	// Reviewer is the team that must approve.
	Reviewer RulesReviewer `json:"reviewer"`
}

type RulesReviewer struct {
	// Id is the ID of the team.
	Id int64 `json:"id"`
	// Type is the type of the reviewer.
	// +kubebuilder:validation:Enum=Team
	Type string `json:"type"`
}

type RulesRequiredStatusChecks struct {
	// DoNotEnforceOnCreate allows a branch to be created even if the status checks would fail. Defaults to false.
	// +optional
	DoNotEnforceOnCreate *bool `json:"doNotEnforceOnCreate,omitempty"`
	// RequiredStatusChecks is the list of status checks to require in order to merge into this branch.
	// +optional
	RequiredStatusChecks []*RulesRequiredStatusChecksParameters `json:"requiredStatusChecks,omitempty"`
	// StrictRequiredStatusChecksPolicy requires branches to be up-to-date before merging.
	// +optional
	StrictRequiredStatusChecksPolicy *bool `json:"strictRequiredStatusChecksPolicy,omitempty"`
}
type RulesRequiredStatusChecksParameters struct {
	// Context is the name of the required check.
	Context string `json:"context"`
	// IntegrationId is the ID of integration that must provide this check.
	// +optional
	IntegrationId *int64 `json:"integrationId,omitempty"`
}

// TemplateRepo represents the configuration for creating a new repository from a template.
type TemplateRepo struct {
	// The account owner of the template repository. The name is not case-sensitive.
	Owner string `json:"owner"`

	// The name of the template repository without the .git extension. The name is not case-sensitive.
	Repo string `json:"repo"`

	// Set to true to include the directory structure and files from all branches in the template repository,
	// and not just the default branch.
	IncludeAllBranches bool `json:"includeAllBranches"`
}

type RepoFork struct {
	// The account owner of the repository. The name is not case-sensitive.
	Owner string `json:"owner"`

	// The name of the repository without the .git extension. The name is not case-sensitive.
	Repo string `json:"repo"`

	// When forking from an existing repository, fork with only the default branch.
	DefaultBranchOnly bool `json:"defaultBranchOnly"`
}

// RepositoryObservation are the observable fields of a Repository.
type RepositoryObservation struct {
	// Branch protection items GitHub did not apply on the last push, per declared rule.
	UnappliedBranchProtection []UnappliedBranchProtection `json:"unappliedBranchProtection,omitempty"`
	// Repository settings GitHub did not apply on the last push, with the value that was declared.
	UnappliedSettings []UnappliedSetting `json:"unappliedSettings,omitempty"`
}

// UnappliedBranchProtection records the items GitHub left out when the provider pushed a branch protection rule.
type UnappliedBranchProtection struct {
	Branch string `json:"branch"`
	// Hash of the declared rule the items were observed against.
	RuleHash string `json:"ruleHash"`
	// Items GitHub did not apply, e.g. "bypassApps:some-app" or "allowForcePushes".
	Items []string `json:"items"`
}

// UnappliedSetting records a repository setting GitHub left unchanged when the provider pushed it.
type UnappliedSetting struct {
	// Field name as in spec.forProvider, e.g. "hasWiki".
	Field string `json:"field"`
	// Declared value the refusal was observed against, e.g. "true".
	Declared string `json:"declared"`
}

// A RepositorySpec defines the desired state of a Repository.
type RepositorySpec struct {
	xpv1.ResourceSpec `json:",inline"`
	ForProvider       RepositoryParameters `json:"forProvider"`
}

// A RepositoryStatus represents the observed state of a Repository.
type RepositoryStatus struct {
	xpv1.ResourceStatus `json:",inline"`
	AtProvider          RepositoryObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// A Repository is an example API type.
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="COLLAB-PARTIAL",type="string",JSONPath=".status.conditions[?(@.type=='CollaboratorPartial')].status"
// +kubebuilder:printcolumn:name="BPR-PARTIAL",type="string",JSONPath=".status.conditions[?(@.type=='BranchProtectionPartial')].status"
// +kubebuilder:printcolumn:name="SETTINGS-PARTIAL",type="string",JSONPath=".status.conditions[?(@.type=='SettingsPartial')].status"
// +kubebuilder:printcolumn:name="ARCHIVED",type="string",JSONPath=".status.conditions[?(@.type=='ArchivedConfigFrozen')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,github}
type Repository struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   RepositorySpec   `json:"spec"`
	Status RepositoryStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// RepositoryList contains a list of Repository
type RepositoryList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Repository `json:"items"`
}

// Repository type metadata.
var (
	RepositoryKind             = reflect.TypeOf(Repository{}).Name()
	RepositoryGroupKind        = schema.GroupKind{Group: Group, Kind: RepositoryKind}.String()
	RepositoryKindAPIVersion   = RepositoryKind + "." + SchemeGroupVersion.String()
	RepositoryGroupVersionKind = SchemeGroupVersion.WithKind(RepositoryKind)
)

func init() {
	SchemeBuilder.Register(&Repository{}, &RepositoryList{})
}
