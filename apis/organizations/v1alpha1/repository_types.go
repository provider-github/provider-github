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
	// Omit this field to automatically select the GitHub App that has recently provided this check,
	// or any app if it was not set by a GitHub App. Pass -1 to explicitly allow any app to set the status.
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
	ObservableField string `json:"observableField,omitempty"`
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
