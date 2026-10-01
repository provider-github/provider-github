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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/google/go-cmp/cmp"

	pointer "k8s.io/utils/ptr"

	"github.com/pkg/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/google/go-github/v62/github"
	"github.com/gosimple/slug"

	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	"github.com/crossplane/crossplane-runtime/pkg/connection"
	"github.com/crossplane/crossplane-runtime/pkg/controller"
	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/crossplane/crossplane-runtime/pkg/meta"
	"github.com/crossplane/crossplane-runtime/pkg/ratelimiter"
	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/pkg/resource"

	"github.com/crossplane/provider-github/apis/organizations/v1alpha1"
	apisv1alpha1 "github.com/crossplane/provider-github/apis/v1alpha1"
	ghclient "github.com/crossplane/provider-github/internal/clients"
	"github.com/crossplane/provider-github/internal/features"
	"github.com/crossplane/provider-github/internal/telemetry"
	"github.com/crossplane/provider-github/internal/util"
)

const (
	errNotRepository = "managed resource is not a Repository custom resource"
	errTrackPCUsage  = "cannot track ProviderConfig usage"
	errGetPC         = "cannot get ProviderConfig"

	errNewClient = "cannot create new Service"
)

// Setup adds a controller that reconciles Repository managed resources.
func Setup(mgr ctrl.Manager, o controller.Options, metrics *telemetry.RateLimitMetrics) error {
	return SetupWithTimeout(mgr, o, metrics, 0) // Use default timeout
}

// SetupWithTimeout adds a controller that reconciles Repository managed resources with configurable timeout.
func SetupWithTimeout(mgr ctrl.Manager, o controller.Options, metrics *telemetry.RateLimitMetrics, timeout time.Duration) error {
	name := managed.ControllerName(v1alpha1.RepositoryGroupKind)

	cps := []managed.ConnectionPublisher{managed.NewAPISecretPublisher(mgr.GetClient(), mgr.GetScheme())}
	if o.Features.Enabled(features.EnableAlphaExternalSecretStores) {
		cps = append(cps, connection.NewDetailsManager(mgr.GetClient(), apisv1alpha1.StoreConfigGroupVersionKind))
	}

	reconcilerOptions := []managed.ReconcilerOption{
		managed.WithExternalConnecter(&connector{
			kube:    mgr.GetClient(),
			usage:   resource.NewProviderConfigUsageTracker(mgr.GetClient(), &apisv1alpha1.ProviderConfigUsage{}),
			metrics: metrics}),
		managed.WithLogger(o.Logger.WithValues("controller", name)),
		managed.WithPollInterval(o.PollInterval),
		managed.WithRecorder(event.NewAPIRecorder(mgr.GetEventRecorderFor(name))),
		managed.WithConnectionPublishers(cps...),
	}

	// Add timeout if specified
	if timeout > 0 {
		reconcilerOptions = append(reconcilerOptions, managed.WithTimeout(timeout))
	}

	r := managed.NewReconciler(mgr,
		resource.ManagedKind(v1alpha1.RepositoryGroupVersionKind),
		reconcilerOptions...)

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		WithOptions(o.ForControllerRuntime()).
		WithEventFilter(resource.DesiredStateChanged()).
		For(&v1alpha1.Repository{}).
		Complete(ratelimiter.NewReconciler(name, r, o.GlobalRateLimiter))
}

type connector struct {
	kube    client.Client
	usage   resource.Tracker
	metrics *telemetry.RateLimitMetrics
}

func (c *connector) Connect(ctx context.Context, mg resource.Managed) (managed.ExternalClient, error) {
	cr, ok := mg.(*v1alpha1.Repository)
	if !ok {
		return nil, errors.New(errNotRepository)
	}

	if err := c.usage.Track(ctx, mg); err != nil {
		return nil, errors.Wrap(err, errTrackPCUsage)
	}

	pc := &apisv1alpha1.ProviderConfig{}
	if err := c.kube.Get(ctx, types.NamespacedName{Name: cr.GetProviderConfigReference().Name}, pc); err != nil {
		return nil, errors.Wrap(err, errGetPC)
	}

	gh, err := ghclient.ResolveAndConnect(ctx, c.kube, pc, c.metrics, cr.Spec.ForProvider.Org)
	if err != nil {
		return nil, errors.Wrap(err, errNewClient)
	}

	return &external{
		github:  gh,
		kube:    c.kube,
		metrics: c.metrics,
	}, nil
}

type external struct {
	kube    client.Client
	github  *ghclient.Client
	metrics *telemetry.RateLimitMetrics
}

//nolint:gocyclo
func (c *external) Observe(ctx context.Context, mg resource.Managed) (managed.ExternalObservation, error) {
	cr, ok := mg.(*v1alpha1.Repository)
	if !ok {
		return managed.ExternalObservation{}, errors.New(errNotRepository)
	}

	name := meta.GetExternalName(cr)

	repo, _, err := c.github.Repositories.Get(ctx, cr.Spec.ForProvider.Org, name)
	if ghclient.Is404(err) {
		if c.metrics != nil {
			c.metrics.ForgetRepository(cr.Spec.ForProvider.Org, name)
		}
		return managed.ExternalObservation{ResourceExists: false}, nil
	}
	if err != nil {
		return managed.ExternalObservation{}, err
	}

	notUpToDate := managed.ExternalObservation{
		ResourceExists:   true,
		ResourceUpToDate: false,
	}

	// Archived repos freeze settings, branch protection, rulesets and webhooks on
	// GitHub; only team access, topics and collaborator removals stay writable. They
	// reconcile on a separate path so frozen drift can't loop, and the freeze is
	// surfaced on the CR rather than ignored silently.
	archivedCr := pointer.Deref(cr.Spec.ForProvider.Archived, false)
	if archivedCr != pointer.Deref(repo.Archived, false) {
		return notUpToDate, nil
	}
	if archivedCr {
		return c.observeArchived(ctx, cr, repo, name)
	}
	setArchivedCondition(cr, false, nil)
	c.recordUnreconcilable(cr, telemetry.DimensionArchived, typeArchivedConfigFrozen)

	collaborators, err := categorizeCollaborators(ctx, c.github, cr.Spec.ForProvider.Org, name, cr.Spec.ForProvider.Permissions.Users)
	if err != nil {
		return managed.ExternalObservation{}, err
	}
	setCollaboratorPartialCondition(cr, collaborators.pendingInvite, collaborators.roleEnforced)
	c.recordUnreconcilable(cr, telemetry.DimensionCollaborators, typeCollaboratorPartial)
	if collaborators.hasDrift() {
		return notUpToDate, nil
	}

	crTToPermission := getTeamPermissionMapFromCr(cr.Spec.ForProvider.Permissions.Teams)
	ghTToPermission, err := getRepoTeamsWithPermissions(ctx, c.github, cr.Spec.ForProvider.Org, name)
	if err != nil {
		return managed.ExternalObservation{}, err
	}

	if !reflect.DeepEqual(util.SortByKey(ghTToPermission), util.SortByKey(crTToPermission)) {
		return notUpToDate, nil
	}

	if cr.Spec.ForProvider.Webhooks != nil {
		ghRepoWebhooks, err := getRepoWebhooks(ctx, c.github, cr.Spec.ForProvider.Org, name)
		if err != nil {
			return managed.ExternalObservation{}, err
		}

		crWToConfig, err := c.getRepoWebhooksMapFromCr(ctx, cr.Spec.ForProvider.Webhooks)
		if err != nil {
			return managed.ExternalObservation{}, err
		}

		ghWToConfig, err := c.getRepoWebhooksWithConfig(ctx, ghRepoWebhooks, cr)
		if err != nil {
			return managed.ExternalObservation{}, err
		}

		if !reflect.DeepEqual(ghWToConfig, crWToConfig) {
			return notUpToDate, nil
		}
	}

	if cr.Spec.ForProvider.BranchProtectionRules != nil {
		protectedBranches, err := listProtectedBranches(ctx, c.github, cr.Spec.ForProvider.Org, name)
		if err != nil {
			return managed.ExternalObservation{}, err
		}
		crBPRToConfig := getBPRMapFromCr(cr.Spec.ForProvider.BranchProtectionRules)
		skipped, err := filterMissingBranchProtectionRules(ctx, c.github, cr.Spec.ForProvider.Org, name, crBPRToConfig, protectedBranchSet(protectedBranches))
		if err != nil {
			return managed.ExternalObservation{}, err
		}
		if len(skipped) > 0 {
			ctrl.LoggerFrom(ctx).Info("skipping branch protection rules for missing branches",
				"repository", name, "branches", skipped)
		}
		ghBPRToConfig, err := getBPRWithConfig(ctx, c.github, cr.Spec.ForProvider.Org, name, protectedBranches)
		if err != nil {
			return managed.ExternalObservation{}, err
		}

		forcePushKept := forcePushKeptBranches(crBPRToConfig, ghBPRToConfig)

		records := currentUnappliedBranchProtection(cr.Status.AtProvider.UnappliedBranchProtection, crBPRToConfig)
		cr.Status.AtProvider.UnappliedBranchProtection = records

		unapplied := detectUnappliedBranchProtectionActors(crBPRToConfig, ghBPRToConfig)
		enforced, err := enforcedBranchProtectionActors(ctx, c.github, cr.Spec.ForProvider.Org, name, unapplied, ghTToPermission)
		if err != nil {
			return managed.ExternalObservation{}, err
		}
		dropped := slices.Concat(enforced, rememberedApps(records, unapplied))
		sortBranchProtectionActorRefs(dropped)
		setBranchProtectionPartialCondition(cr, branchProtectionReport{
			missingBranches: skipped,
			unappliedActors: dropped,
			forcePushKept:   forcePushKept,
		})
		c.recordUnreconcilable(cr, telemetry.DimensionBranchProtection, typeBranchProtectionPartial)

		crBPRWithoutDropped := withoutBranchProtectionActors(crBPRToConfig, dropped)
		applyRememberedForcePushes(crBPRWithoutDropped, ghBPRToConfig, records)
		if !cmp.Equal(crBPRWithoutDropped, ghBPRToConfig) {
			return notUpToDate, nil
		}
	} else {
		cr.Status.AtProvider.UnappliedBranchProtection = nil
		setBranchProtectionPartialCondition(cr, branchProtectionReport{})
		c.recordUnreconcilable(cr, telemetry.DimensionBranchProtection, typeBranchProtectionPartial)
	}

	if cr.Spec.ForProvider.RepositoryRules != nil {
		ghRepositoryRules, _ := getRepositoryRules(ctx, c.github, cr.Spec.ForProvider.Org, name)

		crRepositoryRulesToConfig := getRepositoryRulesMapFromCr(cr.Spec.ForProvider.RepositoryRules)
		ghRepositoryRulesToConfig, err := getRepositoryRulesWithConfig(ctx, c.github, cr.Spec.ForProvider.Org, name, ghRepositoryRules)
		if err != nil {
			return managed.ExternalObservation{}, err
		}

		if !cmp.Equal(crRepositoryRulesToConfig, ghRepositoryRulesToConfig) {
			return notUpToDate, nil
		}
	}

	// repo visibility makes sense only when a repo is not a fork
	if !pointer.Deref(repo.Fork, false) {
		privateCr := pointer.Deref(cr.Spec.ForProvider.Private, true)
		if privateCr != pointer.Deref(repo.Private, false) {
			return notUpToDate, nil
		}
	}

	isTemplate := pointer.Deref(cr.Spec.ForProvider.IsTemplate, false)
	if isTemplate != pointer.Deref(repo.IsTemplate, false) {
		return notUpToDate, nil
	}

	// Check topics
	if cr.Spec.ForProvider.Topics != nil {
		crTopics := util.SortAndReturn(cr.Spec.ForProvider.Topics)
		ghTopics := util.SortAndReturn(repo.Topics)

		if !reflect.DeepEqual(crTopics, ghTopics) {
			return notUpToDate, nil
		}
	}

	if cr.Spec.ForProvider.Description != pointer.Deref(repo.Description, "") {
		return notUpToDate, nil
	}

	if cr.Spec.ForProvider.DefaultBranch != nil &&
		*cr.Spec.ForProvider.DefaultBranch != pointer.Deref(repo.DefaultBranch, "") {
		return notUpToDate, nil
	}

	if cr.Spec.ForProvider.AllowMergeCommit != nil &&
		*cr.Spec.ForProvider.AllowMergeCommit != pointer.Deref(repo.AllowMergeCommit, false) {
		return notUpToDate, nil
	}

	if cr.Spec.ForProvider.AllowSquashMerge != nil &&
		*cr.Spec.ForProvider.AllowSquashMerge != pointer.Deref(repo.AllowSquashMerge, false) {
		return notUpToDate, nil
	}

	if cr.Spec.ForProvider.AllowRebaseMerge != nil &&
		*cr.Spec.ForProvider.AllowRebaseMerge != pointer.Deref(repo.AllowRebaseMerge, false) {
		return notUpToDate, nil
	}

	if cr.Spec.ForProvider.AllowAutoMerge != nil &&
		*cr.Spec.ForProvider.AllowAutoMerge != pointer.Deref(repo.AllowAutoMerge, false) {
		return notUpToDate, nil
	}

	if cr.Spec.ForProvider.AllowUpdateBranch != nil &&
		*cr.Spec.ForProvider.AllowUpdateBranch != pointer.Deref(repo.AllowUpdateBranch, false) {
		return notUpToDate, nil
	}

	if cr.Spec.ForProvider.DeleteBranchOnMerge != nil &&
		*cr.Spec.ForProvider.DeleteBranchOnMerge != pointer.Deref(repo.DeleteBranchOnMerge, false) {
		return notUpToDate, nil
	}

	if cr.Spec.ForProvider.HasIssues != nil &&
		*cr.Spec.ForProvider.HasIssues != pointer.Deref(repo.HasIssues, false) {
		return notUpToDate, nil
	}

	if cr.Spec.ForProvider.HasProjects != nil &&
		*cr.Spec.ForProvider.HasProjects != pointer.Deref(repo.HasProjects, false) {
		return notUpToDate, nil
	}

	if cr.Spec.ForProvider.HasWiki != nil &&
		*cr.Spec.ForProvider.HasWiki != pointer.Deref(repo.HasWiki, false) {
		return notUpToDate, nil
	}

	if cr.Spec.ForProvider.HasDiscussions != nil &&
		*cr.Spec.ForProvider.HasDiscussions != pointer.Deref(repo.HasDiscussions, false) {
		return notUpToDate, nil
	}

	if cr.Spec.ForProvider.MergeCommitTitle != nil &&
		*cr.Spec.ForProvider.MergeCommitTitle != pointer.Deref(repo.MergeCommitTitle, "") {
		return notUpToDate, nil
	}

	if cr.Spec.ForProvider.MergeCommitMessage != nil &&
		*cr.Spec.ForProvider.MergeCommitMessage != pointer.Deref(repo.MergeCommitMessage, "") {
		return notUpToDate, nil
	}

	if cr.Spec.ForProvider.SquashMergeCommitTitle != nil &&
		*cr.Spec.ForProvider.SquashMergeCommitTitle != pointer.Deref(repo.SquashMergeCommitTitle, "") {
		return notUpToDate, nil
	}

	if cr.Spec.ForProvider.SquashMergeCommitMessage != nil &&
		*cr.Spec.ForProvider.SquashMergeCommitMessage != pointer.Deref(repo.SquashMergeCommitMessage, "") {
		return notUpToDate, nil
	}

	cr.SetConditions(xpv1.Available())

	return managed.ExternalObservation{
		ResourceExists:   true,
		ResourceUpToDate: true,
	}, nil
}

// Condition surfaced when a repo is archived. GitHub makes archived repos
// read-only for settings, branch protection, rulesets, webhooks and collaborator
// additions, so the controller cannot reconcile those; the condition states this
// rather than letting the skipped reconciliation go unnoticed on the CR.
const (
	typeArchivedConfigFrozen xpv1.ConditionType   = "ArchivedConfigFrozen"
	reasonRepositoryArchived xpv1.ConditionReason = "RepositoryArchived"
	reasonNotArchived        xpv1.ConditionReason = "NotArchived"
)

// setArchivedCondition reports the frozen dimensions while archived, listing any
// declared collaborators that can't be added because the repo is archived. When
// not archived it clears a previously-set condition (no-op if never set).
func setArchivedCondition(cr *v1alpha1.Repository, archived bool, skippedAdds []string) {
	if !archived {
		if cr.GetCondition(typeArchivedConfigFrozen).Status == corev1.ConditionTrue {
			cr.SetConditions(xpv1.Condition{
				Type:               typeArchivedConfigFrozen,
				Status:             corev1.ConditionFalse,
				Reason:             reasonNotArchived,
				LastTransitionTime: metav1.Now(),
			})
		}
		return
	}
	msg := "repository is archived; settings, branch protection, rulesets and webhooks are not reconciled"
	if len(skippedAdds) > 0 {
		sort.Strings(skippedAdds)
		msg += "; collaborators cannot be added while archived: " + strings.Join(skippedAdds, ", ")
	}
	cr.SetConditions(xpv1.Condition{
		Type:               typeArchivedConfigFrozen,
		Status:             corev1.ConditionTrue,
		Reason:             reasonRepositoryArchived,
		Message:            msg,
		LastTransitionTime: metav1.Now(),
	})
}

// recordUnreconcilable publishes the dimension's gauge from its condition's current status.
func (c *external) recordUnreconcilable(cr *v1alpha1.Repository, dimension string, conditionType xpv1.ConditionType) {
	if c.metrics == nil {
		return
	}
	unreconcilable := cr.GetCondition(conditionType).Status == corev1.ConditionTrue
	c.metrics.SetRepositoryUnreconcilable(cr.Spec.ForProvider.Org, meta.GetExternalName(cr), dimension, unreconcilable)
}

// observeArchived reports drift for an archived repo. Only team access, topics and
// collaborator removals are reconcilable while archived; settings, branch protection,
// rulesets, webhooks and collaborator additions are frozen and surfaced via a
// condition. The frozen dimensions aren't even read here.
func (c *external) observeArchived(ctx context.Context, cr *v1alpha1.Repository, repo *github.Repository, name string) (managed.ExternalObservation, error) {
	org := cr.Spec.ForProvider.Org

	crUsers := getUserPermissionMapFromCr(cr.Spec.ForProvider.Permissions.Users)
	ghUsers, err := getRepoUsersWithPermissions(ctx, c.github, org, name)
	if err != nil {
		return managed.ExternalObservation{}, err
	}
	removable, toAdd, toUpdate := util.DiffPermissions(ghUsers, crUsers)
	skippedAdds := make([]string, 0, len(toAdd)+len(toUpdate))
	for u := range util.MergeMaps(toAdd, toUpdate) {
		skippedAdds = append(skippedAdds, u)
	}

	// Neither is reconciled while archived; skipped adds are named in the archived condition.
	setCollaboratorPartialCondition(cr, nil, nil)
	c.recordUnreconcilable(cr, telemetry.DimensionCollaborators, typeCollaboratorPartial)
	cr.Status.AtProvider.UnappliedBranchProtection = nil
	setBranchProtectionPartialCondition(cr, branchProtectionReport{})
	c.recordUnreconcilable(cr, telemetry.DimensionBranchProtection, typeBranchProtectionPartial)

	setArchivedCondition(cr, true, skippedAdds)
	c.recordUnreconcilable(cr, telemetry.DimensionArchived, typeArchivedConfigFrozen)

	crTeams := getTeamPermissionMapFromCr(cr.Spec.ForProvider.Permissions.Teams)
	ghTeams, err := getRepoTeamsWithPermissions(ctx, c.github, org, name)
	if err != nil {
		return managed.ExternalObservation{}, err
	}
	teamsDrift := !reflect.DeepEqual(util.SortByKey(ghTeams), util.SortByKey(crTeams))

	topicsDrift := false
	if cr.Spec.ForProvider.Topics != nil {
		topicsDrift = !reflect.DeepEqual(util.SortAndReturn(cr.Spec.ForProvider.Topics), util.SortAndReturn(repo.Topics))
	}

	if len(removable) > 0 || teamsDrift || topicsDrift {
		return managed.ExternalObservation{ResourceExists: true, ResourceUpToDate: false}, nil
	}

	cr.SetConditions(xpv1.Available())
	return managed.ExternalObservation{ResourceExists: true, ResourceUpToDate: true}, nil
}

func getTeamPermissionMapFromCr(teams []v1alpha1.RepositoryTeam) map[string]string {
	crTToPermission := make(map[string]string, len(teams))
	for _, team := range teams {
		teamSlug := slug.Make(team.Team)
		crTToPermission[teamSlug] = team.Role
	}

	return crTToPermission
}

func getUserPermissionMapFromCr(users []v1alpha1.RepositoryUser) map[string]string {
	crMToPermission := make(map[string]string, len(users))

	for _, user := range users {
		username := strings.ToLower(user.User)
		crMToPermission[username] = user.Role
	}

	return crMToPermission
}

func (c *external) getRepoWebhooksMapFromCr(ctx context.Context, webhooks []v1alpha1.RepositoryWebhook) (map[string]v1alpha1.RepositoryWebhook, error) {
	crWToConfig := make(map[string]v1alpha1.RepositoryWebhook, len(webhooks))

	for i := range webhooks {
		webhook := webhooks[i]
		// handle optional *bool fields
		insecureSsl := util.BoolDerefToPointer(webhook.InsecureSsl, false)
		active := util.BoolDerefToPointer(webhook.Active, true)

		secret, err := c.getRepoWebhookSecretFromRef(ctx, &webhook)
		if err != nil {
			return nil, err
		}

		// sort events to aid comparison between desired and actual state
		sort.Strings(webhook.Events)

		crWToConfig[webhook.Url] = v1alpha1.RepositoryWebhook{
			Url:         webhook.Url,
			InsecureSsl: insecureSsl,
			ContentType: webhook.ContentType,
			Events:      webhook.Events,
			Active:      active,
			Secret:      secret,
		}
	}
	return crWToConfig, nil
}

func (c *external) getRepoWebhookSecretFromRef(ctx context.Context, webhook *v1alpha1.RepositoryWebhook) (secret *string, err error) {
	if webhook.SecretKeyRef == nil {
		return nil, nil
	}

	secretKey := webhook.SecretKeyRef.Key
	secretName := webhook.SecretKeyRef.Name
	secretNamespace := webhook.SecretKeyRef.Namespace

	nn := types.NamespacedName{
		Name:      secretName,
		Namespace: secretNamespace,
	}

	s := &corev1.Secret{}
	if err := c.kube.Get(ctx, nn, s); err != nil {
		return nil, errors.Errorf("cannot get secret `%s/%s`", secretNamespace, secretName)
	}

	// Check if `secretKey` key exists in secret data
	data, ok := s.Data[secretKey]
	if !ok {
		return nil, errors.Errorf("secret key `%s` not found in secret `%s/%s`", secretKey, secretNamespace, secretName)
	}

	secretValue := string(data)
	return &secretValue, nil
}

type webhookSecretState struct {
	WebhookUrl    string `json:"webhookUrl"`
	WebhookSecret string `json:"webhookSecret"`
}

func (c *external) getRepoWebhookSecretFromState(ctx context.Context, cr *v1alpha1.Repository, webhook *github.Hook) (secret string, err error) {
	if cr.Spec.WriteConnectionSecretToReference == nil {
		return "", errors.New("`spec.writeConnectionSecretToReference` is not set")
	}

	secretKey := util.GenerateSHA1Hash(webhook.Config.GetURL())
	secretName := cr.Spec.WriteConnectionSecretToReference.Name
	secretNamespace := cr.Spec.WriteConnectionSecretToReference.Namespace
	nn := types.NamespacedName{
		Name:      secretName,
		Namespace: secretNamespace,
	}
	s := &corev1.Secret{}

	// the output secret may not exist yet, so we can skip returning an error if the error is `NotFound`
	if err := c.kube.Get(ctx, nn, s); resource.IgnoreNotFound(err) != nil {
		return "", err
	}

	// Check if `secretKey` key exists in secret data
	secretValue, ok := s.Data[secretKey]

	// It's fine to return no error if `secretKey` doesn't exist in secret data, maybe the secret hasn't been updated yet
	if !ok {
		return "", nil
	}

	var data webhookSecretState
	err = json.Unmarshal(secretValue, &data)
	if err != nil {
		return "", errors.Errorf("cannot unmarshal secret value for secret key `%s` in secret `%s/%s`", secretKey, secretNamespace, secretName)
	}
	return data.WebhookSecret, nil
}

func (c *external) updateConnectionSecretEntry(ctx context.Context, cr *v1alpha1.Repository, secretKey string, secretValue webhookSecretState) error {
	if cr.Spec.WriteConnectionSecretToReference == nil {
		return errors.New("cannot update connection secret, `spec.writeConnectionSecretToReference` is not set")
	}

	secretName := cr.Spec.WriteConnectionSecretToReference.Name
	secretNamespace := cr.Spec.WriteConnectionSecretToReference.Namespace
	nn := types.NamespacedName{
		Name:      secretName,
		Namespace: secretNamespace,
	}

	s := &corev1.Secret{}
	if err := c.kube.Get(ctx, nn, s); err != nil {
		return err
	}

	// Ensure the secret's Data field is initialized
	if s.Data == nil {
		s.Data = make(map[string][]byte)
	}

	// Update the secret with the provided key and value
	bytes, err := json.Marshal(secretValue)
	if err != nil {
		return err
	}
	s.Data[secretKey] = bytes

	// Apply the update to the Kubernetes API
	if err := c.kube.Update(ctx, s); err != nil {
		return err
	}
	return nil
}

func (c *external) deleteConnectionSecretEntry(ctx context.Context, cr *v1alpha1.Repository, secretKey string) error {
	if cr.Spec.WriteConnectionSecretToReference == nil {
		return errors.New("cannot update connection secret, `spec.writeConnectionSecretToReference` is not set")
	}

	secretName := cr.Spec.WriteConnectionSecretToReference.Name
	secretNamespace := cr.Spec.WriteConnectionSecretToReference.Namespace
	nn := types.NamespacedName{
		Name:      secretName,
		Namespace: secretNamespace,
	}
	s := &corev1.Secret{}

	// the output secret may not exist yet, so we can skip returning an error if the error is `NotFound`
	if err := c.kube.Get(ctx, nn, s); resource.IgnoreNotFound(err) != nil {
		return err
	}

	// Check if `secretKey` key exists in secret data and delete it if it exists
	_, ok := s.Data[secretKey]
	if ok {
		delete(s.Data, secretKey)
		if err := c.kube.Update(ctx, s); err != nil {
			return errors.Errorf("cannot delete secret entry for `%s` in repository connection secret %s/%s", secretKey, secretNamespace, secretName)
		}
	}
	return nil
}

func getRepoWebhooks(ctx context.Context, gh *ghclient.Client, org, repoName string) ([]*github.Hook, error) {
	opt := &github.ListOptions{PerPage: 100}
	var allHooks []*github.Hook

	for {
		hooks, resp, err := gh.Repositories.ListHooks(ctx, org, repoName, opt)
		if err != nil {
			return nil, err
		}
		allHooks = append(allHooks, hooks...)

		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}

	return allHooks, nil
}

func (c *external) getRepoWebhooksWithConfig(ctx context.Context, hooks []*github.Hook, repo *v1alpha1.Repository) (map[string]v1alpha1.RepositoryWebhook, error) {
	wToConfig := make(map[string]v1alpha1.RepositoryWebhook)

	for _, h := range hooks {
		url := h.Config.GetURL()
		contentType := h.Config.GetContentType()
		insecureSslBool := false
		if h.Config.InsecureSSL != nil && *h.Config.InsecureSSL == "1" {
			insecureSslBool = true
		}
		var secret *string
		if h.Config.Secret != nil {
			var err error
			secretValue, err := c.getRepoWebhookSecretFromState(ctx, repo, h)
			if err != nil {
				return nil, err
			}
			secret = &secretValue
		}
		wToConfig[url] = v1alpha1.RepositoryWebhook{
			Url:         url,
			InsecureSsl: &insecureSslBool,
			ContentType: contentType,
			Events:      h.Events,
			Active:      h.Active,
			Secret:      secret,
		}
	}

	return wToConfig, nil

}

func getRepoWebhookId(hooks []*github.Hook, webhookUrl string) (*int64, error) {

	for _, h := range hooks {
		if h.Config.GetURL() == webhookUrl {
			return h.ID, nil
		}
	}

	return nil, fmt.Errorf("cannot find repository webhook id for %s", webhookUrl)
}

func getRepoTeamsWithPermissions(ctx context.Context, gh *ghclient.Client, org, name string) (map[string]string, error) {
	tToPermission := make(map[string]string)

	opt := &github.ListOptions{PerPage: 100}

	for {
		repos, resp, err := gh.Repositories.ListTeams(ctx, org, name, opt)
		if err != nil {
			return nil, err
		}

		for _, m := range repos {
			tToPermission[*m.Slug] = *m.Permission
		}

		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}

	return tToPermission, nil
}

var permissionsOrdered = [...]string{"admin", "maintain", "push", "triage", "pull"}

func getRepoUsersWithPermissions(ctx context.Context, gh *ghclient.Client, org, name string) (map[string]string, error) {
	uToPermission := make(map[string]string)

	opt := &github.ListCollaboratorsOptions{
		Affiliation: "direct",
		ListOptions: github.ListOptions{PerPage: 100},
	}

	for {
		users, resp, err := gh.Repositories.ListCollaborators(ctx, org, name, opt)
		if err != nil {
			return nil, err
		}

		for _, m := range users {
			username := strings.ToLower(*m.Login)
			uToPermission[username] = "pull"

			for _, p := range permissionsOrdered {
				if m.Permissions[p] {
					uToPermission[username] = p
					break
				}
			}
		}

		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}

	return uToPermission, nil
}

// listProtectedBranches returns every protected branch on a repo,
// iterating pages. The Protected=true filter on GitHub keeps the
// page count tiny (typically 1 page) regardless of how many feature
// branches the repo has, so per-Observe pagination cost stays
// constant even on monorepos with thousands of branches.
func listProtectedBranches(ctx context.Context, gh *ghclient.Client, org, repoName string) ([]*github.Branch, error) {
	opts := &github.BranchListOptions{
		Protected:   github.Bool(true),
		ListOptions: github.ListOptions{PerPage: 100},
	}
	var protected []*github.Branch
	for {
		branches, resp, err := gh.Repositories.ListBranches(ctx, org, repoName, opts)
		if err != nil {
			return nil, err
		}
		protected = append(protected, branches...)
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return protected, nil
}

// 1 hop covers a single branch rename; deeper chains aren't worth chasing.
const branchRenameRedirectsToFollow = 1

// filterMissingBranchProtectionRules removes entries from rules whose
// target branch doesn't exist in the repo. Returns the sorted list of
// skipped branch names so callers can log and emit an Event. Mutates
// rules.
//
// Branches already in protectedSet exist by construction (you cannot
// protect a branch that doesn't exist), so they're accepted without
// any extra API call. The rest are confirmed with a per-branch
// Repositories.GetBranch — 404 means the branch is missing and the
// rule is dropped; a redirect to a different name means the branch
// was renamed (mutating endpoints don't follow redirects, so the rule
// can't apply against the old name) and the skipped entry carries the
// new name so the operator can update the CR; any other error
// propagates.
func filterMissingBranchProtectionRules(ctx context.Context, gh *ghclient.Client, org, repoName string, rules map[string]v1alpha1.BranchProtectionRule, protectedSet map[string]bool) ([]string, error) {
	var skipped []string
	for branch := range rules {
		if protectedSet[branch] {
			continue
		}
		// GetBranch reports non-200 with a bare fmt.Errorf, so check resp.StatusCode rather than Is404(err).
		got, resp, err := gh.Repositories.GetBranch(ctx, org, repoName, branch, branchRenameRedirectsToFollow)
		if err == nil {
			if got != nil && got.GetName() != branch {
				skipped = append(skipped, fmt.Sprintf("%s (was renamed to %s)", branch, got.GetName()))
				delete(rules, branch)
			}
			continue
		}
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			skipped = append(skipped, branch)
			delete(rules, branch)
			continue
		}
		return nil, err
	}
	sort.Strings(skipped)
	return skipped, nil
}

// protectedBranchSet returns the set of branch names from a list of
// protected branches, for fast "is this branch already protected?"
// lookup in filterMissingBranchProtectionRules.
func protectedBranchSet(branches []*github.Branch) map[string]bool {
	set := make(map[string]bool, len(branches))
	for _, b := range branches {
		set[b.GetName()] = true
	}
	return set
}

// One condition for every declared branch protection item GitHub did not apply.
const (
	typeBranchProtectionPartial xpv1.ConditionType   = "BranchProtectionPartial"
	reasonNotFullyApplied       xpv1.ConditionReason = "NotFullyApplied"
	reasonFullyApplied          xpv1.ConditionReason = "FullyApplied"
)

// branchProtectionReport lists the declared branch protection GitHub did not apply.
type branchProtectionReport struct {
	missingBranches []string
	unappliedActors []branchProtectionActorRef
	forcePushKept   []string
}

// Branches declared without force pushes that GitHub keeps enabled (per-actor allowance not settable via REST).
func forcePushKeptBranches(crBPR, ghBPR map[string]v1alpha1.BranchProtectionRule) []string {
	var branches []string
	for branch, want := range crBPR {
		got, ok := ghBPR[branch]
		if !ok {
			continue
		}
		if !pointer.Deref(want.AllowForcePushes, false) && pointer.Deref(got.AllowForcePushes, false) {
			branches = append(branches, branch)
		}
	}
	sort.Strings(branches)
	return branches
}

// Idempotent: SetConditions ignores writes whose (Status, Reason, Message) are unchanged.
func setBranchProtectionPartialCondition(cr *v1alpha1.Repository, report branchProtectionReport) {
	var segments []string
	if len(report.missingBranches) > 0 {
		segments = append(segments, "branches do not exist in repo: "+strings.Join(report.missingBranches, ", "))
	}
	if len(report.unappliedActors) > 0 {
		segments = append(segments, "actors not applied by GitHub: "+strings.Join(branchProtectionActorNames(report.unappliedActors), ", "))
	}
	if len(report.forcePushKept) > 0 {
		segments = append(segments, "force pushes remain enabled: "+strings.Join(report.forcePushKept, ", "))
	}

	c := xpv1.Condition{
		Type:               typeBranchProtectionPartial,
		LastTransitionTime: metav1.Now(),
	}
	if len(segments) == 0 {
		c.Status = corev1.ConditionFalse
		c.Reason = reasonFullyApplied
	} else {
		c.Status = corev1.ConditionTrue
		c.Reason = reasonNotFullyApplied
		c.Message = strings.Join(segments, "; ")
	}
	cr.SetConditions(c)
}

func branchProtectionActorNames(refs []branchProtectionActorRef) []string {
	names := make([]string, len(refs))
	for i, ref := range refs {
		names[i] = fmt.Sprintf("%s/%s:%s", ref.branch, ref.field, ref.actor)
	}
	return names
}

// GitHub drops actors lacking write access with a 200, so Observe treats their absence as enforced.

// Field tokens for the "branch/field:actor" names the condition reports.
const (
	fieldBypassUsers      = "bypassUsers"
	fieldBypassTeams      = "bypassTeams"
	fieldBypassApps       = "bypassApps"
	fieldDismissalUsers   = "dismissalUsers"
	fieldDismissalTeams   = "dismissalTeams"
	fieldDismissalApps    = "dismissalApps"
	fieldRestrictionUsers = "restrictionUsers"
	fieldRestrictionTeams = "restrictionTeams"
	fieldRestrictionApps  = "restrictionApps"
)

// branchProtectionActorRef identifies one actor within a branch protection rule.
type branchProtectionActorRef struct {
	branch string
	field  string
	actor  string
}

func derefStringSlice(s *[]string) []string {
	if s == nil {
		return nil
	}
	return *s
}

// branchProtectionActorRefs flattens every bypass/dismissal/restriction actor in a BPR map.
func branchProtectionActorRefs(m map[string]v1alpha1.BranchProtectionRule) map[branchProtectionActorRef]bool {
	out := map[branchProtectionActorRef]bool{}
	add := func(branch, field string, actors []string) {
		for _, a := range actors {
			out[branchProtectionActorRef{branch: branch, field: field, actor: a}] = true
		}
	}
	for branch, rule := range m {
		if rpr := rule.RequiredPullRequestReviews; rpr != nil {
			if bp := rpr.BypassPullRequestAllowances; bp != nil {
				add(branch, fieldBypassUsers, bp.Users)
				add(branch, fieldBypassTeams, bp.Teams)
				add(branch, fieldBypassApps, bp.Apps)
			}
			if dr := rpr.DismissalRestrictions; dr != nil {
				add(branch, fieldDismissalUsers, derefStringSlice(dr.Users))
				add(branch, fieldDismissalTeams, derefStringSlice(dr.Teams))
				add(branch, fieldDismissalApps, derefStringSlice(dr.Apps))
			}
		}
		if r := rule.BranchProtectionRestrictions; r != nil {
			add(branch, fieldRestrictionUsers, r.Users)
			add(branch, fieldRestrictionTeams, r.Teams)
			add(branch, fieldRestrictionApps, r.Apps)
		}
	}
	return out
}

// Sorted so the condition message is stable across reconciles.
func detectUnappliedBranchProtectionActors(declared, stored map[string]v1alpha1.BranchProtectionRule) []branchProtectionActorRef {
	declaredRefs := branchProtectionActorRefs(declared)
	storedRefs := branchProtectionActorRefs(stored)

	dropped := make([]branchProtectionActorRef, 0, len(declaredRefs))
	for ref := range declaredRefs {
		if storedRefs[ref] {
			continue
		}
		dropped = append(dropped, ref)
	}
	sortBranchProtectionActorRefs(dropped)
	return dropped
}

func sortBranchProtectionActorRefs(refs []branchProtectionActorRef) {
	sort.Slice(refs, func(i, j int) bool {
		a, b := refs[i], refs[j]
		if a.branch != b.branch {
			return a.branch < b.branch
		}
		if a.field != b.field {
			return a.field < b.field
		}
		return a.actor < b.actor
	})
}

// Apps are never enforced: GitHub exposes no permission to probe.
func enforcedBranchProtectionActors(ctx context.Context, gh *ghclient.Client, owner, repo string, unapplied []branchProtectionActorRef, teamPermissions map[string]string) ([]branchProtectionActorRef, error) {
	userCanWrite := map[string]bool{}
	enforced := make([]branchProtectionActorRef, 0, len(unapplied))

	for _, ref := range unapplied {
		switch ref.field {
		case fieldBypassUsers, fieldDismissalUsers, fieldRestrictionUsers:
			if _, probed := userCanWrite[ref.actor]; !probed {
				ok, err := userHasWriteAccess(ctx, gh, owner, repo, ref.actor)
				if err != nil {
					return nil, err
				}
				userCanWrite[ref.actor] = ok
			}
			if !userCanWrite[ref.actor] {
				enforced = append(enforced, ref)
			}
		case fieldBypassTeams, fieldDismissalTeams, fieldRestrictionTeams:
			if !teamHasWriteAccess(teamPermissions[ref.actor]) {
				enforced = append(enforced, ref)
			}
		}
	}
	return enforced, nil
}

const repoPermissionAdmin = "admin"

// 404 (not a collaborator) counts as no access.
func userHasWriteAccess(ctx context.Context, gh *ghclient.Client, owner, repo, user string) (bool, error) {
	level, _, err := gh.Repositories.GetPermissionLevel(ctx, owner, repo, user)
	if ghclient.Is404(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	permission := level.GetPermission()
	return permission == repoPermissionAdmin || permission == "write", nil
}

// "" = team not on the repo.
func teamHasWriteAccess(permission string) bool {
	return permission == repoPermissionAdmin || permission == "maintain" || permission == "push"
}

func withoutBranchProtectionActors(rules map[string]v1alpha1.BranchProtectionRule, drop []branchProtectionActorRef) map[string]v1alpha1.BranchProtectionRule {
	dropSet := make(map[branchProtectionActorRef]bool, len(drop))
	for _, ref := range drop {
		dropSet[ref] = true
	}

	out := make(map[string]v1alpha1.BranchProtectionRule, len(rules))
	for branch, rule := range rules {
		r := rule.DeepCopy()

		if rpr := r.RequiredPullRequestReviews; rpr != nil {
			if bp := rpr.BypassPullRequestAllowances; bp != nil {
				bp.Users = removeActors(bp.Users, branch, fieldBypassUsers, dropSet)
				bp.Teams = removeActors(bp.Teams, branch, fieldBypassTeams, dropSet)
				bp.Apps = removeActors(bp.Apps, branch, fieldBypassApps, dropSet)
			}
			if dr := rpr.DismissalRestrictions; dr != nil {
				dr.Users = removeActorsPtr(dr.Users, branch, fieldDismissalUsers, dropSet)
				dr.Teams = removeActorsPtr(dr.Teams, branch, fieldDismissalTeams, dropSet)
				dr.Apps = removeActorsPtr(dr.Apps, branch, fieldDismissalApps, dropSet)
			}
		}

		if restr := r.BranchProtectionRestrictions; restr != nil {
			restr.Users = removeActors(restr.Users, branch, fieldRestrictionUsers, dropSet)
			restr.Teams = removeActors(restr.Teams, branch, fieldRestrictionTeams, dropSet)
			restr.Apps = removeActors(restr.Apps, branch, fieldRestrictionApps, dropSet)
		}

		out[branch] = *r
	}
	return out
}

// An emptied list becomes nil because getBPRWithConfig reports no actors as nil.
func removeActors(actors []string, branch, field string, dropSet map[branchProtectionActorRef]bool) []string {
	kept := make([]string, 0, len(actors))
	for _, a := range actors {
		ref := branchProtectionActorRef{branch: branch, field: field, actor: a}
		if !dropSet[ref] {
			kept = append(kept, a)
		}
	}

	// An untouched list keeps its shape (nil or empty), so steady-state comparison is unchanged.
	if len(kept) == len(actors) {
		return actors
	}
	if len(kept) == 0 {
		return nil
	}
	return kept
}

func removeActorsPtr(actors *[]string, branch, field string, dropSet map[branchProtectionActorRef]bool) *[]string {
	if actors == nil {
		return nil
	}
	kept := removeActors(*actors, branch, field, dropSet)
	if kept == nil {
		return nil
	}
	return &kept
}

// Item token for a declared allow_force_pushes=false that GitHub kept enabled.
const itemAllowForcePushes = "allowForcePushes"

// ruleHash fingerprints a declared rule so a record only applies to the rule it was observed against.
func ruleHash(rule v1alpha1.BranchProtectionRule) string {
	encoded, _ := json.Marshal(rule) // a plain struct always encodes
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:8])
}

func isAppField(field string) bool {
	return field == fieldBypassApps || field == fieldDismissalApps || field == fieldRestrictionApps
}

// unappliedItems lists the declared apps and force-push setting the echoed rule left out, sorted.
func unappliedItems(declared, echoed v1alpha1.BranchProtectionRule) []string {
	declaredRefs := branchProtectionActorRefs(map[string]v1alpha1.BranchProtectionRule{declared.Branch: declared})
	echoedRefs := branchProtectionActorRefs(map[string]v1alpha1.BranchProtectionRule{declared.Branch: echoed})

	items := make([]string, 0, len(declaredRefs)+1)
	for ref := range declaredRefs {
		if !isAppField(ref.field) || echoedRefs[ref] {
			continue
		}
		items = append(items, ref.field+":"+ref.actor)
	}
	if !pointer.Deref(declared.AllowForcePushes, false) && pointer.Deref(echoed.AllowForcePushes, false) {
		items = append(items, itemAllowForcePushes)
	}
	sort.Strings(items)
	return items
}

// setUnappliedBranchProtection replaces the record for rule's branch; no items drops it.
func setUnappliedBranchProtection(cr *v1alpha1.Repository, rule v1alpha1.BranchProtectionRule, items []string) {
	var records []v1alpha1.UnappliedBranchProtection
	for _, record := range cr.Status.AtProvider.UnappliedBranchProtection {
		if record.Branch != rule.Branch {
			records = append(records, record)
		}
	}
	if len(items) > 0 {
		records = append(records, v1alpha1.UnappliedBranchProtection{
			Branch:   rule.Branch,
			RuleHash: ruleHash(rule),
			Items:    items,
		})
	}
	// Sorted so the status is stable across reconciles.
	sort.Slice(records, func(i, j int) bool { return records[i].Branch < records[j].Branch })
	cr.Status.AtProvider.UnappliedBranchProtection = records
}

// currentUnappliedBranchProtection keeps the records whose branch is still declared with the same rule.
func currentUnappliedBranchProtection(records []v1alpha1.UnappliedBranchProtection, declared map[string]v1alpha1.BranchProtectionRule) []v1alpha1.UnappliedBranchProtection {
	current := make([]v1alpha1.UnappliedBranchProtection, 0, len(records))
	for _, record := range records {
		rule, ok := declared[record.Branch]
		if !ok || record.RuleHash != ruleHash(rule) {
			continue
		}
		current = append(current, record)
	}
	return current
}

// rememberedApps returns the unapplied app actors a current record accounts for.
func rememberedApps(records []v1alpha1.UnappliedBranchProtection, unapplied []branchProtectionActorRef) []branchProtectionActorRef {
	recorded := map[branchProtectionActorRef]bool{}
	for _, record := range records {
		for _, item := range record.Items {
			field, actor, isActor := strings.Cut(item, ":")
			if isActor {
				recorded[branchProtectionActorRef{branch: record.Branch, field: field, actor: actor}] = true
			}
		}
	}

	var remembered []branchProtectionActorRef
	for _, ref := range unapplied {
		if isAppField(ref.field) && recorded[ref] {
			remembered = append(remembered, ref)
		}
	}
	return remembered
}

// applyRememberedForcePushes takes GitHub's force-push setting for branches whose record says it was not applied.
func applyRememberedForcePushes(rules, stored map[string]v1alpha1.BranchProtectionRule, records []v1alpha1.UnappliedBranchProtection) {
	for _, record := range records {
		if !slices.Contains(record.Items, itemAllowForcePushes) {
			continue
		}
		rule, declared := rules[record.Branch]
		got, protected := stored[record.Branch]
		if !declared || !protected {
			continue
		}
		// The record only means "declared off, kept on"; any other pair is ordinary drift.
		if pointer.Deref(rule.AllowForcePushes, false) || !pointer.Deref(got.AllowForcePushes, false) {
			continue
		}
		rule.AllowForcePushes = got.AllowForcePushes
		rules[record.Branch] = rule
	}
}

// getBPRMapFromCr generates a map from a slice of BranchProtectionRules. Each rule is first processed:
// sorts the RequiredStatusChecks and any checks in various rule sub-structures, then the updated rule
// is added to the map with its branch name as the key. The function returns the resulting map.
//
//nolint:gocyclo
func getBPRMapFromCr(rules []v1alpha1.BranchProtectionRule) map[string]v1alpha1.BranchProtectionRule {
	crBPRToConfig := make(map[string]v1alpha1.BranchProtectionRule, len(rules))

	for i := range rules {
		// Use a copy to avoid changing passed []v1alpha1.BranchProtectionRule
		// This prevents the controller from changing the spec of the live CR
		// It can also prevent infinite reconciliation loops when managing the resources with ArgoCD
		orig := &rules[i]
		rCopy := orig.DeepCopy()

		// handle optional *bool fields
		rCopy.RequireLinearHistory = util.BoolDerefToPointer(rCopy.RequireLinearHistory, false)
		rCopy.AllowForcePushes = util.BoolDerefToPointer(rCopy.AllowForcePushes, false)
		rCopy.AllowDeletions = util.BoolDerefToPointer(rCopy.AllowDeletions, false)
		rCopy.RequiredConversationResolution = util.BoolDerefToPointer(rCopy.RequiredConversationResolution, false)
		rCopy.LockBranch = util.BoolDerefToPointer(rCopy.LockBranch, false)
		rCopy.AllowForkSyncing = util.BoolDerefToPointer(rCopy.AllowForkSyncing, false)
		rCopy.RequireSignedCommits = util.BoolDerefToPointer(rCopy.RequireSignedCommits, false)

		if rCopy.RequiredStatusChecks != nil && rCopy.RequiredStatusChecks.Checks != nil {
			copyOfStatusChecks := make([]*v1alpha1.RequiredStatusCheck, len(rCopy.RequiredStatusChecks.Checks))
			copy(copyOfStatusChecks, rCopy.RequiredStatusChecks.Checks)
			util.SortRequiredStatusChecks(copyOfStatusChecks)
			rCopy.RequiredStatusChecks.Checks = copyOfStatusChecks
		}

		restr := rCopy.BranchProtectionRestrictions
		if restr != nil {
			restr.BlockCreations = util.BoolDerefToPointer(restr.BlockCreations, false)
			if restr.Users != nil {
				restr.Users = util.SortAndReturn(util.ToLowerSlice(restr.Users))
			}
			if restr.Teams != nil {
				restr.Teams = util.SortAndReturn(util.ToLowerSlice(restr.Teams))
			}
			if restr.Apps != nil {
				restr.Apps = util.SortAndReturn(util.ToLowerSlice(restr.Apps))
			}
		}

		rPRs := rCopy.RequiredPullRequestReviews
		if rPRs != nil {
			// handle optional *bool fields
			rPRs.RequireLastPushApproval = util.BoolDerefToPointer(rPRs.RequireLastPushApproval, false)

			allowances := rPRs.BypassPullRequestAllowances
			if allowances != nil {
				if allowances.Users != nil {
					allowances.Users = util.SortAndReturn(util.ToLowerSlice(allowances.Users))
				}
				if allowances.Teams != nil {
					allowances.Teams = util.SortAndReturn(util.ToLowerSlice(allowances.Teams))
				}
				if allowances.Apps != nil {
					allowances.Apps = util.SortAndReturn(util.ToLowerSlice(allowances.Apps))
				}
			}
			dismissal := rPRs.DismissalRestrictions
			if dismissal != nil {
				if dismissal.Users != nil {
					dismissal.Users = util.SortAndReturnPointer(util.ToLowerSlice(*dismissal.Users))
				}
				if dismissal.Teams != nil {
					dismissal.Teams = util.SortAndReturnPointer(util.ToLowerSlice(*dismissal.Teams))
				}
				if dismissal.Apps != nil {
					dismissal.Apps = util.SortAndReturnPointer(util.ToLowerSlice(*dismissal.Apps))
				}
			}
		}

		crBPRToConfig[rCopy.Branch] = *rCopy
	}

	return crBPRToConfig
}

// getBPRWithConfig creates a map of BranchProtectionRules for a GitHub repository based on its branches' current protection settings.
// It fetches each branch's protection settings from GitHub and maps them to BranchProtectionRule objects.
// Any lists of users, teams, or apps in the rules are sorted.
// It returns the BranchProtectionRules map, and any error encountered during the process.
func getBPRWithConfig(ctx context.Context, gh *ghclient.Client, owner, repo string, branches []*github.Branch) (map[string]v1alpha1.BranchProtectionRule, error) {
	bprToConfig := make(map[string]v1alpha1.BranchProtectionRule, len(branches))

	for _, branch := range branches {
		protection, _, err := gh.Repositories.GetBranchProtection(ctx, owner, repo, branch.GetName())
		if err != nil {
			return nil, err
		}
		bprToConfig[branch.GetName()] = protectionToRule(branch.GetName(), protection)
	}
	return bprToConfig, nil
}

// protectionToRule maps GitHub's protection of branch to a BranchProtectionRule, with actor lists sorted.
//
//nolint:gocyclo
func protectionToRule(branch string, protection *github.Protection) v1alpha1.BranchProtectionRule {
	bpr := v1alpha1.BranchProtectionRule{
		Branch:                         branch,
		EnforceAdmins:                  protection.GetEnforceAdmins().Enabled,
		RequireLinearHistory:           &protection.GetRequireLinearHistory().Enabled,
		AllowForcePushes:               &protection.GetAllowForcePushes().Enabled,
		AllowDeletions:                 &protection.GetAllowDeletions().Enabled,
		RequiredConversationResolution: &protection.GetRequiredConversationResolution().Enabled,
		LockBranch:                     util.ToBoolPtr(protection.GetLockBranch().GetEnabled()),
		AllowForkSyncing:               util.ToBoolPtr(protection.GetAllowForkSyncing().GetEnabled()),
		RequireSignedCommits:           util.ToBoolPtr(protection.GetRequiredSignatures().GetEnabled()),
	}

	rChecks := protection.GetRequiredStatusChecks()
	if rChecks != nil {
		bpr.RequiredStatusChecks = &v1alpha1.RequiredStatusChecks{
			Strict: rChecks.Strict,
		}
		if rChecks.Checks != nil && len(*rChecks.Checks) > 0 {
			checks := make([]*v1alpha1.RequiredStatusCheck, len(*rChecks.Checks))
			for i, check := range *rChecks.Checks {
				checks[i] = &v1alpha1.RequiredStatusCheck{
					Context: check.Context,
					AppID:   check.AppID,
				}
			}
			util.SortRequiredStatusChecks(checks)
			bpr.RequiredStatusChecks.Checks = checks
		}
	}

	rPRs := protection.GetRequiredPullRequestReviews()
	if rPRs != nil {
		bpr.RequiredPullRequestReviews = &v1alpha1.RequiredPullRequestReviews{
			DismissStaleReviews:          rPRs.DismissStaleReviews,
			RequireCodeOwnerReviews:      rPRs.RequireCodeOwnerReviews,
			RequiredApprovingReviewCount: rPRs.RequiredApprovingReviewCount,
			RequireLastPushApproval:      &rPRs.RequireLastPushApproval,
		}

		dismissal := rPRs.GetDismissalRestrictions()
		if dismissal != nil {
			bpr.RequiredPullRequestReviews.DismissalRestrictions = &v1alpha1.DismissalRestrictionsRequest{}
			if len(dismissal.Users) > 0 {
				users := make([]string, len(dismissal.Users))
				for i, user := range dismissal.Users {
					users[i] = user.GetLogin()
				}
				bpr.RequiredPullRequestReviews.DismissalRestrictions.Users = util.SortAndReturnPointer(util.ToLowerSlice(users))
			}
			if len(dismissal.Teams) > 0 {
				teams := make([]string, len(dismissal.Teams))
				for i, team := range dismissal.Teams {
					teams[i] = team.GetSlug()
				}
				bpr.RequiredPullRequestReviews.DismissalRestrictions.Teams = util.SortAndReturnPointer(util.ToLowerSlice(teams))
			}
			if len(dismissal.Apps) > 0 {
				apps := make([]string, len(dismissal.Apps))
				for i, app := range dismissal.Apps {
					apps[i] = app.GetSlug()
				}
				bpr.RequiredPullRequestReviews.DismissalRestrictions.Apps = util.SortAndReturnPointer(util.ToLowerSlice(apps))
			}
		}

		allowances := rPRs.GetBypassPullRequestAllowances()
		if allowances != nil {
			bpr.RequiredPullRequestReviews.BypassPullRequestAllowances = &v1alpha1.BypassPullRequestAllowancesRequest{}
			if len(allowances.Users) > 0 {
				users := make([]string, len(allowances.Users))
				for i, user := range allowances.Users {
					users[i] = user.GetLogin()
				}
				bpr.RequiredPullRequestReviews.BypassPullRequestAllowances.Users = util.SortAndReturn(util.ToLowerSlice(users))
			}
			if len(allowances.Teams) > 0 {
				teams := make([]string, len(allowances.Teams))
				for i, team := range allowances.Teams {
					teams[i] = team.GetSlug()
				}
				bpr.RequiredPullRequestReviews.BypassPullRequestAllowances.Teams = util.SortAndReturn(util.ToLowerSlice(teams))
			}
			if len(allowances.Apps) > 0 {
				apps := make([]string, len(allowances.Apps))
				for i, app := range allowances.Apps {
					apps[i] = app.GetSlug()
				}
				bpr.RequiredPullRequestReviews.BypassPullRequestAllowances.Apps = util.SortAndReturn(util.ToLowerSlice(apps))
			}
		}
	}

	restr := protection.GetRestrictions()
	if restr != nil {
		bpr.BranchProtectionRestrictions = &v1alpha1.BranchProtectionRestrictions{}
		bpr.BranchProtectionRestrictions.BlockCreations = util.ToBoolPtr(protection.GetBlockCreations().GetEnabled())
		if len(restr.Users) > 0 {
			users := make([]string, len(restr.Users))
			for i, user := range restr.Users {
				users[i] = user.GetLogin()
			}
			bpr.BranchProtectionRestrictions.Users = util.SortAndReturn(util.ToLowerSlice(users))
		}
		if len(restr.Teams) > 0 {
			teams := make([]string, len(restr.Teams))
			for i, team := range restr.Teams {
				teams[i] = team.GetSlug()
			}
			bpr.BranchProtectionRestrictions.Teams = util.SortAndReturn(util.ToLowerSlice(teams))
		}
		if len(restr.Apps) > 0 {
			apps := make([]string, len(restr.Apps))
			for i, app := range restr.Apps {
				apps[i] = app.GetSlug()
			}
			bpr.BranchProtectionRestrictions.Apps = util.SortAndReturn(util.ToLowerSlice(apps))
		}
	}

	return bpr
}

// applyMainSettings copies the optional main-settings fields from spec into req when set.
func applyMainSettings(req *github.Repository, cr *v1alpha1.Repository) {
	fp := cr.Spec.ForProvider
	if fp.DefaultBranch != nil {
		req.DefaultBranch = fp.DefaultBranch
	}
	if fp.AllowMergeCommit != nil {
		req.AllowMergeCommit = fp.AllowMergeCommit
	}
	if fp.AllowSquashMerge != nil {
		req.AllowSquashMerge = fp.AllowSquashMerge
	}
	if fp.AllowRebaseMerge != nil {
		req.AllowRebaseMerge = fp.AllowRebaseMerge
	}
	if fp.AllowAutoMerge != nil {
		req.AllowAutoMerge = fp.AllowAutoMerge
	}
	if fp.AllowUpdateBranch != nil {
		req.AllowUpdateBranch = fp.AllowUpdateBranch
	}
	if fp.DeleteBranchOnMerge != nil {
		req.DeleteBranchOnMerge = fp.DeleteBranchOnMerge
	}
	if fp.HasIssues != nil {
		req.HasIssues = fp.HasIssues
	}
	if fp.HasProjects != nil {
		req.HasProjects = fp.HasProjects
	}
	if fp.HasWiki != nil {
		req.HasWiki = fp.HasWiki
	}
	if fp.HasDiscussions != nil {
		req.HasDiscussions = fp.HasDiscussions
	}
	if fp.MergeCommitTitle != nil {
		req.MergeCommitTitle = fp.MergeCommitTitle
	}
	if fp.MergeCommitMessage != nil {
		req.MergeCommitMessage = fp.MergeCommitMessage
	}
	if fp.SquashMergeCommitTitle != nil {
		req.SquashMergeCommitTitle = fp.SquashMergeCommitTitle
	}
	if fp.SquashMergeCommitMessage != nil {
		req.SquashMergeCommitMessage = fp.SquashMergeCommitMessage
	}
}

//nolint:gocyclo
func (c *external) Create(ctx context.Context, mg resource.Managed) (managed.ExternalCreation, error) {
	cr, ok := mg.(*v1alpha1.Repository)
	if !ok {
		return managed.ExternalCreation{}, errors.New(errNotRepository)
	}

	name := meta.GetExternalName(cr)

	// handle optional *bool fields
	privateCr := pointer.Deref(cr.Spec.ForProvider.Private, true)

	var err error
	switch {
	case cr.Spec.ForProvider.CreateFork != nil:
		owner := cr.Spec.ForProvider.CreateFork.Owner
		repo := cr.Spec.ForProvider.CreateFork.Repo
		_, _, err = c.github.Repositories.CreateFork(ctx, owner, repo, &github.RepositoryCreateForkOptions{
			Organization:      cr.Spec.ForProvider.Org,
			Name:              name,
			DefaultBranchOnly: cr.Spec.ForProvider.CreateFork.DefaultBranchOnly,
		})
	case cr.Spec.ForProvider.CreateFromTemplate != nil:
		templateOwner := cr.Spec.ForProvider.CreateFromTemplate.Owner
		templateRepo := cr.Spec.ForProvider.CreateFromTemplate.Repo
		_, _, err = c.github.Repositories.CreateFromTemplate(ctx, templateOwner, templateRepo, &github.TemplateRepoRequest{
			Name:               &name,
			Owner:              &cr.Spec.ForProvider.Org,
			Description:        &cr.Spec.ForProvider.Description,
			IncludeAllBranches: &cr.Spec.ForProvider.CreateFromTemplate.IncludeAllBranches,
			Private:            &privateCr,
		})
	default:
		createReq := &github.Repository{
			Name:        &name,
			Description: &cr.Spec.ForProvider.Description,
			Private:     &privateCr,
		}
		applyMainSettings(createReq, cr)
		_, _, err = c.github.Repositories.Create(ctx, cr.Spec.ForProvider.Org, createReq)
	}

	if err != nil {
		return managed.ExternalCreation{}, err
	}

	if cr.Spec.ForProvider.Permissions.Users != nil {
		for _, user := range cr.Spec.ForProvider.Permissions.Users {
			opt := &github.RepositoryAddCollaboratorOptions{Permission: user.Role}
			_, _, err := c.github.Repositories.AddCollaborator(ctx, cr.Spec.ForProvider.Org, name, user.User, opt)
			if err != nil {
				return managed.ExternalCreation{}, err
			}
		}
	}

	if cr.Spec.ForProvider.Permissions.Teams != nil {
		for _, team := range cr.Spec.ForProvider.Permissions.Teams {
			teamSlug := slug.Make(team.Team)
			opt := &github.TeamAddTeamRepoOptions{Permission: team.Role}
			_, err := c.github.Teams.AddTeamRepoBySlug(ctx, cr.Spec.ForProvider.Org, teamSlug, cr.Spec.ForProvider.Org, name, opt)
			if err != nil {
				return managed.ExternalCreation{}, err
			}
		}
	}

	if cr.Spec.ForProvider.Webhooks != nil {
		// getRepoWebhooksMapFromCr() provides defaults for optional *bool fields
		hooksMap, err := c.getRepoWebhooksMapFromCr(ctx, cr.Spec.ForProvider.Webhooks)
		if err != nil {
			return managed.ExternalCreation{}, err
		}
		for key := range hooksMap {
			// avoid "G601: Implicit memory aliasing in for loop"
			hook := hooksMap[key]
			hookConfig := crRepoHookToHookConfig(hook)
			_, _, err = c.github.Repositories.CreateHook(ctx, cr.Spec.ForProvider.Org, name, hookConfig)
			if err != nil {
				return managed.ExternalCreation{}, err
			}
			if hookConfig.Config.Secret != nil {
				err = c.updateConnectionSecretEntry(ctx, cr, util.GenerateSHA1Hash(hook.Url), webhookSecretState{
					WebhookUrl:    *hookConfig.Config.URL,
					WebhookSecret: *hookConfig.Config.Secret,
				})
				if err != nil {
					return managed.ExternalCreation{}, err
				}
			}
		}
	}

	if cr.Spec.ForProvider.BranchProtectionRules != nil {
		protectedBranches, err := listProtectedBranches(ctx, c.github, cr.Spec.ForProvider.Org, name)
		if err != nil {
			return managed.ExternalCreation{}, err
		}
		// getBPRMapFromCr() provides defaults for optional *bool fields
		rulesMap := getBPRMapFromCr(cr.Spec.ForProvider.BranchProtectionRules)
		_, err = filterMissingBranchProtectionRules(ctx, c.github, cr.Spec.ForProvider.Org, name, rulesMap, protectedBranchSet(protectedBranches))
		if err != nil {
			return managed.ExternalCreation{}, err
		}
		for key := range rulesMap {
			// avoid "G601: Implicit memory aliasing in for loop"
			rule := rulesMap[key]
			// Status set here is lost: the reconciler re-reads the CR after Create.
			_, err = editProtectedBranch(ctx, &rule, c.github, cr.Spec.ForProvider.Org, name)
			if err != nil {
				return managed.ExternalCreation{}, err
			}
		}
	}
	if cr.Spec.ForProvider.RepositoryRules != nil {
		rulesMap := getRepositoryRulesMapFromCr(cr.Spec.ForProvider.RepositoryRules)
		for key := range rulesMap {
			// avoid "G601: Implicit memory aliasing in for loop"
			rule := rulesMap[key]
			_, _, err := c.github.Repositories.CreateRuleset(ctx, cr.Spec.ForProvider.Org, name, crRepoRulesToRulesConfig(rule))
			if err != nil {
				return managed.ExternalCreation{}, err
			}
		}

	}

	// Set topics if specified
	if len(cr.Spec.ForProvider.Topics) > 0 {
		_, _, err = c.github.Repositories.ReplaceAllTopics(ctx, cr.Spec.ForProvider.Org, name, cr.Spec.ForProvider.Topics)
		if err != nil {
			return managed.ExternalCreation{}, err
		}
	}

	cr.SetConditions(xpv1.Available())

	return managed.ExternalCreation{}, nil
}

// Condition surfaced when one or more declared collaborators can't be brought to
// their declared state right now — currently because they have an outstanding
// (unaccepted) repository invitation. Kept quiet like BranchProtectionPartial:
// SetConditions only writes when (Status, Reason, Message) actually change.
const (
	typeCollaboratorPartial       xpv1.ConditionType   = "CollaboratorPartial"
	reasonPendingInvitation       xpv1.ConditionReason = "PendingInvitation"
	reasonRoleEnforcedByOrg       xpv1.ConditionReason = "RoleEnforcedByOrg"
	reasonAllCollaboratorsPresent xpv1.ConditionReason = "AllCollaboratorsPresent"
)

// setCollaboratorPartialCondition reports declared collaborators the controller can't
// bring to their declared state: those awaiting invitation acceptance, and org owners
// whose declared role GitHub overrides with admin. Keeps the skips visible on the CR
// instead of looping silently.
func setCollaboratorPartialCondition(cr *v1alpha1.Repository, pendingInvite, roleEnforced []string) {
	c := xpv1.Condition{Type: typeCollaboratorPartial, LastTransitionTime: metav1.Now()}
	if len(pendingInvite) == 0 && len(roleEnforced) == 0 {
		c.Status = corev1.ConditionFalse
		c.Reason = reasonAllCollaboratorsPresent
		cr.SetConditions(c)
		return
	}
	c.Status = corev1.ConditionTrue
	if len(pendingInvite) > 0 {
		c.Reason = reasonPendingInvitation
	} else {
		c.Reason = reasonRoleEnforcedByOrg
	}
	var parts []string
	if len(pendingInvite) > 0 {
		sort.Strings(pendingInvite)
		parts = append(parts, "awaiting invitation acceptance: "+strings.Join(pendingInvite, ", "))
	}
	if len(roleEnforced) > 0 {
		sort.Strings(roleEnforced)
		parts = append(parts, "declared role overridden by GitHub org-admin enforcement: "+strings.Join(roleEnforced, ", "))
	}
	c.Message = strings.Join(parts, "; ")
	cr.SetConditions(c)
}

// collaboratorCategorization buckets the union of declared and actual direct collaborators.
type collaboratorCategorization struct {
	toRemove      map[string]string // direct collaborators absent from the CR
	toUpsert      map[string]string // declared collaborators to add or change role
	pendingInvite []string          // declared collaborators with an unaccepted invitation
	roleEnforced  []string          // org owners whose declared (lower) role GitHub overrides with admin
}

func (cc *collaboratorCategorization) hasDrift() bool {
	return len(cc.toRemove) > 0 || len(cc.toUpsert) > 0
}

// categorizeCollaborators classifies collaborators for Observe and Update.
// ListCollaborators(direct) returns only accepted collaborators, so a declared user
// with an outstanding invitation never appears there; recognizing the pending
// invitation keeps the controller from re-inviting them on every reconcile.
func categorizeCollaborators(ctx context.Context, gh *ghclient.Client, org, repo string, crUsers []v1alpha1.RepositoryUser) (*collaboratorCategorization, error) {
	crM := getUserPermissionMapFromCr(crUsers)
	ghM, err := getRepoUsersWithPermissions(ctx, gh, org, repo)
	if err != nil {
		return nil, err
	}

	cc := &collaboratorCategorization{
		toRemove: make(map[string]string),
		toUpsert: make(map[string]string),
	}

	for user, ghRole := range ghM {
		crRole, inCR := crM[user]
		if !inCR {
			cc.toRemove[user] = ghRole
			continue
		}
		if crRole == ghRole {
			continue
		}
		// Role mismatch. GitHub force-keeps admin for org owners on every repo, so a
		// lower declared role for one can't be applied; only (GH=admin, CR<admin) can
		// be enforced, so the org-admin probe runs only in that shape.
		if ghRole == orgRoleAdmin && crRole != orgRoleAdmin {
			enforced, err := isOrgAdmin(ctx, gh, org, user)
			if err != nil {
				return nil, err
			}
			if enforced {
				cc.roleEnforced = append(cc.roleEnforced, user)
				continue
			}
		}
		cc.toUpsert[user] = crRole
	}

	// Pending invitations only matter for declared users who aren't active
	// collaborators; fetch them lazily so steady state costs no extra call.
	var pending map[string]bool
	for user, crRole := range crM {
		if _, ok := ghM[user]; ok {
			continue
		}
		if pending == nil {
			logins, err := getPendingRepoInviteeLogins(ctx, gh, org, repo)
			if err != nil {
				return nil, err
			}
			pending = make(map[string]bool, len(logins))
			for _, l := range logins {
				pending[l] = true
			}
		}
		if pending[user] {
			cc.pendingInvite = append(cc.pendingInvite, user)
			continue
		}
		cc.toUpsert[user] = crRole
	}

	return cc, nil
}

const orgRoleAdmin = "admin"

// isOrgAdmin reports whether the user is an organization owner (org-level admin).
// Org owners hold admin on every repo, so GitHub ignores a lower declared role.
// 404 (not a member) and a missing/other role are treated as not-admin.
func isOrgAdmin(ctx context.Context, gh *ghclient.Client, org, user string) (bool, error) {
	membership, _, err := gh.Organizations.GetOrgMembership(ctx, user, org)
	if ghclient.Is404(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if membership == nil || membership.Role == nil {
		return false, nil
	}
	return *membership.Role == orgRoleAdmin, nil
}

// getPendingRepoInviteeLogins returns the lowercased logins of users with an
// outstanding (unaccepted) repository invitation. Email-only invitations are skipped.
func getPendingRepoInviteeLogins(ctx context.Context, gh *ghclient.Client, org, repo string) ([]string, error) {
	opt := &github.ListOptions{PerPage: 100}
	var logins []string
	for {
		invitations, resp, err := gh.Repositories.ListInvitations(ctx, org, repo, opt)
		if err != nil {
			return nil, err
		}
		for _, inv := range invitations {
			if inv == nil || inv.Invitee == nil || inv.Invitee.Login == nil {
				continue
			}
			logins = append(logins, strings.ToLower(*inv.Invitee.Login))
		}
		if resp == nil || resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}
	return logins, nil
}

func updateRepoUsers(ctx context.Context, cr *v1alpha1.Repository, gh *ghclient.Client, repoName string) error {
	collaborators, err := categorizeCollaborators(ctx, gh, cr.Spec.ForProvider.Org, repoName, cr.Spec.ForProvider.Permissions.Users)
	if err != nil {
		return err
	}

	for userName := range collaborators.toRemove {
		if _, err := gh.Repositories.RemoveCollaborator(ctx, cr.Spec.ForProvider.Org, repoName, userName); err != nil {
			return err
		}
	}

	// Declared collaborators with an outstanding invitation are in flight and stay in
	// pendingInvite, not toUpsert, so they are not re-invited every reconcile.
	for userName, role := range collaborators.toUpsert {
		opt := &github.RepositoryAddCollaboratorOptions{Permission: role}
		if _, _, err := gh.Repositories.AddCollaborator(ctx, cr.Spec.ForProvider.Org, repoName, userName, opt); err != nil {
			return err
		}
	}

	return nil
}

// removeArchivedRepoUsers removes collaborators absent from the CR. While archived,
// GitHub permits collaborator removals but rejects additions and role changes with
// 403, so only removals are applied; skipped additions are surfaced by Observe via
// the ArchivedConfigFrozen condition.
func removeArchivedRepoUsers(ctx context.Context, cr *v1alpha1.Repository, gh *ghclient.Client, repoName string) error {
	crUsers := getUserPermissionMapFromCr(cr.Spec.ForProvider.Permissions.Users)
	ghUsers, err := getRepoUsersWithPermissions(ctx, gh, cr.Spec.ForProvider.Org, repoName)
	if err != nil {
		return err
	}
	toDelete, _, _ := util.DiffPermissions(ghUsers, crUsers)
	for userName := range toDelete {
		if _, err := gh.Repositories.RemoveCollaborator(ctx, cr.Spec.ForProvider.Org, repoName, userName); err != nil {
			return err
		}
	}
	return nil
}

func updateRepoTeams(ctx context.Context, cr *v1alpha1.Repository, gh *ghclient.Client, repoName string) error {
	crTToPermission := getTeamPermissionMapFromCr(cr.Spec.ForProvider.Permissions.Teams)
	ghTToPermission, err := getRepoTeamsWithPermissions(ctx, gh, cr.Spec.ForProvider.Org, repoName)
	if err != nil {
		return err
	}

	toDelete, toAdd, toUpdate := util.DiffPermissions(ghTToPermission, crTToPermission)

	for teamSlug := range toDelete {
		_, err := gh.Teams.RemoveTeamRepoBySlug(ctx, cr.Spec.ForProvider.Org, teamSlug, cr.Spec.ForProvider.Org, repoName)
		if err != nil {
			return err
		}
	}

	for teamSlug, role := range util.MergeMaps(toAdd, toUpdate) {
		opt := &github.TeamAddTeamRepoOptions{Permission: role}
		_, err := gh.Teams.AddTeamRepoBySlug(ctx, cr.Spec.ForProvider.Org, teamSlug, cr.Spec.ForProvider.Org, repoName, opt)
		if err != nil {
			return err
		}
	}

	return nil
}

// crRepoHookToHookConfig converts a RepositoryWebhook object to a *github.Hook object and returns it.
func crRepoHookToHookConfig(hook v1alpha1.RepositoryWebhook) *github.Hook {
	insecureSsl := "0"
	if hook.InsecureSsl != nil && *hook.InsecureSsl {
		insecureSsl = "1"
	}
	return &github.Hook{
		Config: &github.HookConfig{
			ContentType: &hook.ContentType,
			InsecureSSL: &insecureSsl,
			URL:         &hook.Url,
			Secret:      hook.Secret,
		},
		Events: hook.Events,
		Active: hook.Active,
	}
}

//nolint:gocyclo
func updateRepoWebhooks(c *external, ctx context.Context, cr *v1alpha1.Repository, gh *ghclient.Client, repoName string) error {
	ghRepoWebhooks, err := getRepoWebhooks(ctx, gh, cr.Spec.ForProvider.Org, repoName)
	if err != nil {
		return err
	}
	crWToConfig, err := c.getRepoWebhooksMapFromCr(ctx, cr.Spec.ForProvider.Webhooks)
	if err != nil {
		return err
	}
	ghWToConfig, err := c.getRepoWebhooksWithConfig(ctx, ghRepoWebhooks, cr)
	if err != nil {
		return err
	}

	toDelete, toAdd, toUpdate := util.DiffRepoWebhooks(ghWToConfig, crWToConfig)

	for _, hook := range toDelete {
		id, err := getRepoWebhookId(ghRepoWebhooks, hook.Url)
		if err != nil {
			return err
		}
		_, err = gh.Repositories.DeleteHook(ctx, cr.Spec.ForProvider.Org, repoName, *id)
		if err != nil {
			return err
		}
		if hook.Secret != nil {
			err = c.deleteConnectionSecretEntry(ctx, cr, util.GenerateSHA1Hash(hook.Url))
			if err != nil {
				return err
			}
		}
	}

	for _, hook := range toAdd {
		hookConfig := crRepoHookToHookConfig(hook)
		_, _, err = gh.Repositories.CreateHook(ctx, cr.Spec.ForProvider.Org, repoName, hookConfig)
		if err != nil {
			return err
		}
		if hookConfig.Config.Secret != nil {
			err = c.updateConnectionSecretEntry(ctx, cr, util.GenerateSHA1Hash(hook.Url), webhookSecretState{
				WebhookUrl:    *hookConfig.Config.URL,
				WebhookSecret: *hookConfig.Config.Secret,
			})
			if err != nil {
				return err
			}
		}
	}

	for _, hook := range toUpdate {
		id, err := getRepoWebhookId(ghRepoWebhooks, hook.Url)
		if err != nil {
			return err
		}
		hookConfig := crRepoHookToHookConfig(hook)
		_, _, err = gh.Repositories.EditHook(ctx, cr.Spec.ForProvider.Org, repoName, *id, hookConfig)
		if err != nil {
			return err
		}

		// Clear connection secret entry first, if it exists
		err = c.deleteConnectionSecretEntry(ctx, cr, util.GenerateSHA1Hash(*hookConfig.Config.URL))
		if err != nil {
			return err
		}

		// Add updated connection secret entry, if needed
		if hookConfig.Config.Secret != nil {
			err = c.updateConnectionSecretEntry(ctx, cr, util.GenerateSHA1Hash(hook.Url), webhookSecretState{
				WebhookUrl:    *hookConfig.Config.URL,
				WebhookSecret: *hookConfig.Config.Secret,
			})
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// editProtectedBranch updates the branch protection settings for a given GitHub repository
// based on a provided BranchProtectionRule. It returns the items GitHub's echo left out,
// or an error if the update operation fails.
//
//nolint:gocyclo
func editProtectedBranch(ctx context.Context, rule *v1alpha1.BranchProtectionRule, gh *ghclient.Client, owner, repoName string) ([]string, error) {
	protectionRequest := &github.ProtectionRequest{
		EnforceAdmins:                  rule.EnforceAdmins,
		RequireLinearHistory:           rule.RequireLinearHistory,
		AllowForcePushes:               rule.AllowForcePushes,
		AllowDeletions:                 rule.AllowDeletions,
		RequiredConversationResolution: rule.RequiredConversationResolution,
		LockBranch:                     rule.LockBranch,
		AllowForkSyncing:               rule.AllowForkSyncing,
	}

	if rule.RequiredStatusChecks != nil {
		var checks []*github.RequiredStatusCheck
		for _, check := range rule.RequiredStatusChecks.Checks {
			// if nil, allow any app to set the status of a check
			appId := pointer.Deref(check.AppID, -1)
			checks = append(checks, &github.RequiredStatusCheck{
				Context: check.Context,
				AppID:   &appId,
			})
		}
		protectionRequest.RequiredStatusChecks = &github.RequiredStatusChecks{
			Strict: rule.RequiredStatusChecks.Strict,
			Checks: &checks,
		}
	}

	if rule.RequiredPullRequestReviews != nil {
		emptySlice := make([]string, 0)
		protectionRequest.RequiredPullRequestReviews = &github.PullRequestReviewsEnforcementRequest{
			// Avoid unmanaged bypass allowances when they're not set in the CR
			BypassPullRequestAllowancesRequest: &github.BypassPullRequestAllowancesRequest{
				Users: emptySlice, Teams: emptySlice, Apps: emptySlice,
			},
			// Avoid unmanaged dismissal restrictions when they're not set in the CR
			DismissalRestrictionsRequest: &github.DismissalRestrictionsRequest{Users: nil, Teams: nil, Apps: nil},
			DismissStaleReviews:          rule.RequiredPullRequestReviews.DismissStaleReviews,
			RequireCodeOwnerReviews:      rule.RequiredPullRequestReviews.RequireCodeOwnerReviews,
			RequiredApprovingReviewCount: rule.RequiredPullRequestReviews.RequiredApprovingReviewCount,
			RequireLastPushApproval:      rule.RequiredPullRequestReviews.RequireLastPushApproval,
		}
		if rule.RequiredPullRequestReviews.BypassPullRequestAllowances != nil {
			protectionRequest.RequiredPullRequestReviews.BypassPullRequestAllowancesRequest = &github.BypassPullRequestAllowancesRequest{
				Users: util.DefaultToStringSlice(rule.RequiredPullRequestReviews.BypassPullRequestAllowances.Users),
				Teams: util.DefaultToStringSlice(rule.RequiredPullRequestReviews.BypassPullRequestAllowances.Teams),
				Apps:  util.DefaultToStringSlice(rule.RequiredPullRequestReviews.BypassPullRequestAllowances.Apps),
			}
		}
		if rule.RequiredPullRequestReviews.DismissalRestrictions != nil {
			protectionRequest.RequiredPullRequestReviews.DismissalRestrictionsRequest = &github.DismissalRestrictionsRequest{
				Users: rule.RequiredPullRequestReviews.DismissalRestrictions.Users,
				Teams: rule.RequiredPullRequestReviews.DismissalRestrictions.Teams,
				Apps:  rule.RequiredPullRequestReviews.DismissalRestrictions.Apps,
			}
		}
	}

	if rule.BranchProtectionRestrictions != nil {
		protectionRequest.BlockCreations = rule.BranchProtectionRestrictions.BlockCreations
		protectionRequest.Restrictions = &github.BranchRestrictionsRequest{
			Users: util.DefaultToStringSlice(rule.BranchProtectionRestrictions.Users),
			Teams: util.DefaultToStringSlice(rule.BranchProtectionRestrictions.Teams),
			Apps:  util.DefaultToStringSlice(rule.BranchProtectionRestrictions.Apps),
		}
	}

	protection, _, err := gh.Repositories.UpdateBranchProtection(ctx, owner, repoName, rule.Branch, protectionRequest)
	if err != nil {
		return nil, err
	}

	err = handleBranchProtectionSignature(ctx, gh, owner, repoName, rule)
	if err != nil {
		return nil, err
	}

	return unappliedItems(*rule, protectionToRule(rule.Branch, protection)), nil
}

// updateProtectedBranches synchronizes the branch protection rules of a GitHub repository
// to match with those detailed in the repository resource object.
// It performs necessary additions, updates, or deletions based on the difference between
// the actual state on GitHub and the desired state in the resource object.
func updateProtectedBranches(ctx context.Context, cr *v1alpha1.Repository, gh *ghclient.Client, repoName string) error {
	protectedBranches, err := listProtectedBranches(ctx, gh, cr.Spec.ForProvider.Org, repoName)
	if err != nil {
		return err
	}
	crBPRToConfig := getBPRMapFromCr(cr.Spec.ForProvider.BranchProtectionRules)
	_, err = filterMissingBranchProtectionRules(ctx, gh, cr.Spec.ForProvider.Org, repoName, crBPRToConfig, protectedBranchSet(protectedBranches))
	if err != nil {
		return err
	}
	ghBPRToConfig, err := getBPRWithConfig(ctx, gh, cr.Spec.ForProvider.Org, repoName, protectedBranches)
	if err != nil {
		return err
	}

	toDelete, toAdd, toUpdate := util.DiffProtectedBranches(ghBPRToConfig, crBPRToConfig)

	for branchName := range toDelete {
		_, err = gh.Repositories.RemoveBranchProtection(ctx, cr.Spec.ForProvider.Org, repoName, branchName)
		if err != nil {
			return err
		}
	}

	for key := range toAdd {
		// avoid "G601: Implicit memory aliasing in for loop"
		config := toAdd[key]
		items, err := editProtectedBranch(ctx, &config, gh, cr.Spec.ForProvider.Org, repoName)
		if err != nil {
			return err
		}
		setUnappliedBranchProtection(cr, config, items)
	}

	for key := range toUpdate {
		// avoid "G601: Implicit memory aliasing in for loop"
		config := toUpdate[key]
		items, err := editProtectedBranch(ctx, &config, gh, cr.Spec.ForProvider.Org, repoName)
		if err != nil {
			return err
		}
		setUnappliedBranchProtection(cr, config, items)
	}

	return nil
}

// handleBranchProtectionSignature manages the requirement of signed commits for protected branches
// depending on the configuration. If RequireSignedCommits is set to true, it enforces signed commits,
// making them mandatory for all contributors. If it's false, signing commits is optional.
// It returns an error if any of the GitHub API calls fail.
func handleBranchProtectionSignature(ctx context.Context, gh *ghclient.Client, owner, repoName string, protectionRule *v1alpha1.BranchProtectionRule) error {
	if protectionRule.RequireSignedCommits != nil && *protectionRule.RequireSignedCommits {
		_, _, err := gh.Repositories.RequireSignaturesOnProtectedBranch(ctx, owner, repoName, protectionRule.Branch)
		if err != nil {
			return err
		}
	} else {
		_, err := gh.Repositories.OptionalSignaturesOnProtectedBranch(ctx, owner, repoName, protectionRule.Branch)
		if err != nil {
			return err
		}
	}
	return nil
}

// getRepositoryRules retrieves all the rules for a given GitHub repository.
// It uses pagination to handle large numbers of rules, fetching 100 rules per API call.
func getRepositoryRules(ctx context.Context, gh *ghclient.Client, org, repo string) ([]*github.Ruleset, error) {
	opt := &github.ListOptions{PerPage: 100}
	var allRules []*github.Ruleset

	for {
		rules, resp, err := gh.Repositories.GetAllRulesets(ctx, org, repo, true)
		if err != nil {
			return nil, err
		}

		allRules = append(allRules, rules...)

		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}

	return allRules, nil
}

// getRepositoryRulesMapFromCr generates a map from the RepositoryRules slice
// in the Crossplane resource.
//
//nolint:gocyclo
func getRepositoryRulesMapFromCr(rules []v1alpha1.RepositoryRuleset) map[string]v1alpha1.RepositoryRuleset {
	crRulesToConfig := make(map[string]v1alpha1.RepositoryRuleset, len(rules))

	for i := range rules {
		// Use a copy to avoid changing passed []v1alpha1.RepositoryRules
		// This prevents the controller from changing the spec of the live CR
		// It can also prevent infinite reconciliation loops when managing the resources with ArgoCD
		orig := &rules[i]
		rCopy := orig.DeepCopy()

		// handle optional fields
		rCopy.Target = util.StringDerefToPointer(rCopy.Target, "branch")
		rCopy.Enforcement = util.StringDerefToPointer(rCopy.Enforcement, "active")

		rConditions := rCopy.Conditions

		if rConditions != nil && rConditions.RefName != nil {
			if rConditions.RefName.Include != nil {
				rConditions.RefName.Include = util.SortAndReturn(rConditions.RefName.Include)
			}
			if rConditions.RefName.Exclude != nil {
				rConditions.RefName.Exclude = util.SortAndReturn(rConditions.RefName.Exclude)
			}
		}

		if rConditions == nil {
			rConditions = &v1alpha1.RulesetConditions{
				RefName: &v1alpha1.RulesetRefName{
					Include: []string{},
					Exclude: []string{},
				},
			}
			// Update the rConditions reference in rCopy
			rCopy.Conditions = rConditions
		}

		rBActors := rCopy.BypassActors
		if rBActors != nil {
			for a := range rBActors {
				actor := rBActors[a] // Make a copy of the actor

				// Set ActorId, ActorType, and BypassMode fields
				actor.ActorId = rBActors[a].ActorId
				actor.ActorType = rBActors[a].ActorType
				actor.BypassMode = rBActors[a].BypassMode

				// Update the actor in the slice
				rBActors[a] = actor
			}
			util.SortRulesBypassActors(rBActors)
		}
		rRules := rCopy.Rules
		if rRules != nil {
			rRules.RequiredSignatures = util.BoolDerefToPointer(rRules.RequiredSignatures, false)
			rRules.NonFastForward = util.BoolDerefToPointer(rRules.NonFastForward, false)
			rRules.Creation = util.BoolDerefToPointer(rRules.Creation, false)
			rRules.Deletion = util.BoolDerefToPointer(rRules.Deletion, false)
			rRules.RequiredLinearHistory = util.BoolDerefToPointer(rRules.RequiredLinearHistory, false)
			rRules.Update = util.BoolDerefToPointer(rRules.Update, false)

			if rRules.RequiredDeployments != nil {
				if rRules.RequiredDeployments.Environments != nil {
					rRules.RequiredDeployments.Environments = util.SortAndReturn(rRules.RequiredDeployments.Environments)
				}
			}
			if rRules.PullRequest != nil {
				rRules.PullRequest.DismissStaleReviewsOnPush = util.BoolDerefToPointer(rRules.PullRequest.DismissStaleReviewsOnPush, false)
				rRules.PullRequest.RequireCodeOwnerReview = util.BoolDerefToPointer(rRules.PullRequest.RequireCodeOwnerReview, false)
				rRules.PullRequest.RequireLastPushApproval = util.BoolDerefToPointer(rRules.PullRequest.RequireLastPushApproval, false)
				rRules.PullRequest.RequiredReviewThreadResolution = util.BoolDerefToPointer(rRules.PullRequest.RequiredReviewThreadResolution, false)
				rRules.PullRequest.RequiredApprovingReviewCount = util.IntDerefToPointer(rRules.PullRequest.RequiredApprovingReviewCount, 0)
			}
			if rRules.RequiredStatusChecks != nil {
				if rRules.RequiredStatusChecks.RequiredStatusChecks != nil {
					copyOfStatusChecks := make([]*v1alpha1.RulesRequiredStatusChecksParameters, len(rRules.RequiredStatusChecks.RequiredStatusChecks))
					copy(copyOfStatusChecks, rRules.RequiredStatusChecks.RequiredStatusChecks)
					util.SortRulesRequiredStatusChecks(copyOfStatusChecks)
					rRules.RequiredStatusChecks.RequiredStatusChecks = copyOfStatusChecks
				}
				rRules.RequiredStatusChecks.StrictRequiredStatusChecksPolicy = util.BoolDerefToPointer(rRules.RequiredStatusChecks.StrictRequiredStatusChecksPolicy, false)
			}
		}
		crRulesToConfig[rCopy.Name] = *rCopy
	}

	return crRulesToConfig
}

// getRepositoryRulesWithConfig creates a map of RepositoryRules based on the
// branch rules fetched from the GitHub API.
//
//nolint:gocyclo
func getRepositoryRulesWithConfig(ctx context.Context, gh *ghclient.Client, owner, repo string, ghRulesets []*github.Ruleset) (map[string]v1alpha1.RepositoryRuleset, error) {
	rulesToConfig := make(map[string]v1alpha1.RepositoryRuleset, len(ghRulesets))

	for _, rule := range ghRulesets {
		rRuleset, _, err := gh.Repositories.GetRuleset(ctx, owner, repo, *rule.ID, true)
		if err != nil {
			return nil, err
		}
		ruleset := v1alpha1.RepositoryRuleset{
			Target:      util.ToStringPtr(rule.GetTarget()),
			Enforcement: &rule.Enforcement,
			Name:        rule.Name,

			Conditions: &v1alpha1.RulesetConditions{
				RefName: &v1alpha1.RulesetRefName{
					Include: []string{},
					Exclude: []string{},
				},
			},
			BypassActors: nil,
			Rules: &v1alpha1.Rules{
				Creation:              util.ToBoolPtr(false),
				Update:                util.ToBoolPtr(false),
				Deletion:              util.ToBoolPtr(false),
				RequiredLinearHistory: util.ToBoolPtr(false),
				RequiredDeployments:   nil,
				RequiredSignatures:    util.ToBoolPtr(false),
				NonFastForward:        util.ToBoolPtr(false),
				PullRequest:           nil,
				RequiredStatusChecks:  nil,
			},
		}

		if rRuleset.Conditions != nil {
			if rRuleset.Conditions.RefName != nil {
				ruleset.Conditions.RefName = &v1alpha1.RulesetRefName{
					Include: util.SortAndReturn(rRuleset.Conditions.RefName.Include),
					Exclude: util.SortAndReturn(rRuleset.Conditions.RefName.Exclude),
				}
			}
		}

		if rRuleset.BypassActors != nil {
			if len(rRuleset.BypassActors) > 0 {
				ruleset.BypassActors = make([]*v1alpha1.RulesetByPassActors, len(rRuleset.BypassActors))
				for i, actor := range rRuleset.BypassActors {
					ruleset.BypassActors[i] = &v1alpha1.RulesetByPassActors{
						ActorType:  actor.ActorType,
						ActorId:    actor.ActorID,
						BypassMode: actor.BypassMode,
					}
				}
				util.SortRulesBypassActors(ruleset.BypassActors)
			}

		}
		if rRuleset != nil {
			for _, rule := range rRuleset.Rules {
				switch rule.Type {
				case "creation":
					ruleset.Rules.Creation = util.ToBoolPtr(true)
				case "deletion":
					ruleset.Rules.Deletion = util.ToBoolPtr(true)
				case "required_linear_history":
					ruleset.Rules.RequiredLinearHistory = util.ToBoolPtr(true)
				case "required_signatures":
					ruleset.Rules.RequiredSignatures = util.ToBoolPtr(true)
				case "non_fast_forward":
					ruleset.Rules.NonFastForward = util.ToBoolPtr(true)
				case "update":
					ruleset.Rules.Update = util.ToBoolPtr(true)
				case "pull_request":
					if rule.Parameters != nil {
						params := github.PullRequestRuleParameters{}
						if err := json.Unmarshal(*rule.Parameters, &params); err != nil {
							return nil, err
						}
						ruleset.Rules.PullRequest = &v1alpha1.RulesPullRequest{
							RequireCodeOwnerReview:         util.ToBoolPtr(params.RequireCodeOwnerReview),
							RequireLastPushApproval:        util.ToBoolPtr(params.RequireLastPushApproval),
							RequiredReviewThreadResolution: util.ToBoolPtr(params.RequiredReviewThreadResolution),
							RequiredApprovingReviewCount:   util.ToIntPtr(params.RequiredApprovingReviewCount),
							DismissStaleReviewsOnPush:      util.ToBoolPtr(params.DismissStaleReviewsOnPush),
						}
					}
				case "required_deployments":
					if rule.Parameters != nil {
						params := github.RequiredDeploymentEnvironmentsRuleParameters{}
						if err := json.Unmarshal(*rule.Parameters, &params); err != nil {
							return nil, err
						}
						ruleset.Rules.RequiredDeployments = &v1alpha1.RulesRequiredDeployments{
							Environments: util.SortAndReturn(params.RequiredDeploymentEnvironments),
						}
					}
				case "required_status_checks":
					if rule.Parameters != nil {
						params := github.RequiredStatusChecksRuleParameters{}
						if err := json.Unmarshal(*rule.Parameters, &params); err != nil {
							return nil, err
						}
						requiredStatusChecksParameters := make([]*v1alpha1.RulesRequiredStatusChecksParameters, len(params.RequiredStatusChecks))
						for i, statusCheck := range params.RequiredStatusChecks {
							requiredStatusChecksParameters[i] = &v1alpha1.RulesRequiredStatusChecksParameters{
								Context:       statusCheck.Context,
								IntegrationId: statusCheck.IntegrationID,
							}
						}
						util.SortRulesRequiredStatusChecks(requiredStatusChecksParameters)

						ruleset.Rules.RequiredStatusChecks = &v1alpha1.RulesRequiredStatusChecks{
							StrictRequiredStatusChecksPolicy: util.ToBoolPtr(params.StrictRequiredStatusChecksPolicy),
							RequiredStatusChecks:             requiredStatusChecksParameters,
						}
					}
				}

			}

		}

		rulesToConfig[rule.Name] = ruleset
	}

	return rulesToConfig, nil

}

// crRepoRulesToRulesConfig transforms a RepositoryRuleset object from the Crossplane resource
// into a Ruleset object that can be used with the GitHub API.
//
//nolint:gocyclo
func crRepoRulesToRulesConfig(rule v1alpha1.RepositoryRuleset) *github.Ruleset {
	githubRuleset := &github.Ruleset{
		Name:        rule.Name,
		Enforcement: *rule.Enforcement,
		Target:      rule.Target,
	}

	// If BypassActors is not nil, transform it into the github rule BypassActors
	if rule.BypassActors != nil {
		githubBypassActors := make([]*github.BypassActor, len(rule.BypassActors))
		for i, actor := range rule.BypassActors {
			githubBypassActors[i] = &github.BypassActor{
				ActorID:    actor.ActorId,
				ActorType:  actor.ActorType,
				BypassMode: actor.BypassMode,
			}
		}
		githubRuleset.BypassActors = githubBypassActors
	}

	// If Conditions is not nil, transform it into the github rule Conditions
	if rule.Conditions != nil {
		githubConditions := &github.RulesetConditions{
			RefName: &github.RulesetRefConditionParameters{
				Include: rule.Conditions.RefName.Include,
				Exclude: rule.Conditions.RefName.Exclude,
			},
		}
		githubRuleset.Conditions = githubConditions
	}
	// If Rules is not nil, transform it into the github rule Rules
	if rule.Rules != nil {
		githubRules := make([]*github.RepositoryRule, 0)
		if rule.Rules.RequiredStatusChecks != nil {
			params := github.RequiredStatusChecksRuleParameters{
				StrictRequiredStatusChecksPolicy: *rule.Rules.RequiredStatusChecks.StrictRequiredStatusChecksPolicy,
			}
			requiredStatusChecks := make([]github.RuleRequiredStatusChecks, len(rule.Rules.RequiredStatusChecks.RequiredStatusChecks))
			for i, statusCheck := range rule.Rules.RequiredStatusChecks.RequiredStatusChecks {
				requiredStatusChecks[i] = github.RuleRequiredStatusChecks{
					Context:       statusCheck.Context,
					IntegrationID: statusCheck.IntegrationId,
				}
			}
			params.RequiredStatusChecks = requiredStatusChecks
			paramsBytes, err := json.Marshal(params)
			if err != nil {
				return nil
			}
			rawParams := json.RawMessage(paramsBytes)
			githubRules = append(githubRules, &github.RepositoryRule{
				Type:       "required_status_checks",
				Parameters: &rawParams,
			})
		}

		if *rule.Rules.Creation {
			githubRules = append(githubRules, &github.RepositoryRule{
				Type: "creation",
			})
		}

		if *rule.Rules.Deletion {
			githubRules = append(githubRules, &github.RepositoryRule{
				Type: "deletion",
			})
		}

		if *rule.Rules.RequiredLinearHistory {
			githubRules = append(githubRules, &github.RepositoryRule{
				Type: "required_linear_history",
			})
		}

		if *rule.Rules.RequiredSignatures {
			githubRules = append(githubRules, &github.RepositoryRule{
				Type: "required_signatures",
			})
		}
		if *rule.Rules.NonFastForward {
			githubRules = append(githubRules, &github.RepositoryRule{
				Type: "non_fast_forward",
			})
		}
		if *rule.Rules.Update {
			githubRules = append(githubRules, &github.RepositoryRule{
				Type: "update",
			})
		}
		if rule.Rules.PullRequest != nil {
			params := github.PullRequestRuleParameters{
				DismissStaleReviewsOnPush:      *rule.Rules.PullRequest.DismissStaleReviewsOnPush,
				RequireCodeOwnerReview:         *rule.Rules.PullRequest.RequireCodeOwnerReview,
				RequireLastPushApproval:        *rule.Rules.PullRequest.RequireLastPushApproval,
				RequiredReviewThreadResolution: *rule.Rules.PullRequest.RequiredReviewThreadResolution,
				RequiredApprovingReviewCount:   *rule.Rules.PullRequest.RequiredApprovingReviewCount,
			}
			paramsBytes, err := json.Marshal(params)
			if err != nil {
				return nil
			}
			rawParams := json.RawMessage(paramsBytes)
			githubRules = append(githubRules, &github.RepositoryRule{
				Type:       "pull_request",
				Parameters: &rawParams,
			})
		}
		if rule.Rules.RequiredDeployments != nil {
			params := github.RequiredDeploymentEnvironmentsRuleParameters{
				RequiredDeploymentEnvironments: rule.Rules.RequiredDeployments.Environments,
			}
			paramsBytes, err := json.Marshal(params)
			if err != nil {
				return nil
			}
			rawParams := json.RawMessage(paramsBytes)
			githubRules = append(githubRules, &github.RepositoryRule{
				Type:       "required_deployments",
				Parameters: &rawParams,
			})
		}
		githubRuleset.Rules = githubRules

	}
	return githubRuleset
}

// updateRepositoryRules synchronizes the repository rules of a GitHub repository
// to match with those detailed in the repository resource object.
// It performs necessary additions, updates, or deletions based on the difference between
// the actual state on GitHub and the desired state in the resource object.
func updateRepositoryRules(ctx context.Context, cr *v1alpha1.Repository, gh *ghclient.Client, repoName string) error {
	// Fetch the current repository rules from GitHub
	ghRepoRules, err := getRepositoryRules(ctx, gh, cr.Spec.ForProvider.Org, repoName)
	if err != nil {
		return err
	}
	// Generate a map of the repository rules from the Crossplane resource
	crRToConfig := getRepositoryRulesMapFromCr(cr.Spec.ForProvider.RepositoryRules)
	// Generate a map of the repository rules from GitHub
	ghRToConfig, err := getRepositoryRulesWithConfig(ctx, gh, cr.Spec.ForProvider.Org, repoName, ghRepoRules)
	if err != nil {
		return err
	}
	// Determine which rules need to be deleted, added, or updated
	toDelete, toAdd, toUpdate := util.DiffRepositoryRulesets(ghRToConfig, crRToConfig)

	// Delete the rules that are no longer needed
	for name := range toDelete {
		rulesetID, _ := findRulesetIDByName(ghRepoRules, name)
		_, err = gh.Repositories.DeleteRuleset(ctx, cr.Spec.ForProvider.Org, repoName, rulesetID)
		if err != nil {
			return err
		}
	}
	// Add the new rules
	for _, rule := range toAdd {
		_, _, err := gh.Repositories.CreateRuleset(ctx, cr.Spec.ForProvider.Org, repoName, crRepoRulesToRulesConfig(rule))
		if err != nil {
			return err
		}
	}
	// Update the existing rules
	for name, rule := range toUpdate {
		rulesetID, _ := findRulesetIDByName(ghRepoRules, name)
		_, _, err := gh.Repositories.UpdateRuleset(ctx, cr.Spec.ForProvider.Org, repoName, rulesetID, crRepoRulesToRulesConfig(rule))
		if err != nil {
			return err
		}
	}
	return nil
}

// findRulesetIDByName iterates over a slice of GitHub Ruleset pointers and returns the ID of the ruleset
// that matches the provided name. If no match is found, it returns an error.
func findRulesetIDByName(rulesets []*github.Ruleset, name string) (int64, error) {
	for _, ruleset := range rulesets {
		if ruleset.Name == name {
			return *ruleset.ID, nil
		}
	}
	return 0, fmt.Errorf("ruleset with name %s not found", name)
}

//nolint:gocyclo
func (c *external) Update(ctx context.Context, mg resource.Managed) (managed.ExternalUpdate, error) {
	cr, ok := mg.(*v1alpha1.Repository)
	if !ok {
		return managed.ExternalUpdate{}, errors.New(errNotRepository)
	}

	name := meta.GetExternalName(cr)

	archivedCr := pointer.Deref(cr.Spec.ForProvider.Archived, false)

	// repo visibility makes sense only when a repo is not a fork
	var privateCr *bool

	repo, _, err := c.github.Repositories.Get(ctx, cr.Spec.ForProvider.Org, name)
	if err != nil {
		return managed.ExternalUpdate{}, err
	}

	// Archived repos freeze settings, branch protection, rulesets and webhooks (and
	// collaborator additions). Reconcile only what GitHub still permits while archived:
	// team access, topics and collaborator removals.
	archivedGh := pointer.Deref(repo.Archived, false)
	if archivedCr {
		if !archivedGh {
			if _, _, err = c.github.Repositories.Edit(ctx, cr.Spec.ForProvider.Org, name, &github.Repository{Archived: pointer.To(true)}); err != nil {
				return managed.ExternalUpdate{}, err
			}
		}
		if err = updateRepoTeams(ctx, cr, c.github, name); err != nil {
			return managed.ExternalUpdate{}, err
		}
		if err = removeArchivedRepoUsers(ctx, cr, c.github, name); err != nil {
			return managed.ExternalUpdate{}, err
		}
		if cr.Spec.ForProvider.Topics != nil {
			if _, _, err = c.github.Repositories.ReplaceAllTopics(ctx, cr.Spec.ForProvider.Org, name, cr.Spec.ForProvider.Topics); err != nil {
				return managed.ExternalUpdate{}, err
			}
		}
		return managed.ExternalUpdate{}, nil
	}
	if archivedGh {
		// Unarchive first so the setting writes below are accepted.
		if _, _, err = c.github.Repositories.Edit(ctx, cr.Spec.ForProvider.Org, name, &github.Repository{Archived: pointer.To(false)}); err != nil {
			return managed.ExternalUpdate{}, err
		}
	}

	if repo.Fork != nil && !*repo.Fork {
		val := pointer.Deref(cr.Spec.ForProvider.Private, true)
		privateCr = &val
	}

	isTemplate := pointer.Deref(cr.Spec.ForProvider.IsTemplate, false)

	editReq := &github.Repository{
		Name:        &name,
		Description: &cr.Spec.ForProvider.Description,
		Archived:    &archivedCr,
		Private:     privateCr,
		IsTemplate:  &isTemplate,
	}
	applyMainSettings(editReq, cr)

	_, _, err = c.github.Repositories.Edit(ctx, cr.Spec.ForProvider.Org, name, editReq)
	if err != nil {
		return managed.ExternalUpdate{}, err
	}

	err = updateRepoUsers(ctx, cr, c.github, name)
	if err != nil {
		return managed.ExternalUpdate{}, err
	}

	err = updateRepoTeams(ctx, cr, c.github, name)
	if err != nil {
		return managed.ExternalUpdate{}, err
	}

	if cr.Spec.ForProvider.Webhooks != nil {
		err = updateRepoWebhooks(c, ctx, cr, c.github, name)
		if err != nil {
			return managed.ExternalUpdate{}, err
		}
	}

	if cr.Spec.ForProvider.BranchProtectionRules != nil {
		err = updateProtectedBranches(ctx, cr, c.github, name)
		if err != nil {
			return managed.ExternalUpdate{}, err
		}
	}
	if cr.Spec.ForProvider.RepositoryRules != nil {
		err = updateRepositoryRules(ctx, cr, c.github, name)
		if err != nil {
			return managed.ExternalUpdate{}, err
		}

	}

	// Update topics if specified
	if cr.Spec.ForProvider.Topics != nil {
		_, _, err = c.github.Repositories.ReplaceAllTopics(ctx, cr.Spec.ForProvider.Org, name, cr.Spec.ForProvider.Topics)
		if err != nil {
			return managed.ExternalUpdate{}, err
		}
	}

	return managed.ExternalUpdate{}, nil
}

func (c *external) Delete(ctx context.Context, mg resource.Managed) error {
	cr, ok := mg.(*v1alpha1.Repository)
	if !ok {
		return errors.New(errNotRepository)
	}

	name := meta.GetExternalName(cr)

	forceDelete := pointer.Deref(cr.Spec.ForProvider.ForceDelete, false)
	if !forceDelete {
		return errors.New("You can only delete repositories by setting `forceDelete: true`")
	}

	_, err := c.github.Repositories.Delete(ctx, cr.Spec.ForProvider.Org, name)
	if err != nil {
		return err
	}

	if c.metrics != nil {
		c.metrics.ForgetRepository(cr.Spec.ForProvider.Org, name)
	}

	return nil
}
