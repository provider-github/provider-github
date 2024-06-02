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
	"reflect"

	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/pointer"
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
	"github.com/crossplane/provider-github/internal/util"
)

const (
	errNotTeam      = "managed resource is not a Team custom resource"
	errTrackPCUsage = "cannot track ProviderConfig usage"
	errGetPC        = "cannot get ProviderConfig"
	errGetCreds     = "cannot get credentials"

	errNewClient = "cannot create new Service"
)

// Setup adds a controller that reconciles Team managed resources.
func Setup(mgr ctrl.Manager, o controller.Options) error {
	name := managed.ControllerName(v1alpha1.TeamGroupKind)

	cps := []managed.ConnectionPublisher{managed.NewAPISecretPublisher(mgr.GetClient(), mgr.GetScheme())}
	if o.Features.Enabled(features.EnableAlphaExternalSecretStores) {
		cps = append(cps, connection.NewDetailsManager(mgr.GetClient(), apisv1alpha1.StoreConfigGroupVersionKind))
	}

	r := managed.NewReconciler(mgr,
		resource.ManagedKind(v1alpha1.TeamGroupVersionKind),
		managed.WithExternalConnecter(&connector{
			kube:        mgr.GetClient(),
			usage:       resource.NewProviderConfigUsageTracker(mgr.GetClient(), &apisv1alpha1.ProviderConfigUsage{}),
			newClientFn: ghclient.NewClient}),
		managed.WithLogger(o.Logger.WithValues("controller", name)),
		managed.WithPollInterval(o.PollInterval),
		managed.WithRecorder(event.NewAPIRecorder(mgr.GetEventRecorderFor(name))),
		managed.WithConnectionPublishers(cps...))

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		WithOptions(o.ForControllerRuntime()).
		WithEventFilter(resource.DesiredStateChanged()).
		For(&v1alpha1.Team{}).
		Complete(ratelimiter.NewReconciler(name, r, o.GlobalRateLimiter))
}

type connector struct {
	kube        client.Client
	usage       resource.Tracker
	newClientFn func(string) (*ghclient.Client, error)
}

func (c *connector) Connect(ctx context.Context, mg resource.Managed) (managed.ExternalClient, error) {
	cr, ok := mg.(*v1alpha1.Team)
	if !ok {
		return nil, errors.New(errNotTeam)
	}

	if err := c.usage.Track(ctx, mg); err != nil {
		return nil, errors.Wrap(err, errTrackPCUsage)
	}

	pc := &apisv1alpha1.ProviderConfig{}
	if err := c.kube.Get(ctx, types.NamespacedName{Name: cr.GetProviderConfigReference().Name}, pc); err != nil {
		return nil, errors.Wrap(err, errGetPC)
	}

	cd := pc.Spec.Credentials
	data, err := resource.CommonCredentialExtractor(ctx, cd.Source, c.kube, cd.CommonCredentialSelectors)
	if err != nil {
		return nil, errors.Wrap(err, errGetCreds)
	}

	gh, err := c.newClientFn(string(data))
	if err != nil {
		return nil, errors.Wrap(err, errNewClient)
	}

	return &external{github: gh}, nil
}

type external struct {
	github *ghclient.Client
}

func (c *external) Observe(ctx context.Context, mg resource.Managed) (managed.ExternalObservation, error) {
	cr, ok := mg.(*v1alpha1.Team)
	if !ok {
		return managed.ExternalObservation{}, errors.New(errNotTeam)
	}

	name := meta.GetExternalName(cr)
	teamSlug := slug.Make(name)

	t, _, err := c.github.Teams.GetTeamBySlug(ctx, cr.Spec.ForProvider.Org, teamSlug)
	if ghclient.Is404(err) {
		return managed.ExternalObservation{ResourceExists: false}, nil
	}
	if err != nil {
		return managed.ExternalObservation{}, err
	}

	crMToPermission := getUserPermissionMapFromCr(cr.Spec.ForProvider.Members)
	ghMToPermission, err := getMembersWithPermissions(ctx, c.github, cr.Spec.ForProvider.Org, teamSlug)
	if err != nil {
		return managed.ExternalObservation{}, err
	}

	crParentTeamSlug := slug.Make(pointer.StringDeref(cr.Spec.ForProvider.Parent, ""))
	ghParentTeamSlug := ""
	if t.Parent != nil {
		ghParentTeamSlug = *t.Parent.Slug
	}

	if crParentTeamSlug != ghParentTeamSlug ||
		pointer.StringDeref(cr.Spec.ForProvider.Privacy, "secret") != *t.Privacy ||
		cr.Spec.ForProvider.Description != *t.Description ||
		!reflect.DeepEqual(util.SortByKey(ghMToPermission), util.SortByKey(crMToPermission)) {

		return managed.ExternalObservation{
			ResourceExists:   true,
			ResourceUpToDate: false,
		}, nil
	}

	cr.SetConditions(xpv1.Available())

	return managed.ExternalObservation{
		ResourceExists:   true,
		ResourceUpToDate: true,
	}, nil
}

func getUserPermissionMapFromCr(users []v1alpha1.TeamMemberUser) map[string]string {
	crMToPermission := make(map[string]string, len(users))

	for _, user := range users {
		crMToPermission[user.User] = user.Role
	}

	return crMToPermission
}

func getMembersWithPermissions(ctx context.Context, gh *ghclient.Client, org, slug string) (map[string]string, error) {
	mToPermission := make(map[string]string)
	roles := []string{"member", "maintainer"}

	for _, role := range roles {
		opt := &github.TeamListTeamMembersOptions{
			Role:        role,
			ListOptions: github.ListOptions{PerPage: 100},
		}

		for {
			members, resp, err := gh.Teams.ListTeamMembersBySlug(ctx, org, slug, opt)
			if err != nil {
				return nil, err
			}

			for _, m := range members {
				mToPermission[*m.Login] = role
			}

			if resp.NextPage == 0 {
				break
			}
			opt.Page = resp.NextPage
		}
	}

	return mToPermission, nil
}

func (c *external) Create(ctx context.Context, mg resource.Managed) (managed.ExternalCreation, error) {
	cr, ok := mg.(*v1alpha1.Team)
	if !ok {
		return managed.ExternalCreation{}, errors.New(errNotTeam)
	}

	name := meta.GetExternalName(cr)
	teamSlug := slug.Make(name)
	privacy := pointer.StringDeref(cr.Spec.ForProvider.Privacy, "secret")

	t := github.NewTeam{
		Name:        name,
		Description: &cr.Spec.ForProvider.Description,
		Privacy:     &privacy,
	}
	_, _, err := c.github.Teams.CreateTeam(ctx, cr.Spec.ForProvider.Org, t)
	if err != nil {
		return managed.ExternalCreation{}, err
	}

	if cr.Spec.ForProvider.Members != nil {
		for _, user := range cr.Spec.ForProvider.Members {
			opt := &github.TeamAddTeamMembershipOptions{
				Role: user.Role,
			}
			_, _, err = c.github.Teams.AddTeamMembershipBySlug(ctx, cr.Spec.ForProvider.Org, teamSlug, user.User, opt)
			if err != nil {
				return managed.ExternalCreation{}, err
			}
		}
	}

	return managed.ExternalCreation{}, nil
}

func updateTeamUsers(ctx context.Context, cr *v1alpha1.Team, gh *ghclient.Client, teamSlug string) error {
	crMToPermission := getUserPermissionMapFromCr(cr.Spec.ForProvider.Members)
	ghMToPermission, err := getMembersWithPermissions(ctx, gh, cr.Spec.ForProvider.Org, teamSlug)
	if err != nil {
		return err
	}

	toDelete, toInvite, toUpdate := util.DiffPermissions(ghMToPermission, crMToPermission)

	for userName := range toDelete {
		_, err := gh.Teams.RemoveTeamMembershipBySlug(ctx, cr.Spec.ForProvider.Org, teamSlug, userName)
		if err != nil {
			return err
		}
	}

	for userName, role := range util.MergeMaps(toInvite, toUpdate) {
		opt := &github.TeamAddTeamMembershipOptions{
			Role: role,
		}

		_, _, err = gh.Teams.AddTeamMembershipBySlug(ctx, cr.Spec.ForProvider.Org, teamSlug, userName, opt)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *external) Update(ctx context.Context, mg resource.Managed) (managed.ExternalUpdate, error) {
	cr, ok := mg.(*v1alpha1.Team)
	if !ok {
		return managed.ExternalUpdate{}, errors.New(errNotTeam)
	}

	name := meta.GetExternalName(cr)
	teamSlug := slug.Make(name)

	err := updateTeamUsers(ctx, cr, c.github, teamSlug)
	if err != nil {
		return managed.ExternalUpdate{}, err
	}

	crParentTeamSlug := ""
	parentT := &github.Team{}
	removeParent := true

	if cr.Spec.ForProvider.Parent != nil {
		crParentTeamSlug = slug.Make(*cr.Spec.ForProvider.Parent)
		parentT, _, err = c.github.Teams.GetTeamBySlug(ctx, cr.Spec.ForProvider.Org, crParentTeamSlug)
		if err != nil {
			return managed.ExternalUpdate{}, err
		}
		removeParent = false
	}

	privacy := pointer.StringDeref(cr.Spec.ForProvider.Privacy, "secret")
	newTeam := github.NewTeam{
		Name:        name,
		Privacy:     &privacy,
		Description: &cr.Spec.ForProvider.Description,
	}
	if !removeParent {
		newTeam.ParentTeamID = parentT.ID
	}

	_, _, err = c.github.Teams.EditTeamBySlug(ctx, cr.Spec.ForProvider.Org, teamSlug, newTeam, removeParent)
	if err != nil {
		return managed.ExternalUpdate{}, err
	}

	return managed.ExternalUpdate{}, nil
}

func (c *external) Delete(ctx context.Context, mg resource.Managed) error {
	cr, ok := mg.(*v1alpha1.Team)
	if !ok {
		return errors.New(errNotTeam)
	}

	name := meta.GetExternalName(cr)
	teamSlug := slug.Make(name)

	_, err := c.github.Teams.DeleteTeamBySlug(ctx, cr.Spec.ForProvider.Org, teamSlug)
	if err != nil {
		return err
	}

	return nil
}
