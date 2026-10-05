/*
Copyright 2026 The Crossplane Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package util

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	pointer "k8s.io/utils/ptr"

	"github.com/crossplane/provider-github/apis/organizations/v1alpha1"
)

// Bypass actors sort into one order from any input order, nil actor IDs included.
func TestSortRulesBypassActorsNilActorID(t *testing.T) {
	actor := func(id *int64, typ, mode string) *v1alpha1.RulesetByPassActors {
		return &v1alpha1.RulesetByPassActors{ActorId: id, ActorType: pointer.To(typ), BypassMode: pointer.To(mode)}
	}
	want := []*v1alpha1.RulesetByPassActors{
		actor(nil, "DeployKey", "always"),
		actor(nil, "OrganizationAdmin", "always"),
		actor(pointer.To(int64(5)), "RepositoryRole", "always"),
		actor(pointer.To(int64(2)), "Team", "always"),
		actor(pointer.To(int64(2)), "Team", "pull_request"),
		actor(pointer.To(int64(9)), "Team", "always"),
	}
	got := []*v1alpha1.RulesetByPassActors{want[4], want[2], want[1], want[5], want[0], want[3]}

	SortRulesBypassActors(got)

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("SortRulesBypassActors: -want, +got:\n%s", diff)
	}
}

// Status checks with the same context sort by integration ID, nil first.
func TestSortRulesRequiredStatusChecksSameContext(t *testing.T) {
	check := func(id *int64) *v1alpha1.RulesRequiredStatusChecksParameters {
		return &v1alpha1.RulesRequiredStatusChecksParameters{Context: "ci", IntegrationId: id}
	}
	want := []*v1alpha1.RulesRequiredStatusChecksParameters{check(nil), check(pointer.To(int64(1))), check(pointer.To(int64(2)))}
	got := []*v1alpha1.RulesRequiredStatusChecksParameters{want[2], want[0], want[1]}

	SortRulesRequiredStatusChecks(got)

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("SortRulesRequiredStatusChecks: -want, +got:\n%s", diff)
	}
}
