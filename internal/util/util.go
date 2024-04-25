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

package util

import (
	"reflect"
	"sort"

	"github.com/crossplane/provider-github/apis/organizations/v1alpha1"
	"github.com/google/go-cmp/cmp"
	"k8s.io/utils/pointer"
)

func SortByKey(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	keys := make([]string, 0, len(m))

	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		out[k] = m[k]
	}

	return out
}

func DiffPermissions(a map[string]string, b map[string]string) (map[string]string, map[string]string, map[string]string) {
	inANotInB := make(map[string]string)
	inBNotInA := make(map[string]string)
	diffs := make(map[string]string)

	for entity, va := range a {
		vb, ok := b[entity]
		if !ok {
			inANotInB[entity] = va
		} else if va != vb {
			diffs[entity] = vb
		}
	}

	for entity, vb := range b {
		_, ok := a[entity]
		if !ok {
			inBNotInA[entity] = vb
		}
	}

	return inANotInB, inBNotInA, diffs
}

func MergeMaps(m1 map[string]string, m2 map[string]string) map[string]string {
	merged := make(map[string]string)
	for k, v := range m1 {
		merged[k] = v
	}
	for key, value := range m2 {
		merged[key] = value
	}
	return merged
}

// Contains function to check if a string slice contains a specific string
func Contains(slice []string, str string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}
	return false
}

func DiffRepoWebhooks(a, b map[string]v1alpha1.RepositoryWebhook) (map[string]v1alpha1.RepositoryWebhook, map[string]v1alpha1.RepositoryWebhook, map[string]v1alpha1.RepositoryWebhook) {
	inANotInB := make(map[string]v1alpha1.RepositoryWebhook)
	inBNotInA := make(map[string]v1alpha1.RepositoryWebhook)
	diffs := make(map[string]v1alpha1.RepositoryWebhook)

	for entity, va := range a {
		vb, ok := b[entity]
		if !ok {
			inANotInB[entity] = va
		} else if !reflect.DeepEqual(va, vb) {
			diffs[entity] = vb
		}
	}

	for entity, vb := range b {
		_, ok := a[entity]
		if !ok {
			inBNotInA[entity] = vb
		}
	}

	return inANotInB, inBNotInA, diffs
}

// DiffProtectedBranches compares two maps of BranchProtectionRule, map 'a’ and map 'b’.
// It returns three maps:
// inANotInB: entities (keys) that are present in 'a' but not in 'b' mapped to their values in 'a'
// inBNotInA: entities (keys) that are present in 'b' but not in 'a' mapped to their values in 'b'
// diffs: entities (keys) that are present in both 'a' and 'b' but have different values, mapped to their values in 'b'
func DiffProtectedBranches(a, b map[string]v1alpha1.BranchProtectionRule) (
	map[string]v1alpha1.BranchProtectionRule,
	map[string]v1alpha1.BranchProtectionRule,
	map[string]v1alpha1.BranchProtectionRule,
) {
	inANotInB := make(map[string]v1alpha1.BranchProtectionRule)
	inBNotInA := make(map[string]v1alpha1.BranchProtectionRule)
	diffs := make(map[string]v1alpha1.BranchProtectionRule)

	for entity, va := range a {
		vb, ok := b[entity]
		if !ok {
			inANotInB[entity] = va
		} else if !cmp.Equal(va, vb) {
			diffs[entity] = vb
		}
	}

	for entity, vb := range b {
		_, ok := a[entity]
		if !ok {
			inBNotInA[entity] = vb
		}
	}

	return inANotInB, inBNotInA, diffs

}

// DiffRepositoryRulesets compares two maps of RepositoryRuleset, 'a' and 'b'.
// It returns three maps:
// inANotInB: entities (keys) that are present in 'a' but not in 'b' mapped to their values in 'a'
// inBNotInA: entities (keys) that are present in 'b' but not in 'a' mapped to their values in 'b'
// diffs: entities (keys) that are present in both 'a' and 'b' but have different values, mapped to their values in 'b'
func DiffRepositoryRulesets(a, b map[string]v1alpha1.RepositoryRuleset) (
	map[string]v1alpha1.RepositoryRuleset,
	map[string]v1alpha1.RepositoryRuleset,
	map[string]v1alpha1.RepositoryRuleset) {
	inANotInB := make(map[string]v1alpha1.RepositoryRuleset)
	inBNotInA := make(map[string]v1alpha1.RepositoryRuleset)
	diffs := make(map[string]v1alpha1.RepositoryRuleset)

	for entity, va := range a {
		vb, ok := b[entity]
		if !ok {
			inANotInB[entity] = va
		} else if !reflect.DeepEqual(va, vb) {
			diffs[entity] = vb
		}
	}

	for entity, vb := range b {
		_, ok := a[entity]
		if !ok {
			inBNotInA[entity] = vb
		}
	}

	return inANotInB, inBNotInA, diffs
}

// DefaultToStringSlice is a helper function that checks if the provided slice is
// nil and returns an empty string slice in that case. If the slice is not nil,
// the same slice is returned. The purpose of this function is to avoid nil
// dereference issues in slices and provide a safe way to default to an empty slice.
func DefaultToStringSlice(value []string) []string {
	if value == nil {
		return []string{}
	}
	return value
}

// SortAndReturnPointer sorts a slice of strings and returns
// a pointer to that sorted slice.
func SortAndReturnPointer(s []string) *[]string {
	sort.Strings(s)
	return &s
}

// SortAndReturn sorts a slice of strings in lexicographical order
// and returns the sorted slice.
func SortAndReturn(s []string) []string {
	sort.Strings(s)
	return s
}

// SortRequiredStatusChecks sorts a slice of RequiredStatusCheck pointers in-place
// by the Context field in ascending order.
func SortRequiredStatusChecks(checks []*v1alpha1.RequiredStatusCheck) {
	sort.Slice(checks, func(i, j int) bool {
		return checks[i].Context < checks[j].Context
	})
}

// SortRulesRequiredStatusChecks sorts a slice of RequiredStatusCheck pointers in-place
// by the Context field in ascending order.
func SortRulesRequiredStatusChecks(checks []*v1alpha1.RulesRequiredStatusChecksParameters) {
	sort.Slice(checks, func(i, j int) bool {
		return checks[i].Context < checks[j].Context
	})
}

// SortRulesBypassActors sorts a slice of RulesetByPassActors pointers in-place
// by the ActorId field in ascending order.
func SortRulesBypassActors(actors []*v1alpha1.RulesetByPassActors) {
	sort.Slice(actors, func(i, j int) bool {
		return *actors[i].ActorId < *actors[j].ActorId
	})

}

// ToBoolPtr converts a boolean value to a pointer to a boolean value.
func ToBoolPtr(b bool) *bool {
	return &b
}

// ToIntPtr is a helper function that takes an integer 'i' as input and returns a pointer to 'i'.
// This can be useful when you want to create a pointer to an integer value.
func ToIntPtr(i int) *int {
	return &i
}

// ToInt64Ptr is a helper function that takes an int64 'i' as input and returns a pointer to 'i'.
// This can be useful when you want to create a pointer to an int64 value.
func ToInt64Ptr(i int64) *int64 {
	return &i
}

// ToStringPtr is a helper function that takes a string 's' as input and returns a pointer to 's'.
// This can be useful when you want to create a pointer to a string value.
func ToStringPtr(s string) *string {
	return &s
}

// BoolDerefToPointer dereferences the pointer to bool 'ptr',
// uses 'def' as a default if 'ptr' is nil, and returns a new pointer to the resulting bool.
func BoolDerefToPointer(ptr *bool, def bool) *bool {
	b := pointer.BoolDeref(ptr, def)
	return &b
}

// StringDerefToPointer is a helper function that dereferences a pointer to a string 'ptr',
// and returns a new pointer to the resulting string. If 'ptr' is nil, it uses 'def' as a default value.
func StringDerefToPointer(ptr *string, def string) *string {
	s := pointer.StringDeref(ptr, def)
	return &s
}

// IntDerefToPointer is a helper function that dereferences a pointer to an int 'ptr',
// and returns a new pointer to the resulting int. If 'ptr' is nil, it uses 'def' as a default value.
func IntDerefToPointer(ptr *int, def int) *int {
	i := pointer.IntDeref(ptr, def)
	return &i
}

// Int64DerefToPointer is a helper function that dereferences a pointer to an int64 'ptr',
// and returns a new pointer to the resulting int64. If 'ptr' is nil, it uses 'def' as a default value.
func Int64DerefToPointer(ptr *int64, def int64) *int64 {
	i := pointer.Int64Deref(ptr, def)
	return &i
}

// BoolToInt converts a boolean value to an integer
func BoolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
