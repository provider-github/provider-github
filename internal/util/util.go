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
