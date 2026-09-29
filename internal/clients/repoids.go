/*
Copyright 2026 The Crossplane Authors.

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

package clients

import (
	"context"
	"sort"
	"sync"
)

// SortInt64 sorts s in ascending order, in place.
func SortInt64(s []int64) {
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
}

// RepoIDResolver resolves repository names to numeric IDs once per
// reconcile. Avoids hitting Repositories.Get more than once for the
// same name when both Observe and Update need IDs for the same
// SelectedRepositories list.
type RepoIDResolver struct {
	mu    sync.Mutex
	cache map[string]int64
	gh    *Client
	org   string
}

// NewRepoIDResolver returns a RepoIDResolver for repositories in org.
func NewRepoIDResolver(gh *Client, org string) *RepoIDResolver {
	return &RepoIDResolver{cache: map[string]int64{}, gh: gh, org: org}
}

// BatchGetIDs resolves names to repository IDs, preserving order.
func (c *RepoIDResolver) BatchGetIDs(ctx context.Context, names []string) ([]int64, error) {
	if len(names) == 0 {
		return []int64{}, nil
	}
	ids := make([]int64, 0, len(names))
	for _, n := range names {
		id, err := c.getID(ctx, n)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func (c *RepoIDResolver) getID(ctx context.Context, name string) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if id, ok := c.cache[name]; ok {
		return id, nil
	}
	r, _, err := c.gh.Repositories.Get(ctx, c.org, name)
	if err != nil {
		return 0, err
	}
	id := r.GetID()
	c.cache[name] = id
	return id, nil
}
