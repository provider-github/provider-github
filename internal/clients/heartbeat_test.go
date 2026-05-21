/*
Copyright 2026 The Crossplane Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package clients

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/google/go-github/v62/github"

	"github.com/crossplane/provider-github/internal/clients/fake"
)

// newHeartbeatTestCache returns an isolated *ClientCache pre-populated from entries.
func newHeartbeatTestCache(entries map[string]*fake.MockAppsClient) *ClientCache {
	c := &ClientCache{clients: make(map[string]*cachedClientEntry)}
	for key, mock := range entries {
		c.clients[key] = &cachedClientEntry{
			client:    &Client{Apps: mock},
			createdAt: time.Now(),
			cacheKey:  key,
		}
	}
	return c
}

func TestHeartbeatOnce_PingsEachCachedApp(t *testing.T) {
	now := time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)
	pool := newQuotaPool(fixedNow(now))

	calls := map[string]int{}
	makeMock := func(key string) *fake.MockAppsClient {
		return &fake.MockAppsClient{
			MockListRepos: func(ctx context.Context, opts *github.ListOptions) (*github.ListRepositories, *github.Response, error) {
				calls[key]++
				return &github.ListRepositories{}, &github.Response{
					Response: &http.Response{StatusCode: 200},
					Rate:     github.Rate{Limit: 12500, Remaining: 12499, Reset: github.Timestamp{Time: now.Add(time.Hour)}},
				}, nil
			},
		}
	}
	cache := newHeartbeatTestCache(map[string]*fake.MockAppsClient{
		"app-A": makeMock("app-A"),
		"app-B": makeMock("app-B"),
		"app-C": makeMock("app-C"),
	})

	heartbeatOnce(context.Background(), cache, pool, nil)

	for _, key := range []string{"app-A", "app-B", "app-C"} {
		if calls[key] != 1 {
			t.Errorf("Apps.ListRepos for %s called %d times, want 1", key, calls[key])
		}
	}
}

func TestHeartbeatOnce_SkipsAppInCooldown(t *testing.T) {
	now := time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)
	pool := newQuotaPool(fixedNow(now))

	// Put app-cool into a future cooldown; heartbeatOnce must skip it.
	pool.recordResponse("app-cool", &github.Response{
		Response: &http.Response{StatusCode: http.StatusTooManyRequests},
		Rate:     github.Rate{Reset: github.Timestamp{Time: now.Add(5 * time.Minute)}},
	}, nil)

	hotCalls, coolCalls := 0, 0
	cache := newHeartbeatTestCache(map[string]*fake.MockAppsClient{
		"app-hot": {
			MockListRepos: func(ctx context.Context, opts *github.ListOptions) (*github.ListRepositories, *github.Response, error) {
				hotCalls++
				return &github.ListRepositories{}, &github.Response{Response: &http.Response{StatusCode: 200}}, nil
			},
		},
		"app-cool": {
			MockListRepos: func(ctx context.Context, opts *github.ListOptions) (*github.ListRepositories, *github.Response, error) {
				coolCalls++
				return nil, nil, nil
			},
		},
	})

	heartbeatOnce(context.Background(), cache, pool, nil)

	if hotCalls != 1 {
		t.Errorf("app-hot Apps.ListRepos called %d times, want 1 (not in cooldown)", hotCalls)
	}
	if coolCalls != 0 {
		t.Errorf("app-cool Apps.ListRepos called %d times, want 0 (in cooldown)", coolCalls)
	}
}

func TestHeartbeatOnce_RecordsPoolResponseOnSuccess(t *testing.T) {
	now := time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)
	pool := newQuotaPool(fixedNow(now))

	cache := newHeartbeatTestCache(map[string]*fake.MockAppsClient{
		"app-1": {
			MockListRepos: func(ctx context.Context, opts *github.ListOptions) (*github.ListRepositories, *github.Response, error) {
				return &github.ListRepositories{}, &github.Response{
					Response: &http.Response{StatusCode: 200},
					Rate:     github.Rate{Limit: 12500, Remaining: 12000, Reset: github.Timestamp{Time: now.Add(30 * time.Minute)}},
				}, nil
			},
		},
	})

	heartbeatOnce(context.Background(), cache, pool, nil)

	q := pool.snapshot("app-1")
	if q.Remaining != 12000 {
		t.Errorf("pool snapshot Remaining = %d, want 12000 (heartbeat response should be recorded)", q.Remaining)
	}
	if q.Limit != 12500 {
		t.Errorf("pool snapshot Limit = %d, want 12500", q.Limit)
	}
}

func TestHeartbeatOnce_RecordsPoolFailureSoFutureSkipsApply(t *testing.T) {
	now := time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)
	pool := newQuotaPool(fixedNow(now))

	cache := newHeartbeatTestCache(map[string]*fake.MockAppsClient{
		"app-broken": {
			MockListRepos: func(ctx context.Context, opts *github.ListOptions) (*github.ListRepositories, *github.Response, error) {
				return nil, nil, errors.New("token mint failed: 401")
			},
		},
	})

	heartbeatOnce(context.Background(), cache, pool, nil)

	q := pool.snapshot("app-broken")
	if q.ConsecutiveFailures == 0 {
		t.Errorf("ConsecutiveFailures = 0, want >0 (failure should be recorded)")
	}
	if q.CooldownUntil.IsZero() || !q.CooldownUntil.After(now) {
		t.Errorf("CooldownUntil = %v, want a future time", q.CooldownUntil)
	}
}
