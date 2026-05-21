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
	"time"

	"github.com/google/go-github/v62/github"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/crossplane/provider-github/internal/telemetry"
)

// HeartbeatApps periodically pings each GitHub App installation to keep it on the high rate-limit tier.
func HeartbeatApps(ctx context.Context, metrics *telemetry.RateLimitMetrics, interval time.Duration) {
	heartbeatLoop(ctx, globalClientCache, globalPool, metrics, interval)
}

func heartbeatLoop(ctx context.Context, cache *ClientCache, pool *quotaPool, metrics *telemetry.RateLimitMetrics, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	heartbeatOnce(ctx, cache, pool, metrics)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			heartbeatOnce(ctx, cache, pool, metrics)
		}
	}
}

func heartbeatOnce(ctx context.Context, cache *ClientCache, pool *quotaPool, metrics *telemetry.RateLimitMetrics) {
	log := ctrl.LoggerFrom(ctx).WithName("app-heartbeat")
	now := pool.now()

	for _, key := range cache.SnapshotCacheKeys() {
		if snap := pool.snapshot(key); !snap.CooldownUntil.IsZero() && now.Before(snap.CooldownUntil) {
			continue
		}
		entry, ok := cache.LookupEntry(key)
		if !ok {
			continue
		}
		_, resp, err := entry.client.Apps.ListRepos(ctx, &github.ListOptions{PerPage: 1})
		pool.recordResponse(key, resp, err)
		if metrics != nil {
			metrics.RecordAppHeartbeat(entry.installationOrg, entry.appID, entry.installationID)
			metrics.RecordRateLimitInfo(resp, entry.installationOrg, entry.appID, entry.installationID)
			if err != nil {
				metrics.RecordAppHeartbeatError(entry.installationOrg, entry.appID, entry.installationID)
			}
		}
		if err != nil {
			log.V(1).Info("heartbeat ping failed", "cacheKey", key, "err", err.Error())
		}
	}
}
