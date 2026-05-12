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
	"fmt"

	"github.com/pkg/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/crossplane/crossplane-runtime/pkg/resource"

	apisv1alpha1 "github.com/crossplane/provider-github/apis/v1alpha1"
	"github.com/crossplane/provider-github/internal/telemetry"
)

// pickCredsForPool returns the entry from resolvedCreds whose corresponding
// pool snapshot has the highest remaining quota and is not currently in
// cooldown, plus a reason label suitable for picker_picks_total. If every
// entry is in cooldown, the returned error wraps ErrAllAppsInCooldown
// (use errors.As to extract *CooldownError for the soonest retry hint).
func pickCredsForPool(resolvedCreds []string) (string, string, error) {
	if len(resolvedCreds) == 0 {
		return "", "", errors.New("no credentials available")
	}

	keys := make([]string, len(resolvedCreds))
	keyToCreds := make(map[string]string, len(resolvedCreds))
	for i, c := range resolvedCreds {
		k := GenerateCacheKey(c)
		keys[i] = k
		keyToCreds[k] = c
	}

	chosenKey, reason, err := globalPool.pick(keys)
	if err != nil {
		return "", "", err
	}
	return keyToCreds[chosenKey], reason, nil
}

// ResolveAndConnect resolves every credential entry on pc (Credentials and
// AdditionalCredentials), picks the one with the most available rate-limit
// quota, builds a cached GitHub client for it, and returns a wrapped
// RateLimitClient ready for use by a controller.
//
// On a fully-exhausted pool the returned error wraps ErrAllAppsInCooldown
// so callers can decide whether to requeue or surface the error.
func ResolveAndConnect(ctx context.Context, kube client.Client, pc *apisv1alpha1.ProviderConfig, metrics *telemetry.RateLimitMetrics, org string) (*RateLimitClient, error) {
	resolved, err := resolveAllCredentials(ctx, kube, pc)
	if err != nil {
		return nil, err
	}

	chosen, pickReason, err := pickCredsForPool(resolved)
	if err != nil {
		return nil, err
	}

	// Pull the IDs out first so we can record a failure with meaningful
	// labels even if NewCachedClient (below) rejects the credentials.
	// ExtractAppIDs only requires the three-field comma layout; it's
	// strictly more lenient than NewCachedClient.
	appID, installationID, err := ExtractAppIDs(chosen)
	if err != nil {
		return nil, err
	}
	cacheKey := GenerateCacheKey(chosen)

	// Record the pick before any further work — even if construction
	// fails downstream, the picker did select this credential.
	if metrics != nil {
		metrics.RecordPickerPick(org, appID, installationID, pickReason)
	}

	gh, err := NewCachedClient(chosen)
	if err != nil {
		// Treat construction failures (non-numeric IDs, malformed PEM,
		// etc.) the same way as token-mint failures: record on the pool
		// so the picker steers away, and bump the unhealthy counter so
		// the operator can see the broken credential in Grafana.
		globalPool.recordResponse(cacheKey, nil, err)
		if metrics != nil {
			metrics.RecordAppUnhealthy(org, appID, installationID)
		}
		return nil, err
	}
	return NewRateLimitClient(gh, metrics).WithRateLimitTracking(org, appID, installationID, cacheKey), nil
}

// resolveAllCredentials extracts every credential entry on pc (the primary
// Credentials field plus any AdditionalCredentials) into a slice of raw
// credential strings, in declaration order.
//
// Returns an error pointing at the exact offending entry when extraction
// fails or when the extractor returns empty bytes (typically a missing
// Secret key or an unpopulated value, neither of which the extractor
// surfaces as an error on its own).
func resolveAllCredentials(ctx context.Context, kube client.Client, pc *apisv1alpha1.ProviderConfig) ([]string, error) {
	all := make([]apisv1alpha1.ProviderCredentials, 0, 1+len(pc.Spec.AdditionalCredentials))
	all = append(all, pc.Spec.Credentials)
	all = append(all, pc.Spec.AdditionalCredentials...)

	resolved := make([]string, 0, len(all))
	for i, cd := range all {
		data, err := resource.CommonCredentialExtractor(ctx, cd.Source, kube, cd.CommonCredentialSelectors)
		if err != nil {
			return nil, errors.Wrapf(err, "cannot get credentials at index %d", i)
		}
		if len(data) == 0 {
			return nil, errors.New(describeEmptyCredentials(i, cd))
		}
		resolved = append(resolved, string(data))
	}
	return resolved, nil
}

// describeEmptyCredentials builds an operator-friendly error message for a
// credential entry whose extraction returned empty bytes. The most useful
// thing to point at is the underlying reference (Secret namespace/name/key,
// env var name, filesystem path) — that's what the operator needs to fix.
func describeEmptyCredentials(index int, cd apisv1alpha1.ProviderCredentials) string {
	switch {
	case cd.SecretRef != nil:
		return fmt.Sprintf("credentials at index %d: secret %s/%s key %q is empty or missing", index, cd.SecretRef.Namespace, cd.SecretRef.Name, cd.SecretRef.Key)
	case cd.Env != nil:
		return fmt.Sprintf("credentials at index %d: env var %q is empty or unset", index, cd.Env.Name)
	case cd.Fs != nil:
		return fmt.Sprintf("credentials at index %d: file %q is empty or missing", index, cd.Fs.Path)
	default:
		return fmt.Sprintf("credentials at index %d: extracted empty bytes (source=%s)", index, cd.Source)
	}
}
