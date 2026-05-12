/*
Copyright 2026 The Crossplane Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package telemetry

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/go-github/v62/github"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// Every rate-limit metric carries organization, app_id, and
// app_installation_id labels with the values supplied at record time.
func TestRecordRateLimitInfo_LabelsByOrgAppAndInstallation(t *testing.T) {
	m := newRateLimitMetrics()

	resetAt := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	m.RecordRateLimitInfo(&github.Response{
		Response: &http.Response{StatusCode: 200},
		Rate: github.Rate{
			Limit:     5000,
			Remaining: 4321,
			Reset:     github.Timestamp{Time: resetAt},
		},
	}, "acme", "12345", "67890")

	if got := testutil.ToFloat64(m.rateLimitRemaining.WithLabelValues("acme", "12345", "67890")); got != 4321 {
		t.Errorf("remaining = %v, want 4321", got)
	}
	if got := testutil.ToFloat64(m.rateLimitLimit.WithLabelValues("acme", "12345", "67890")); got != 5000 {
		t.Errorf("limit = %v, want 5000", got)
	}
	if got := testutil.ToFloat64(m.rateLimitResetTime.WithLabelValues("acme", "12345", "67890")); got != float64(resetAt.Unix()) {
		t.Errorf("reset = %v, want %v", got, float64(resetAt.Unix()))
	}
}

// Two installations of the same App (same app_id, different
// app_installation_id) produce distinct time series rather than
// overwriting each other.
func TestRecordRateLimitInfo_DistinctInstallationsAreSeparate(t *testing.T) {
	m := newRateLimitMetrics()

	m.RecordRateLimitInfo(&github.Response{
		Response: &http.Response{StatusCode: 200},
		Rate:     github.Rate{Limit: 5000, Remaining: 4000},
	}, "acme", "12345", "67890")

	m.RecordRateLimitInfo(&github.Response{
		Response: &http.Response{StatusCode: 200},
		Rate:     github.Rate{Limit: 5000, Remaining: 100},
	}, "acme", "12345", "67891")

	if got := testutil.ToFloat64(m.rateLimitRemaining.WithLabelValues("acme", "12345", "67890")); got != 4000 {
		t.Errorf("remaining{install=67890} = %v, want 4000", got)
	}
	if got := testutil.ToFloat64(m.rateLimitRemaining.WithLabelValues("acme", "12345", "67891")); got != 100 {
		t.Errorf("remaining{install=67891} = %v, want 100", got)
	}
}

// A 429 response increments rate_limit_exceeded_total under the supplied
// org, app_id, and app_installation_id labels.
func TestRecordRateLimitInfo_429IncrementsExceededCounter(t *testing.T) {
	m := newRateLimitMetrics()

	m.RecordRateLimitInfo(&github.Response{
		Response: &http.Response{StatusCode: http.StatusTooManyRequests},
	}, "acme", "12345", "67890")

	if got := testutil.ToFloat64(m.rateLimitExceededTotal.WithLabelValues("acme", "12345", "67890")); got != 1 {
		t.Errorf("exceeded_total = %v, want 1", got)
	}
}

// RecordPickerPick increments picker_picks_total under (org, app_id,
// installation_id, reason). Reason values distinguish picker decisions:
// highest_remaining (strict winner), random_tiebreak (N ≥ 2 tied),
// only_candidate (others in cooldown).
func TestRecordPickerPick_IncrementsCounter(t *testing.T) {
	m := newRateLimitMetrics()

	m.RecordPickerPick("acme", "12345", "67890", "highest_remaining")
	m.RecordPickerPick("acme", "12345", "67890", "highest_remaining")
	m.RecordPickerPick("acme", "12345", "67890", "random_tiebreak")

	if got := testutil.ToFloat64(m.picksTotal.WithLabelValues("acme", "12345", "67890", "highest_remaining")); got != 2 {
		t.Errorf("picks_total{reason=highest_remaining} = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.picksTotal.WithLabelValues("acme", "12345", "67890", "random_tiebreak")); got != 1 {
		t.Errorf("picks_total{reason=random_tiebreak} = %v, want 1", got)
	}
}

// RecordAPICall increments the api_calls_total counter for the given
// (org, app_id, installation_id, method) series. Counts every wrapped
// call regardless of outcome; operators sum across `method` for per-app
// traffic volume.
func TestRecordAPICall_IncrementsCounter(t *testing.T) {
	m := newRateLimitMetrics()

	m.RecordAPICall("acme", "12345", "67890", "Organizations.Get")
	m.RecordAPICall("acme", "12345", "67890", "Organizations.Get")
	m.RecordAPICall("acme", "12345", "67890", "Repositories.Edit")

	if got := testutil.ToFloat64(m.apiCallsTotal.WithLabelValues("acme", "12345", "67890", "Organizations.Get")); got != 2 {
		t.Errorf("api_calls_total{method=Organizations.Get} = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.apiCallsTotal.WithLabelValues("acme", "12345", "67890", "Repositories.Edit")); got != 1 {
		t.Errorf("api_calls_total{method=Repositories.Edit} = %v, want 1", got)
	}
}

// app_unhealthy_total is a separate counter from rate_limit_exceeded:
// every call to RecordAppUnhealthy increments the (org, app_id,
// installation_id) series by one.
func TestRecordAppUnhealthy_IncrementsCounter(t *testing.T) {
	m := newRateLimitMetrics()

	m.RecordAppUnhealthy("acme", "12345", "67890")
	m.RecordAppUnhealthy("acme", "12345", "67890")

	if got := testutil.ToFloat64(m.appUnhealthyTotal.WithLabelValues("acme", "12345", "67890")); got != 2 {
		t.Errorf("unhealthy_total = %v, want 2", got)
	}
}
