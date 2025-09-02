/*
Copyright 2024 The Crossplane Authors.

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

package telemetry

import (
	"errors"
	"net/http"
	"time"

	"github.com/google/go-github/v62/github"
	"github.com/prometheus/client_golang/prometheus"
	ctrl "sigs.k8s.io/controller-runtime"
)

// RateLimitMetrics holds only the essential Prometheus metrics for GitHub rate limiting
type RateLimitMetrics struct {
	// Rate limit remaining gauge - most important metric
	rateLimitRemaining *prometheus.GaugeVec

	// Rate limit reset time gauge
	rateLimitResetTime *prometheus.GaugeVec

	// Rate limit limit gauge
	rateLimitLimit *prometheus.GaugeVec

	// Rate limit exceeded counter
	rateLimitExceededTotal *prometheus.CounterVec
}

// NewRateLimitMetrics creates and registers only essential Prometheus metrics for GitHub rate limiting
func NewRateLimitMetrics(mgr ctrl.Manager) *RateLimitMetrics {
	// Create only essential metrics
	rateLimitRemaining := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "github_rate_limit_remaining",
			Help: "Number of API requests remaining in the current rate limit window",
		},
		[]string{"organization"},
	)

	rateLimitResetTime := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "github_rate_limit_reset_time",
			Help: "Unix timestamp when the rate limit will reset",
		},
		[]string{"organization"},
	)

	rateLimitLimit := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "github_rate_limit_limit",
			Help: "Total number of API requests allowed in the current rate limit window",
		},
		[]string{"organization"},
	)

	rateLimitExceededTotal := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "github_rate_limit_exceeded_total",
			Help: "Total number of times GitHub rate limit was exceeded",
		},
		[]string{"organization"},
	)

	// Register metrics with the default Prometheus registry
	prometheus.MustRegister(rateLimitRemaining)
	prometheus.MustRegister(rateLimitResetTime)
	prometheus.MustRegister(rateLimitLimit)
	prometheus.MustRegister(rateLimitExceededTotal)

	metrics := &RateLimitMetrics{
		rateLimitRemaining:     rateLimitRemaining,
		rateLimitResetTime:     rateLimitResetTime,
		rateLimitLimit:         rateLimitLimit,
		rateLimitExceededTotal: rateLimitExceededTotal,
	}

	return metrics
}

// RecordRateLimitInfo records only essential rate limit information from GitHub API response
func (m *RateLimitMetrics) RecordRateLimitInfo(resp *github.Response, org string) {
	if resp == nil {
		return
	}

	// Record rate limit exceeded
	if resp.StatusCode == http.StatusTooManyRequests {
		m.rateLimitExceededTotal.WithLabelValues(org).Inc()
	}

	// Record rate limit headers if available
	if resp.Rate.Limit > 0 {
		m.rateLimitLimit.WithLabelValues(org).Set(float64(resp.Rate.Limit))
		m.rateLimitRemaining.WithLabelValues(org).Set(float64(resp.Rate.Remaining))
		m.rateLimitResetTime.WithLabelValues(org).Set(float64(resp.Rate.Reset.Unix()))
	}
}

// IsRateLimited checks if the error is due to rate limiting
func IsRateLimited(err error) bool {
	if err == nil {
		return false
	}

	var errResp *github.ErrorResponse
	if errors.As(err, &errResp) {
		return errResp.Response.StatusCode == http.StatusTooManyRequests
	}

	return false
}

// GetRateLimitInfo extracts rate limit information from GitHub response
func GetRateLimitInfo(resp *github.Response) (limit, remaining int, resetTime time.Time) {
	if resp == nil {
		return 0, 0, time.Time{}
	}

	return resp.Rate.Limit, resp.Rate.Remaining, resp.Rate.Reset.Time
}

// IsRateLimitExceeded checks if the response indicates rate limit exceeded
func IsRateLimitExceeded(resp *github.Response) bool {
	return resp != nil && resp.StatusCode == 429
}

// GetRateLimitUsagePercentage calculates the percentage of rate limit used
func GetRateLimitUsagePercentage(resp *github.Response) float64 {
	if resp == nil || resp.Rate.Limit == 0 {
		return 0
	}

	used := resp.Rate.Limit - resp.Rate.Remaining
	return float64(used) / float64(resp.Rate.Limit) * 100
}
