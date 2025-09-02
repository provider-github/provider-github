# GitHub API Rate Limit Tracking

This document describes the simplified rate limit tracking implementation for the GitHub Crossplane provider.

## Overview

The rate limit tracking system provides essential monitoring of GitHub API rate limits, focusing only on the most important metrics needed to track remaining API requests and detect rate limit violations.

## Metrics

The following Prometheus metrics are available:

### Rate Limiting Metrics

- `github_rate_limit_remaining` (Gauge)
  - Labels: `organization`
  - Description: Number of API requests remaining in the current rate limit window

- `github_rate_limit_reset_time` (Gauge)
  - Labels: `organization`
  - Description: Unix timestamp when the rate limit will reset

- `github_rate_limit_limit` (Gauge)
  - Labels: `organization`
  - Description: Total number of API requests allowed in the current rate limit window

- `github_rate_limit_exceeded_total` (Counter)
  - Labels: `organization`
  - Description: Total number of times GitHub rate limit was exceeded

## Implementation

### Rate Limit Package (`internal/telemetry/rate_limit.go`)

- **RateLimitMetrics**: Core metrics structure with only essential Prometheus metrics
- **NewRateLimitMetrics()**: Creates and registers rate limit metrics
- **RecordRateLimitInfo()**: Records rate limit information from GitHub responses
- **IsRateLimited()**: Checks if an error is due to rate limiting
- **GetRateLimitInfo()**: Extracts rate limit information from responses
- **IsRateLimitExceeded()**: Checks if response indicates rate limit exceeded
- **GetRateLimitUsagePercentage()**: Calculates percentage of rate limit used

### Rate Limit Client (`internal/clients/rate_limit_client.go`)

- **RateLimitClient**: Wraps the standard GitHub client with rate limit tracking
- **NewRateLimitClient()**: Creates a new rate limit tracking client
- **WithRateLimitTracking()**: Returns a client configured for a specific organization

All GitHub API calls automatically record rate limit information from response headers.

## Usage

The rate limit tracking is automatically enabled for all GitHub API calls. The metrics are exposed on the `/metrics` endpoint and can be scraped by Prometheus.

### Example Prometheus Queries

```promql
# Current remaining requests for an organization
github_rate_limit_remaining{organization="my-org"}

# Rate limit exceeded events
rate(github_rate_limit_exceeded_total[5m])

# Rate limit usage percentage
(1 - github_rate_limit_remaining{organization="my-org"} / github_rate_limit_limit{organization="my-org"}) * 100
```

### Example Alert Rules

```yaml
groups:
- name: github-rate-limits
  rules:
  - alert: GitHubRateLimitLow
    expr: github_rate_limit_remaining{organization="my-org"} < 100
    for: 1m
    labels:
      severity: warning
    annotations:
      summary: "GitHub API rate limit is low"
      description: "Only {{ $value }} requests remaining for organization {{ $labels.organization }}"

  - alert: GitHubRateLimitExceeded
    expr: rate(github_rate_limit_exceeded_total[5m]) > 0
    for: 0m
    labels:
      severity: critical
    annotations:
      summary: "GitHub API rate limit exceeded"
      description: "Rate limit exceeded for organization {{ $labels.organization }}"
```

## Benefits

1. **Simple and Focused**: Only tracks essential rate limit information
2. **Automatic Monitoring**: All GitHub API calls are automatically monitored
3. **Rate Limit Detection**: Specific detection and tracking of rate limiting events
4. **Alerting**: Essential alert rules for operational monitoring
5. **Minimal Overhead**: Reduced complexity and resource usage compared to full telemetry

## Files

### Core Files
- `internal/telemetry/rate_limit.go` - Rate limit metrics and utilities
- `internal/clients/rate_limit_client.go` - Rate limit tracking client wrapper

### Integration
- All controllers updated to use `RateLimitClient` instead of `TelemetryClient`
- Main application initializes rate limit metrics
- Metrics exposed on `/metrics` endpoint
