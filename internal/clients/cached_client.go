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

package clients

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/google/go-github/v62/github"
)

// CachedClient represents a cached GitHub client with token reuse
type CachedClient struct {
	*Client
}

// ClientCache manages cached GitHub clients to reduce token requests
type ClientCache struct {
	mu      sync.RWMutex
	clients map[string]*cachedClientEntry
}

type cachedClientEntry struct {
	client    *Client
	createdAt time.Time
	cacheKey  string
}

var (
	globalClientCache = &ClientCache{
		clients: make(map[string]*cachedClientEntry),
	}
	// Cache clients for 50 minutes (GitHub App tokens expire after 1 hour)
	clientCacheTimeout = 50 * time.Minute
)

// generateCacheKey creates a consistent cache key from credentials
func generateCacheKey(creds string) string {
	hash := sha256.Sum256([]byte(creds))
	return fmt.Sprintf("%x", hash[:8]) // Use first 8 bytes of hash
}

// NewCachedClient creates a new cached GitHub client that reuses tokens
func NewCachedClient(creds string) (*Client, error) {
	cacheKey := generateCacheKey(creds)

	globalClientCache.mu.Lock()
	defer globalClientCache.mu.Unlock()

	// Check if we have a valid cached client
	if entry, exists := globalClientCache.clients[cacheKey]; exists {
		// Check if cache entry is still valid
		if time.Since(entry.createdAt) < clientCacheTimeout {
			return entry.client, nil
		}
		// Remove expired entry
		delete(globalClientCache.clients, cacheKey)
	}

	// Create new client using existing logic
	client, err := createNewClient(creds)
	if err != nil {
		return nil, err
	}

	// Cache the new client
	globalClientCache.clients[cacheKey] = &cachedClientEntry{
		client:    client,
		createdAt: time.Now(),
		cacheKey:  cacheKey,
	}

	return client, nil
}

// createNewClient contains the original client creation logic
func createNewClient(creds string) (*Client, error) {
	credss := strings.Split(creds, ",")
	if len(credss) != 3 {
		return nil, fmt.Errorf("invalid format for credentials")
	}

	appId, err := strconv.Atoi(credss[0])
	if err != nil {
		return nil, err
	}

	installationId, err := strconv.Atoi(credss[1])
	if err != nil {
		return nil, err
	}

	itr, err := ghinstallation.New(http.DefaultTransport, int64(appId), int64(installationId), []byte(credss[2]))
	if err != nil {
		return nil, err
	}

	ghclient := github.NewClient(&http.Client{Transport: itr})

	return &Client{
		Actions:       ghclient.Actions,
		Dependabot:    ghclient.Dependabot,
		Organizations: ghclient.Organizations,
		Users:         ghclient.Users,
		Teams:         ghclient.Teams,
		Repositories:  ghclient.Repositories,
	}, nil
}

// CleanupExpiredClients removes expired clients from cache (optional background cleanup)
func CleanupExpiredClients() {
	globalClientCache.mu.Lock()
	defer globalClientCache.mu.Unlock()

	now := time.Now()
	for key, entry := range globalClientCache.clients {
		if now.Sub(entry.createdAt) >= clientCacheTimeout {
			delete(globalClientCache.clients, key)
		}
	}
}
