# provider-github

`provider-github` is a [Crossplane](https://crossplane.io/) Provider
that is meant to be used to manage github organizations.

The project is in a prototyping phase but it's already functional and
implements the following resources with partial functionality:

* **Organization** — manages an existing organization (creation and deletion are not supported)
  * description
  * Actions enabled repositories
  * Actions secrets — repository access (secret values are set out-of-band)
  * Dependabot secrets — repository access (secret values are set out-of-band)
* **OrganizationVariable** — Actions variables at the organization level
  * value
  * visibility (`all`, `private`, `selected`)
  * selected repositories
* **Repository**
  * description, visibility (private/public), topics, template flag
  * creation from a template repository or as a fork
  * user (collaborator) permissions
  * team permissions
  * webhooks
  * branch protection rules (including required status checks, required reviews, restrictions, signed commits)
  * repository rulesets
  * archive-on-delete safeguard
* **Team**
  * description
  * visibility (`secret`, `closed`)
  * members
  * parent team
* **Membership** — organization membership
  * role

## GitHub App permissions

See [PERMISSIONS.md](./PERMISSIONS.md) for the GitHub App permissions
the provider requires, including a per-resource breakdown for
least-privilege setups.

## Operational considerations

### `--reconcile-timeout`

The provider takes a `--reconcile-timeout` flag that bounds the time any
single managed-resource reconcile (Observe + Create/Update/Delete) is
allowed to run. The runtime cancels the reconcile's context when the
deadline is reached.

The `Organization` CR's `spec.forProvider.actions.enabledRepos` field
lists the repositories that are allowed to run GitHub Actions at the
organization level (this maps to GitHub's `selected_repository_ids`
list under `Actions › General › Allow select repositories` in the org
settings, and to the `actions/permissions/repositories` REST API).

The field is **tri-state** — omitting it leaves the org's enabled list
unmanaged, setting it to `[]` explicitly wipes the list (disabling
Actions for every repo in the org), and a non-empty list reconciles
the list to exactly those repositories. See the field's CRD docstring
(`kubectl explain organization.spec.forProvider.actions.enabledRepos`)
for the full contract.

The two timeout-sensitive scenarios below both involve reconciling
that list.

**Default: `1m`.** Suitable for steady-state reconciliation and small
spec changes. The default is **not** enough for two operational
scenarios:

1. **Cold bootstrap of an `Organization` CR with a large Actions
   enabled-repos list.** On first reconcile the provider issues one
   sequential `Repositories.Get` per repo in `actions.enabledRepos`
   that is not already enabled in GitHub, to resolve names to numeric
   IDs. At ~0.5s per call through the rate-limit-aware client this is
   roughly `N × 0.5s`. An org bootstrapping with 200 enabled repos
   takes ~100s — past the 60s budget — so the reconcile will time out
   and retry on the next cycle. The system is **self-healing** across
   cycles (each retry resolves a smaller remaining diff) but doesn't
   converge in one shot.

2. **Bulk spec edits to the Actions enabled-repos list.** Adding or
   replacing tens of repos in an existing `Organization`'s
   `actions.enabledRepos` triggers the same per-new-repo
   `Repositories.Get` burst. Removals do not — repo IDs for
   already-enabled repos come back free from the paginated
   `ListEnabledReposInOrg` walk that the controller does anyway.

Steady-state reconciles (no spec drift, or drift confined to
description/secrets) cost a handful of API calls regardless of org
size and fit comfortably in the default.

**Raising it.** Pass `--reconcile-timeout=3m` (or whatever fits your
worst-case bootstrap) on the provider deployment. A 3-minute budget
covers ~300 sequential ID resolutions plus the usual overhead. Pick the
smallest value that contains your operational worst case — larger
timeouts let stuck reconciles hold a worker for longer before the
runtime cancels them, which reduces overall throughput across all
controllers.

**Detecting it.** A reconcile that hits the deadline surfaces as
`Synced=False` with `reason=ReconcileError, message="... context
deadline exceeded"` on the CR's status, and a `Warning` event of type
`CannotUpdateExternalResource`. If you see this on an `Organization`
right after a large change to its Actions enabled-repos list, the
timeout is the most likely cause; let the controller retry a couple
of cycles before raising the flag.


## Developing

To add a new resource follow these steps:
1. Run `make submodules` to initialize the "build" Make submodule we use for CI/CD.
2. Add your new type by running the following command:
```shell
  export group=sample # lower case e.g. core, cache, database, storage, etc.
  export type=MyType # Camel casee.g. Bucket, Database, CacheCluster, etc.
  make provider.addtype provider=GitHub group=${group} kind=${type}
```
3. Call the `Setup` function of your controller here `internal/controller/github.go`
4. Run `make run` to run locally
5. Run `make reviewable` to run code generation, linters, and tests.
6. Run `make build` to build the provider.

Refer to Crossplane's [CONTRIBUTING.md] file for more information on how the
Crossplane community prefers to work. The [Provider Development][provider-dev]
guide may also be of use.

[CONTRIBUTING.md]: https://github.com/crossplane/crossplane/blob/master/CONTRIBUTING.md
[provider-dev]: https://github.com/crossplane/crossplane/blob/master/contributing/guide-provider-development.md
