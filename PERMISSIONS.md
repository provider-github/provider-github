# Required GitHub App permissions

`provider-github` authenticates as a [GitHub App](https://docs.github.com/en/apps/creating-github-apps)
installed on the organization it manages. The App must be granted the
following permissions:

## Repository permissions

| Permission     | Access         | Why                                                                      |
| -------------- | -------------- | ------------------------------------------------------------------------ |
| Metadata       | Read           | Mandatory for every GitHub App; used by every controller for repo lookups |
| Contents       | Read           | Listing repository branches                                              |
| Administration | Read and write | Repository create/delete, settings, topics, collaborators, team access, branch protection rules, rulesets |
| Webhooks       | Read and write | Repository webhooks (`Repository.spec.forProvider.webhooks`)             |

## Organization permissions

| Permission           | Access         | Why                                                          |
| -------------------- | -------------- | ------------------------------------------------------------ |
| Administration       | Read and write | Organization profile/description, Actions enabled-repos selection |
| Members              | Read and write | `Membership` CR, `Team` CR (team CRUD + team membership)     |
| Actions variables    | Read and write | `OrganizationVariable` CR                                    |
| Secrets              | Read and write | `secrets.actionsSecrets` on the `Organization` CR (repo-access selection) |
| Dependabot secrets   | Read and write | `secrets.dependabotSecrets` on the `Organization` CR (repo-access selection) |

> **Note** — the provider does not create or update the secret values themselves;
> it only manages which repositories are granted access to existing
> organization-level secrets. The secret values are expected to be set out-of-band.

## Per-resource breakdown

If you run a least-privilege setup with multiple Apps, the table below maps
each managed resource to the permissions its controller actually exercises.
For pooled multi-App configurations (`ProviderConfig.spec.additionalCredentials`)
the union of all listed permissions must be present on every App, since the
provider picks an App per reconcile based on rate-limit headroom.

| Managed resource       | Repository permissions                                | Organization permissions                                       |
| ---------------------- | ----------------------------------------------------- | -------------------------------------------------------------- |
| `Organization`         | Metadata (R)                                          | Administration (R/W), Secrets (R/W), Dependabot secrets (R/W)  |
| `OrganizationVariable` | Metadata (R)                                          | Actions variables (R/W)                                        |
| `Repository`           | Metadata (R), Contents (R), Administration (R/W), Webhooks (R/W) | Members (R) — for team-to-repo associations          |
| `Team`                 | Administration (R/W) — for team-to-repo associations  | Members (R/W)                                                  |
| `Membership`           | —                                                     | Members (R/W)                                                  |

## Repository access scope

When installing the App on the organization, grant it access to **All
repositories** (or to the explicit subset you intend to manage). The
provider does not request the App-installation token to be narrowed at
runtime; it uses the installation token as issued.
