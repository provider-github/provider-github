# provider-github

`provider-github` is a [Crossplane](https://crossplane.io/) Provider
that is meant to be used to manage github organizations.

The project is in a prototyping phase but it's already functional and
implements follwing objects with partial functionality:

* Organization
  * description
  * creation and deleteion not supported
* Team
  * visibility
  * description
  * members
  * parent team
* Repository
  * user permissions  
  * team permissions
* Membership
  * role


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
