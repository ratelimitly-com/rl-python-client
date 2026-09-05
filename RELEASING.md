# Releasing the Python client

The repository publishes only the `ratelimitly` Python client. It does not
build or publish a RateLimitly server package.

## Release artifacts

The `release` workflow builds a source distribution and universal wheel,
proves that two independent builds are byte-identical, tests both artifacts,
attests them, and publishes them as an atomic GitHub release.

The separate `publish-pypi` workflow never rebuilds a distribution. Given a
numeric version, it downloads that version's existing GitHub release, rejects
missing or unexpected files, verifies `SHA256SUMS` and package metadata, and
uploads those exact bytes to PyPI.

## Authentication and setup

PyPI publishing uses an API token stored as a GitHub Actions secret:

- Secret name: `PYPI_API_TOKEN` (or `PYPI_TOKEN`)
- Permission: Scoped API token with upload permissions for the `ratelimitly` project on PyPI

## Publish an existing release

1. Confirm that `vX.Y.Z` is a complete, public GitHub release and that its tag
   targets the intended commit.
2. In GitHub Actions, run `publish-pypi` from `main` with version `X.Y.Z`
   (without the `v` prefix).
3. Verify the workflow succeeds and compare the PyPI wheel and sdist SHA-256
   digests with the GitHub release's `SHA256SUMS`.
4. Install the exact version in a clean virtual environment and verify that
   `import ratelimitly` reports the released version.

PyPI versions are immutable. If any verification fails, fix the release process
and publish a new version; never replace an existing PyPI file.
