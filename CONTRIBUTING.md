# Contributing to Keyorix SDKs

Thanks for considering a contribution.

## Before you start

- **Security issues**: do not open a public issue or PR. See
  [SECURITY.md](SECURITY.md) for the private disclosure process.
- **License**: everything in this repository is Apache-2.0 (see
  [LICENSE](LICENSE)). Your contribution will be under the same license.

## Developer Certificate of Origin (DCO)

Every commit must be signed off, certifying you wrote it (or otherwise have
the right to submit it) under the
[Developer Certificate of Origin](https://developercertificate.org/):

```
git commit -s -m "your commit message"
```

This adds a `Signed-off-by: Your Name <you@example.com>` trailer to the
commit, matching your git author identity — nothing more. PRs with any
commit missing this trailer won't be merged. If you forgot:

```
git commit --amend -s --no-edit                              # last commit only
git rebase --exec 'git commit --amend --no-edit -s' <base>    # every commit since <base>
```

## Making a change

Each language subdirectory (`go/`, `node/`, `python/`, `java/`) has its own
README covering how to build and test that SDK. One logical change per
commit; open an issue first for anything beyond a small fix.
