# Release notes

One file per release, named after the tag (`v1.0.0.md`). The release workflow uses it as the GitHub release body; without it, notes are generated from the pull requests.

## How to release / Como publicar

1. Write `docs/releases/vX.Y.Z.md` (EN and PT-PT) and bump `VERSION` in both installers, in a pull request.
2. After it is merged: `git tag -a vX.Y.Z -m vX.Y.Z origin/main && git push origin vX.Y.Z`
3. The workflow builds, scans (govulncheck gate), signs provenance, pushes the images, creates a draft release with every asset and publishes it. Releases are immutable once published.

Do not publish releases from the GitHub UI: a release published before its assets are attached cannot be completed.
