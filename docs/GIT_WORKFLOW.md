# Git Workflow

## Branching Strategy

- `main` is the protected release-candidate and production-preparation branch.
- Use short-lived feature or hardening branches from `main`.
- Recommended branch naming:
  - `feature/<scope>`
  - `fix/<scope>`
  - `hardening/<scope>`
  - `docs/<scope>`
  - `hotfix/<scope>`

Examples:

- `hardening/trust-center`
- `fix/workbench-heading-sync`
- `docs/release-guidance`

## Commit Conventions

Use concise, imperative commit subjects. Recommended format:

```text
type(scope): summary
```

Examples:

- `fix(workbench): update HTMX page heading sync`
- `hardening(git): add production .gitignore and workflow docs`
- `docs(release): add repository guidance`

Recommended commit types:

- `feat`
- `fix`
- `hardening`
- `docs`
- `refactor`
- `test`
- `chore`

## Release Tags

Use annotated tags for release milestones:

```bash
git tag -a v1.0.0-rc1 -m "Release candidate 1"
```

Follow semantic versioning with release-candidate suffixes during stabilization:

- `v1.0.0-rc1`
- `v1.0.0-rc2`
- `v1.0.0`

## Hotfix Flow

1. Branch from the currently deployed tag or from `main` if that is the deployed state.
2. Name the branch `hotfix/<scope>`.
3. Make the minimal corrective change.
4. Re-run tests and smoke validation.
5. Merge back into `main`.
6. Create a new annotated tag, for example:

```bash
git tag -a v1.0.0-rc2 -m "Release candidate 2"
```

## Rollback Strategy

- Deploy from immutable tags, not floating branches.
- If a release candidate regresses, roll back to the previous known-good tag.
- Keep diagnostics bundles and deployment notes for each release candidate.
- Record rollback reason and remediation plan before the next candidate is cut.

## Remote Workflow

Typical first-time sequence after GitHub repository creation:

```bash
git remote add origin <github-repository-url>
git push -u origin main
git push origin v1.0.0-rc1
```

## Review Expectations

- Review `git status` before each commit.
- Confirm no runtime state, outputs, or secrets are staged.
- Prefer small, reviewable commits grouped by concern.
