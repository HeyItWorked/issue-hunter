# Issue Hunter

Finds **actually unclaimed** open source "good first issue" candidates using GitHub's GraphQL API.

Unlike every aggregator out there (goodfirstissue.dev, up-for-grabs.net, etc.), this tool doesn't just filter by label. It checks:

- **Assignees** — is anyone assigned?
- **Linked PRs** — does any open/draft PR reference this issue?
- **Linked branches** — has someone started a branch for it?
- **Comment signals** — did anyone say "I'll take this" or "working on it"?
- **Staleness** — has the issue gone cold (no updates in 90 days)?
- **Definition-of-done clarity** — does the issue body actually explain what "done" means?
- **Likely expertise required** — is the issue mislabeled as approachable?
- **Repo setup support** — does the repo expose devcontainer / task-runner / onboarding signals?
- **CLA / DCO friction** — do recent PRs suggest a legal gate for first contributions?
- **Contributor fit** — optional profile-aware downgrade for language/domain mismatch

## Usage

```bash
GITHUB_TOKEN=$(gh auth token) python issue_hunter.py
```

Results land in `results/unclaimed.json` and `index.html`.

## Automated

Runs every 6 hours via GitHub Actions. Results deployed to GitHub Pages.

## Config

Edit `config.yaml` to add/remove target repos, change labels, adjust the staleness window, or provide an optional contributor profile.

Example profile:

```yaml
contributor_profile:
  languages: ["Rust", "Go"]
  domains: ["cli", "docs", "tooling"]
  avoid_domains: ["security", "compiler"]
  max_specialization: "moderate"
```

When a profile is present, Issue Hunter still shows all surviving issues, but it downgrades confidence and adds flags like `profile_stretch` or `profile_mismatch`.
