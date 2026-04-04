#!/usr/bin/env python3
"""Issue Hunter — find actually-unclaimed good first issues via GitHub GraphQL."""

import json
import os
import re
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

import requests
import yaml

GRAPHQL_URL = "https://api.github.com/graphql"

# Pass 2 query: fetch issue body + all comments for a single issue
PASS2_QUERY = """
query($owner: String!, $name: String!, $number: Int!, $after: String) {
  repository(owner: $owner, name: $name) {
    issue(number: $number) {
      body
      author { login }
      comments(first: 100, after: $after) {
        pageInfo { hasNextPage endCursor }
        nodes {
          body
          author { login }
          createdAt
        }
      }
    }
  }
}
"""

# Labels that mean "not ready for implementation" or "harder than labeled"
LABEL_BLOCKLIST = {
    "discussion", "needs-design", "needs-triage", "needs-discussion",
    "not-as-easy-as-it-looks", "needs-investigation", "needs-rfc",
    "wontfix", "won't fix", "invalid", "duplicate", "stale",
    "blocked", "on-hold", "on hold", "waiting-for-upstream",
}
LABEL_BLOCKLIST_LOWER = {label.lower() for label in LABEL_BLOCKLIST}

# --- Claim detection ---

# Hard claim: someone is explicitly taking the issue
CLAIM_PATTERNS = [
    r"i.?ll\s+take\s+this",
    r"i.?m\s+(working|gonna\s+work)\s+on",
    r"i.?m\s+interested",
    r"can\s+i\s+(work|take)",
    r"assigned\s+to\s+me",
    r"i.?ll\s+(submit|open)\s+a\s+pr",
    r"working\s+on\s+(this|it)",
    r"let\s+me\s+take\s+(this|it)",
    r"i.?d\s+like\s+to\s+(work|take|submit|make|open)",
    r"claiming\s+this",
    r"i\s+want\s+to\s+(work|take)",
    r"i.?ll\s+work\s+on\s+(this|it)",
    r"i.?ll\s+send\s+a\s+(pr|patch|fix)",
    r"i.?ll\s+fix\s+(this|it)",
    r"i.?ll\s+make\s+a\s+pr",
    r"i\s+can\s+fix\s+(this|it)",
    r"i\s+can\s+work\s+on\s+(this|it)",
    r"i.?ll\s+give\s+(this|it)\s+a\s+(shot|try|go)",
    r"^\s*take\s*$",  # bare "take" (DataFusion convention)
]
CLAIM_RE = re.compile("|".join(CLAIM_PATTERNS), re.IGNORECASE | re.MULTILINE)

# Unclaim: someone gave it back
UNCLAIM_PATTERNS = [
    r"^\s*untake\s*$",
    r"i.?m\s+no\s+longer\s+(working|interested)",
    r"i\s+won.?t\s+be\s+(able|working)",
    r"feel\s+free\s+to\s+pick\s+(this|it)\s+up",
    r"up\s+for\s+grabs",
    r"anyone\s+else\s+.*\s+(take|pick|grab)",
    r"i.?m\s+dropping\s+this",
    r"not\s+going\s+to\s+work\s+on\s+this",
]
UNCLAIM_RE = re.compile("|".join(UNCLAIM_PATTERNS), re.IGNORECASE | re.MULTILINE)

# Investigative language — softer signal, someone poking at it
INVESTIGATING_PATTERNS = [
    r"i\s+(can\s+)?reproduc(e|ed)\s+(this|it)",
    r"i.?m\s+(looking|digging)\s+into",
    r"i.?ve\s+been\s+(investigating|looking)",
    r"investigating\s+(this|it|now)",
    r"started\s+(debugging|looking|investigating)",
    r"i\s+found\s+(the|a)\s+(root\s+cause|bug|issue|problem)",
    r"i\s+traced\s+(this|it)\s+(to|back)",
]
INVESTIGATING_RE = re.compile("|".join(INVESTIGATING_PATTERNS), re.IGNORECASE)

# --- Semantic triage ---

STRUCTURED_BODY_RE = re.compile(r"(^|\n)\s*(?:[-*]|\d+\.)\s+\S", re.MULTILINE)
SPECIFIC_ARTIFACT_RE = re.compile(r"`[^`]+`|--[a-z0-9-]+|[A-Za-z0-9_./-]+\.[A-Za-z0-9_]+")
CONCRETE_OUTCOME_RE = re.compile(
    r"\b(steps to reproduce|expected(?: behavior| result)?|actual(?: behavior| result)?|"
    r"acceptance criteria|definition of done|support|rename|add|remove|update|implement|fix)\b",
    re.IGNORECASE,
)
OPEN_ENDED_RE = re.compile(
    r"\b(investigate|explore|research|figure out|look into|understand why|root cause)\b",
    re.IGNORECASE,
)
VAGUE_LANGUAGE_RE = re.compile(
    r"\b(something|somehow|misc(?:ellaneous)?|make it better|needs work|doesn.?t work)\b",
    re.IGNORECASE,
)

DOMAIN_KEYWORDS = {
    "cli": {"cli", "command", "command line", "flag", "shell", "terminal"},
    "compiler": {"compiler", "parser", "lexer", "ast", "type checker", "typechecking", "type inference"},
    "database": {"database", "sql", "query engine", "planner", "optimizer", "postgres", "index"},
    "docs": {"documentation", "docs", "readme", "man page", "reference", "guide"},
    "frontend": {"ui", "ux", "theme", "layout", "css", "html", "webview", "frontend"},
    "language-server": {"lsp", "language server", "completion", "hover", "rename", "diagnostic"},
    "security": {"security", "auth", "authentication", "authorization", "crypto", "tls", "secret"},
    "tooling": {"build", "packaging", "formatter", "lint", "tooling", "benchmark", "config"},
}

APPROACHABLE_KEYWORDS = {
    "documentation", "docs", "readme", "typo", "copy", "example", "examples",
    "test", "tests", "error message", "man page", "theme", "layout",
}

MODERATE_KEYWORDS = {
    "cli", "config", "api", "validation", "serialization", "integration",
    "migration", "refactor", "language server", "completion", "hover",
}

SPECIALIZED_KEYWORDS = {
    "compiler", "parser", "lexer", "type checker", "typechecking", "type inference",
    "borrow checker", "unsafe", "lifetime", "wasm", "webassembly", "query engine",
    "planner", "optimizer", "benchmark", "concurrency", "scheduler", "ffi",
    "runtime", "protocol", "driver", "security", "authentication", "crypto",
    "postgres", "database engine", "tracking issue",
}

SPECIALIZATION_ORDER = {
    "approachable": 0,
    "moderate": 1,
    "specialized": 2,
}

CLA_KEYWORD_RE = re.compile(
    r"\b(cla|contributor license agreement|cla assistant|easycla|dco|signed-off-by|sign[- ]off)\b",
    re.IGNORECASE,
)
CLA_AUTHOR_RE = re.compile(r"(cla|dco|easycla)", re.IGNORECASE)

REPO_FILE_ALIASES = {
    "devcontainerDir": "HEAD:.devcontainer",
    "devcontainerFile": "HEAD:.devcontainer/devcontainer.json",
    "dockerfile": "HEAD:Dockerfile",
    "dockerCompose": "HEAD:docker-compose.yml",
    "dockerComposeAlt": "HEAD:docker-compose.yaml",
    "makefile": "HEAD:Makefile",
    "makefileLower": "HEAD:makefile",
    "justfile": "HEAD:justfile",
    "justfileAlt": "HEAD:Justfile",
    "cargoToml": "HEAD:Cargo.toml",
    "packageJson": "HEAD:package.json",
    "pyprojectToml": "HEAD:pyproject.toml",
    "goMod": "HEAD:go.mod",
    "contributing": "HEAD:CONTRIBUTING.md",
    "githubContributing": "HEAD:.github/CONTRIBUTING.md",
    "contributingLower": "HEAD:contributing.md",
    "githubContributingLower": "HEAD:.github/contributing.md",
}


def load_config(path: str = "config.yaml") -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def graphql(query: str, variables: dict | None = None) -> dict:
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("Error: GITHUB_TOKEN not set", file=sys.stderr)
        sys.exit(1)
    headers = {"Authorization": f"bearer {token}"}
    payload = {"query": query}
    if variables:
        payload["variables"] = variables
    resp = requests.post(GRAPHQL_URL, json=payload, headers=headers)
    resp.raise_for_status()
    data = resp.json()
    if "errors" in data:
        print(f"GraphQL errors: {json.dumps(data['errors'], indent=2)}", file=sys.stderr)
    return data.get("data", {})


def build_pass1_query(repos: list[str], labels: list[str], cursors: dict[str, str | None]) -> str:
    """Build a batched pass-1 query for multiple repos using aliases."""
    label_list = json.dumps(labels)
    aliases = []
    for i, repo in enumerate(repos):
        owner, name = repo.split("/")
        cursor = cursors.get(repo)
        cursor_arg = f', after: "{cursor}"' if cursor else ""
        aliases.append(f'''
  repo_{i}: repository(owner: "{owner}", name: "{name}") {{
    nameWithOwner
    stargazerCount
    primaryLanguage {{ name }}
    issues(
      first: 50
      states: OPEN
      labels: {label_list}
      orderBy: {{field: UPDATED_AT, direction: DESC}}
      {cursor_arg}
    ) {{
      pageInfo {{ hasNextPage endCursor }}
      nodes {{
        number
        title
        url
        body
        createdAt
        updatedAt
        author {{ login }}
        labels(first: 10) {{ nodes {{ name }} }}
        assignees(first: 1) {{ totalCount }}
        comments {{ totalCount }}
        closedByPullRequestsReferences(includeClosedPrs: true, first: 5) {{
          nodes {{
            state
            url
            isDraft
          }}
        }}
        linkedBranches(first: 5) {{
          nodes {{
            ref {{ name }}
          }}
        }}
      }}
    }}
  }}''')
    return "query HuntPass1 {" + "\n".join(aliases) + "\n}"


# --- Pass 1 filters ---

def has_assignee(issue: dict) -> bool:
    return issue["assignees"]["totalCount"] > 0


def has_linked_pr(issue: dict) -> bool:
    for pr in issue["closedByPullRequestsReferences"]["nodes"]:
        if pr["state"] in ("OPEN", "MERGED") or pr.get("isDraft"):
            return True
    return False


def has_linked_branch(issue: dict) -> bool:
    return len(issue["linkedBranches"]["nodes"]) > 0


def has_blocklist_label(issue: dict) -> bool:
    for label in issue["labels"]["nodes"]:
        if label["name"].lower() in LABEL_BLOCKLIST_LOWER:
            return True
    return False


def is_stale(issue: dict, staleness_days: int) -> bool:
    updated = datetime.fromisoformat(issue["updatedAt"].replace("Z", "+00:00"))
    cutoff = datetime.now(timezone.utc) - timedelta(days=staleness_days)
    return updated < cutoff


def body_has_claim_signal(issue: dict) -> bool:
    """Check the issue body for claim signals from the OP."""
    body = issue.get("body") or ""
    return bool(CLAIM_RE.search(body))


def pass1_filter(issue: dict, staleness_days: int) -> str | None:
    """Return None if issue survives, or a reason string if filtered."""
    if has_assignee(issue):
        return "assigned"
    if has_linked_pr(issue):
        return "linked_pr"
    if has_linked_branch(issue):
        return "linked_branch"
    if has_blocklist_label(issue):
        return "blocklist_label"
    if is_stale(issue, staleness_days):
        return "stale"
    if body_has_claim_signal(issue):
        return "body_claim"
    return None


# --- Pass 2: deep comment scan ---

def fetch_all_comments(owner: str, name: str, number: int) -> list[dict]:
    """Paginate through all comments on an issue."""
    comments = []
    cursor = None
    while True:
        variables = {"owner": owner, "name": name, "number": number, "after": cursor}
        data = graphql(PASS2_QUERY, variables)
        comment_data = data["repository"]["issue"]["comments"]
        comments.extend(comment_data["nodes"])
        if not comment_data["pageInfo"]["hasNextPage"]:
            break
        cursor = comment_data["pageInfo"]["endCursor"]
    return comments


def analyze_comments(comments: list[dict]) -> dict:
    """Analyze comment thread for claim/unclaim signals and investigation activity.

    Returns a dict with:
      - claimed: bool (net claim state after processing all take/untake)
      - investigating: bool (someone is actively investigating)
      - flags: list of string flags for the output
      - claim_history: list of {action, user, date} for take/untake tracking
    """
    flags = []
    claim_history = []
    investigating_by = set()
    net_claimed = False

    for comment in comments:
        body = comment.get("body") or ""
        author = (comment.get("author") or {}).get("login", "unknown")
        date = comment.get("createdAt", "")[:10]

        # Check for unclaim first (order matters for bare "take"/"untake")
        if UNCLAIM_RE.search(body):
            claim_history.append({"action": "untake", "user": author, "date": date})
            net_claimed = False
            continue

        if CLAIM_RE.search(body):
            claim_history.append({"action": "take", "user": author, "date": date})
            net_claimed = True
            continue

        if INVESTIGATING_RE.search(body):
            investigating_by.add(author)

    if claim_history:
        takes = sum(1 for c in claim_history if c["action"] == "take")
        untakes = sum(1 for c in claim_history if c["action"] == "untake")
        if untakes > 0:
            flags.append(f"abandoned_{untakes}x")

    if investigating_by:
        flags.append(f"investigating:{','.join(investigating_by)}")

    return {
        "claimed": net_claimed,
        "investigating": len(investigating_by) > 0,
        "flags": flags,
        "claim_history": claim_history,
    }


def extract_label_names(issue: dict) -> set[str]:
    return {label["name"].lower() for label in issue["labels"]["nodes"]}


def infer_issue_domains(issue: dict) -> list[str]:
    combined = " ".join(
        [
            issue.get("title", ""),
            issue.get("body", ""),
            " ".join(label["name"] for label in issue["labels"]["nodes"]),
        ]
    ).lower()

    matches = []
    for domain, keywords in DOMAIN_KEYWORDS.items():
        if any(keyword in combined for keyword in keywords):
            matches.append(domain)
    return sorted(matches)


def assess_issue_clarity(issue: dict) -> dict:
    title = issue.get("title") or ""
    body = issue.get("body") or ""
    combined = f"{title}\n{body}"
    reasons = []
    score = 0.0

    body_length = len(body.strip())
    if body_length >= 120:
        score += 1
        reasons.append("substantial_description")
    if body_length >= 350:
        score += 0.5
        reasons.append("detailed_description")
    if STRUCTURED_BODY_RE.search(body) or "```" in body:
        score += 1
        reasons.append("structured_body")
    if CONCRETE_OUTCOME_RE.search(combined):
        score += 1
        reasons.append("clear_outcome")
    if SPECIFIC_ARTIFACT_RE.search(combined):
        score += 0.5
        reasons.append("specific_artifacts")

    if body_length == 0:
        score -= 2
        reasons.append("missing_body")
    elif body_length < 80:
        score -= 1.5
        reasons.append("thin_description")

    if OPEN_ENDED_RE.search(combined):
        score -= 1
        reasons.append("open_ended")
    if VAGUE_LANGUAGE_RE.search(combined) and score < 2:
        score -= 0.5
        reasons.append("vague_language")

    if score >= 2.5:
        clarity = "high"
    elif score >= 1.0:
        clarity = "medium"
    else:
        clarity = "low"

    flags = []
    if clarity == "low":
        flags.append("vague_definition_of_done")
    elif "open_ended" in reasons:
        flags.append("needs_scope_check")

    return {
        "clarity": clarity,
        "clarity_score": round(score, 1),
        "clarity_reasons": reasons,
        "flags": flags,
    }


def assess_required_expertise(issue: dict) -> dict:
    labels = extract_label_names(issue)
    combined = " ".join(
        [
            issue.get("title", ""),
            issue.get("body", ""),
            " ".join(labels),
        ]
    ).lower()

    score = 0.0
    hits = set()

    for keyword in SPECIALIZED_KEYWORDS:
        if keyword in combined:
            score += 1.0
            hits.add(keyword)

    for keyword in MODERATE_KEYWORDS:
        if keyword in combined:
            score += 0.4
            hits.add(keyword)

    for keyword in APPROACHABLE_KEYWORDS:
        if keyword in combined:
            score -= 0.5
            hits.add(keyword)

    if labels & WARNING_LABELS_LOWER:
        score += 1.0
    if labels & POSITIVE_LABELS_LOWER:
        score -= 0.5
    if issue["comments"]["totalCount"] > 15:
        score += 0.5

    if score >= 2.5:
        level = "specialized"
    elif score >= 1.0:
        level = "moderate"
    else:
        level = "approachable"

    flags = []
    if level == "specialized":
        flags.append("requires_domain_knowledge")

    return {
        "required_expertise": level,
        "expertise_score": round(score, 1),
        "expertise_signals": sorted(hits)[:8],
        "domains": infer_issue_domains(issue),
        "flags": flags,
    }


def assess_profile_fit(
    repo_language: str,
    domains: list[str],
    required_expertise: str,
    contributor_profile: dict | None,
) -> dict | None:
    if not contributor_profile:
        return None

    preferred_languages = {item.lower() for item in contributor_profile.get("languages", [])}
    preferred_domains = {item.lower() for item in contributor_profile.get("domains", [])}
    avoid_domains = {item.lower() for item in contributor_profile.get("avoid_domains", [])}
    max_specialization = contributor_profile.get("max_specialization", "specialized").lower()

    score = 0.0
    reasons = []
    domain_set = {domain.lower() for domain in domains}

    if preferred_languages:
        if repo_language.lower() in preferred_languages:
            score += 1
            reasons.append("language_match")
        else:
            score -= 1
            reasons.append("language_mismatch")

    if preferred_domains and domain_set:
        if preferred_domains & domain_set:
            score += 1
            reasons.append("domain_match")
        else:
            score -= 0.5
            reasons.append("domain_mismatch")

    if avoid_domains & domain_set:
        score -= 1.5
        reasons.append("avoided_domain")

    if SPECIALIZATION_ORDER[required_expertise] > SPECIALIZATION_ORDER.get(max_specialization, 2):
        score -= 1.5
        reasons.append("expertise_ceiling")

    if score >= 1:
        fit = "good"
    elif score >= 0:
        fit = "stretch"
    else:
        fit = "poor"

    flags = []
    if fit == "poor":
        flags.append("profile_mismatch")
    elif fit == "stretch":
        flags.append("profile_stretch")

    return {
        "profile_fit": fit,
        "profile_reasons": reasons,
        "flags": flags,
    }


def analyze_issue_semantics(issue: dict, repo_language: str, contributor_profile: dict | None) -> dict:
    clarity = assess_issue_clarity(issue)
    expertise = assess_required_expertise(issue)
    profile = assess_profile_fit(
        repo_language=repo_language,
        domains=expertise["domains"],
        required_expertise=expertise["required_expertise"],
        contributor_profile=contributor_profile,
    )

    flags = []
    flags.extend(clarity["flags"])
    flags.extend(expertise["flags"])
    if profile:
        flags.extend(profile["flags"])

    return {
        **clarity,
        **expertise,
        "profile_fit": profile["profile_fit"] if profile else None,
        "profile_reasons": profile["profile_reasons"] if profile else [],
        "flags": flags,
    }


def assess_setup_support(repo_data: dict) -> dict:
    signals = []

    if repo_data.get("devcontainerDir") or repo_data.get("devcontainerFile"):
        signals.append("devcontainer")
    if repo_data.get("dockerfile") or repo_data.get("dockerCompose") or repo_data.get("dockerComposeAlt"):
        signals.append("containerized")
    if (
        repo_data.get("makefile")
        or repo_data.get("makefileLower")
        or repo_data.get("justfile")
        or repo_data.get("justfileAlt")
    ):
        signals.append("task_runner")
    if (
        repo_data.get("contributing")
        or repo_data.get("githubContributing")
        or repo_data.get("contributingLower")
        or repo_data.get("githubContributingLower")
    ):
        signals.append("contributing_guide")
    if repo_data.get("cargoToml") or repo_data.get("packageJson") or repo_data.get("pyprojectToml") or repo_data.get("goMod"):
        signals.append("standard_manifest")

    has_guided_setup = {"devcontainer", "task_runner", "contributing_guide"} & set(signals)
    has_standard_setup = "standard_manifest" in signals or "containerized" in signals

    if has_guided_setup:
        support = "guided"
    elif has_standard_setup:
        support = "standard"
    else:
        support = "unclear"

    flags = []
    if support == "standard" and "contributing_guide" not in signals and "devcontainer" not in signals:
        flags.append("manual_setup")
    elif support == "unclear":
        flags.append("dev_setup_unclear")

    return {
        "setup_support": support,
        "setup_signals": signals,
        "flags": flags,
    }


def detect_cla_requirement(prs: list[dict]) -> dict:
    signals = []

    for pr in prs:
        for comment in pr.get("comments", {}).get("nodes", []):
            body = comment.get("body") or ""
            author = (comment.get("author") or {}).get("login", "")
            if CLA_KEYWORD_RE.search(body) or CLA_AUTHOR_RE.search(author):
                signals.append({
                    "pr": pr.get("url"),
                    "author": author or "unknown",
                })
                break

    return {
        "cla_required": bool(signals),
        "cla_signals": signals[:3],
        "flags": ["cla_required"] if signals else [],
    }


def merge_flags(*flag_groups: list[str]) -> list[str]:
    merged = []
    seen = set()
    for group in flag_groups:
        for flag in group:
            if flag not in seen:
                seen.add(flag)
                merged.append(flag)
    return merged


# --- Pass 0: repo health check ---

REPO_HEALTH_QUERY = """
query RepoHealth {
  $ALIASES
}
"""


def build_repo_health_query(repos: list[str]) -> str:
    """Query recent merged PRs and contributor activity per repo."""
    aliases = []
    repo_objects = "\n".join(
        [
            f'    {alias}: object(expression: "{expression}") {{ __typename }}'
            for alias, expression in REPO_FILE_ALIASES.items()
        ]
    )
    for i, repo in enumerate(repos):
        owner, name = repo.split("/")
        aliases.append(f'''
  repo_{i}: repository(owner: "{owner}", name: "{name}") {{
    nameWithOwner
{repo_objects}
    pullRequests(states: MERGED, first: 10, orderBy: {{field: UPDATED_AT, direction: DESC}}) {{
      nodes {{
        mergedAt
        url
        author {{ login }}
        authorAssociation
        reviews(first: 1) {{
          nodes {{ submittedAt }}
        }}
        comments(first: 10) {{
          nodes {{
            body
            author {{ login }}
          }}
        }}
      }}
    }}
  }}''')
    return "query RepoHealth {" + "\n".join(aliases) + "\n}"


def check_repo_health(repos: list[str], batch_size: int) -> dict[str, dict]:
    """Pass 0: check repo responsiveness. Returns repo -> health dict."""
    health = {}
    now = datetime.now(timezone.utc)

    for batch_start in range(0, len(repos), batch_size):
        batch = repos[batch_start:batch_start + batch_size]
        query = build_repo_health_query(batch)
        data = graphql(query)

        for key, repo_data in data.items():
            repo_name = repo_data["nameWithOwner"]
            prs = repo_data["pullRequests"]["nodes"]
            setup = assess_setup_support(repo_data)
            cla = detect_cla_requirement(prs)

            if not prs:
                health[repo_name] = {
                    "merge_speed_days": None,
                    "first_timer_merges": 0,
                    "active": False,
                    "health_score": "poor",
                    "setup_support": setup["setup_support"],
                    "setup_signals": setup["setup_signals"],
                    "cla_required": cla["cla_required"],
                    "cla_signals": cla["cla_signals"],
                    "flags": merge_flags(setup["flags"], cla["flags"]),
                }
                continue

            # Average days from first review to merge
            merge_deltas = []
            first_timer_count = 0
            for pr in prs:
                merged_at = pr.get("mergedAt")
                if not merged_at:
                    continue
                reviews = pr.get("reviews", {}).get("nodes", [])
                if reviews and reviews[0].get("submittedAt"):
                    reviewed = datetime.fromisoformat(reviews[0]["submittedAt"].replace("Z", "+00:00"))
                    merged = datetime.fromisoformat(merged_at.replace("Z", "+00:00"))
                    delta = (merged - reviewed).total_seconds() / 86400
                    merge_deltas.append(max(0, delta))

                # First-time contributor = not MEMBER, OWNER, or COLLABORATOR
                assoc = pr.get("authorAssociation", "")
                if assoc in ("FIRST_TIMER", "FIRST_TIME_CONTRIBUTOR", "CONTRIBUTOR", "NONE"):
                    first_timer_count += 1

            avg_merge = sum(merge_deltas) / len(merge_deltas) if merge_deltas else None

            # Check recency: was last merge within 14 days?
            last_merge = prs[0].get("mergedAt", "")
            if last_merge:
                last_dt = datetime.fromisoformat(last_merge.replace("Z", "+00:00"))
                days_since = (now - last_dt).days
                active = days_since <= 14
            else:
                active = False

            # Health score
            score = "good"
            if not active:
                score = "poor"
            elif avg_merge is not None and avg_merge > 7:
                score = "slow"
            elif first_timer_count == 0:
                score = "insular"

            health[repo_name] = {
                "merge_speed_days": round(avg_merge, 1) if avg_merge is not None else None,
                "first_timer_merges": first_timer_count,
                "active": active,
                "health_score": score,
                "setup_support": setup["setup_support"],
                "setup_signals": setup["setup_signals"],
                "cla_required": cla["cla_required"],
                "cla_signals": cla["cla_signals"],
                "flags": merge_flags(setup["flags"], cla["flags"]),
            }

    return health


# --- Enrichment: warning labels + confidence ---

WARNING_LABELS = {
    "not-as-easy-as-it-looks", "complex", "high-effort", "large",
    "size/XL", "size/L", "priority/P0", "priority/P1", "critical",
}
WARNING_LABELS_LOWER = {label.lower() for label in WARNING_LABELS}

POSITIVE_LABELS = {
    "good first issue", "good-first-issue", "easy", "beginner",
    "starter", "low-hanging-fruit", "accepted", "ready",
}
POSITIVE_LABELS_LOWER = {label.lower() for label in POSITIVE_LABELS}


def compute_confidence(
    issue: dict,
    comment_analysis: dict,
    semantic_analysis: dict,
    repo_health: dict | None = None,
) -> str:
    """Compute a confidence level: high, medium, or low."""
    labels = extract_label_names(issue)

    # Start at high, deduct
    score = 3

    if comment_analysis["investigating"]:
        score -= 1
    if comment_analysis["claim_history"]:
        score -= 0.5
    if labels & WARNING_LABELS_LOWER:
        score -= 1
    if issue["comments"]["totalCount"] > 20:
        score -= 1
    if labels & POSITIVE_LABELS_LOWER:
        score += 0.5

    if semantic_analysis["clarity"] == "low":
        score -= 1.5
    elif semantic_analysis["clarity"] == "medium":
        score -= 0.5

    if semantic_analysis["required_expertise"] == "specialized":
        score -= 1
    elif semantic_analysis["required_expertise"] == "moderate":
        score -= 0.25

    if semantic_analysis.get("profile_fit") == "stretch":
        score -= 0.5
    elif semantic_analysis.get("profile_fit") == "poor":
        score -= 1

    # Repo health adjustments
    if repo_health:
        h = repo_health.get("health_score", "good")
        if h == "poor":
            score -= 1.5  # inactive repo, don't bother
        elif h == "slow":
            score -= 0.5  # PRs take a while to review
        elif h == "insular":
            score -= 0.5  # no first-timer merges recently

        if repo_health.get("first_timer_merges", 0) >= 3:
            score += 0.5  # actively merges outside contributors
        if repo_health.get("setup_support") == "unclear":
            score -= 0.5
        elif repo_health.get("setup_support") == "standard":
            score -= 0.25
        if repo_health.get("cla_required"):
            score -= 0.5

    if score >= 2.5:
        return "high"
    elif score >= 1.5:
        return "medium"
    return "low"


# --- Orchestration ---

def hunt(config: dict) -> tuple[list[dict], dict, dict]:
    repos = config["repos"]
    labels = config["labels"]
    staleness_days = config.get("staleness_days", 90)
    batch_size = config.get("batch_size", 8)
    contributor_profile = config.get("contributor_profile")
    cutoff = datetime.now(timezone.utc) - timedelta(days=staleness_days)

    print(f"Hunting across {len(repos)} repos...")

    # Pass 0: repo health check
    print("Pass 0: checking repo health...")
    repo_health = check_repo_health(repos, batch_size)
    for name, h in repo_health.items():
        speed = f"{h['merge_speed_days']}d" if h['merge_speed_days'] is not None else "?"
        cla = "yes" if h["cla_required"] else "no"
        print(
            f"  {name:<40} {h['health_score']:<8} merge:{speed:<6} "
            f"first-timers:{h['first_timer_merges']:<2} setup:{h['setup_support']:<8} cla:{cla}"
        )

    # Pass 1: cheap scan with pagination
    all_survivors = []
    repo_meta = {}

    for batch_start in range(0, len(repos), batch_size):
        batch = repos[batch_start:batch_start + batch_size]
        cursors = {r: None for r in batch}
        active = set(batch)

        while active:
            query = build_pass1_query(list(active), labels, cursors)
            data = graphql(query)

            next_active = set()
            for key, repo_data in data.items():
                repo_name = repo_data["nameWithOwner"]
                repo_meta[repo_name] = {
                    "stars": repo_data["stargazerCount"],
                    "language": (repo_data.get("primaryLanguage") or {}).get("name", "Unknown"),
                }

                issues = repo_data["issues"]
                hit_cutoff = False

                for issue in issues["nodes"]:
                    updated = datetime.fromisoformat(issue["updatedAt"].replace("Z", "+00:00"))
                    if updated < cutoff:
                        hit_cutoff = True
                        break

                    reason = pass1_filter(issue, staleness_days)
                    if reason is None:
                        issue["_repo"] = repo_name
                        all_survivors.append(issue)

                if issues["pageInfo"]["hasNextPage"] and not hit_cutoff:
                    cursors[repo_name] = issues["pageInfo"]["endCursor"]
                    next_active.add(repo_name)

            active = next_active

        batch_end = min(batch_start + batch_size, len(repos))
        print(f"  Scanned repos {batch_start + 1}-{batch_end}, {len(all_survivors)} survivors so far")

    print(f"Pass 1 done: {len(all_survivors)} issues survived")

    # Pass 2: deep comment scan + enrichment on survivors
    results = []
    for i, issue in enumerate(all_survivors):
        owner, name = issue["_repo"].split("/")

        if issue["comments"]["totalCount"] == 0:
            analysis = {"claimed": False, "investigating": False, "flags": [], "claim_history": []}
        else:
            comments = fetch_all_comments(owner, name, issue["number"])
            analysis = analyze_comments(comments)

        if analysis["claimed"]:
            print(f"  Filtered (claimed): {issue['_repo']}#{issue['number']} — {issue['title'][:60]}")
            continue

        rh = repo_health.get(issue["_repo"])
        repo_language = repo_meta.get(issue["_repo"], {}).get("language", "Unknown")
        semantic = analyze_issue_semantics(issue, repo_language, contributor_profile)
        combined_flags = merge_flags(
            analysis["flags"],
            semantic["flags"],
            (rh or {}).get("flags", []),
        )
        confidence = compute_confidence(issue, analysis, semantic, rh)
        if confidence == "low":
            print(f"  Filtered (low confidence): {issue['_repo']}#{issue['number']} — {issue['title'][:60]}")
            continue

        issue["_analysis"] = analysis
        issue["_semantic"] = semantic
        issue["_flags"] = combined_flags
        issue["_confidence"] = confidence
        results.append(issue)

        if (i + 1) % 10 == 0:
            print(f"  Pass 2: {i + 1}/{len(all_survivors)} checked")

    print(f"Pass 2 done: {len(results)} issues are genuinely unclaimed")
    return results, repo_meta, repo_health


def format_output(issues: list[dict], repo_meta: dict, repo_health: dict, total_repos: int) -> dict:
    now = datetime.now(timezone.utc)
    formatted = []
    for issue in issues:
        created = datetime.fromisoformat(issue["createdAt"].replace("Z", "+00:00"))
        meta = repo_meta.get(issue["_repo"], {})
        analysis = issue.get("_analysis", {})
        semantic = issue.get("_semantic", {})
        health = repo_health.get(issue["_repo"], {})

        entry = {
            "repo": issue["_repo"],
            "stars": meta.get("stars", 0),
            "language": meta.get("language", "Unknown"),
            "number": issue["number"],
            "title": issue["title"],
            "url": issue["url"],
            "created_at": issue["createdAt"],
            "updated_at": issue["updatedAt"],
            "labels": [l["name"] for l in issue["labels"]["nodes"]],
            "comment_count": issue["comments"]["totalCount"],
            "age_days": (now - created).days,
            "confidence": issue.get("_confidence", "unknown"),
            "flags": issue.get("_flags", []),
            "clarity": semantic.get("clarity", "unknown"),
            "clarity_reasons": semantic.get("clarity_reasons", []),
            "required_expertise": semantic.get("required_expertise", "unknown"),
            "expertise_signals": semantic.get("expertise_signals", []),
            "domains": semantic.get("domains", []),
            "profile_fit": semantic.get("profile_fit"),
            "profile_reasons": semantic.get("profile_reasons", []),
            "repo_health": health.get("health_score", "unknown"),
            "merge_speed_days": health.get("merge_speed_days"),
            "first_timer_merges": health.get("first_timer_merges", 0),
            "setup_support": health.get("setup_support", "unknown"),
            "setup_signals": health.get("setup_signals", []),
            "cla_required": health.get("cla_required", False),
        }

        if analysis.get("claim_history"):
            entry["claim_history"] = analysis["claim_history"]
        if health.get("cla_signals"):
            entry["cla_signals"] = health["cla_signals"]

        formatted.append(entry)

    # Sort: high confidence first, then by freshness
    confidence_order = {"high": 0, "medium": 1}
    formatted.sort(key=lambda x: (confidence_order.get(x["confidence"], 2), -datetime.fromisoformat(x["updated_at"].replace("Z", "+00:00")).timestamp()))

    return {
        "generated_at": now.isoformat(),
        "total_repos_scanned": total_repos,
        "total_issues_found": len(formatted),
        "unclaimed_count": len(formatted),
        "issues": formatted,
    }


def write_html(data: dict, path: str):
    json_blob = json.dumps(data)
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Issue Hunter — Unclaimed Good First Issues</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ background: #0d1117; color: #c9d1d9; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; padding: 2rem; }}
  h1 {{ color: #f0f6fc; margin-bottom: 0.5rem; }}
  .meta {{ color: #8b949e; margin-bottom: 1.5rem; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th {{ text-align: left; padding: 0.75rem; border-bottom: 2px solid #30363d; color: #8b949e; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; cursor: pointer; }}
  th:hover {{ color: #c9d1d9; }}
  td {{ padding: 0.75rem; border-bottom: 1px solid #21262d; vertical-align: top; }}
  tr:hover {{ background: #161b22; }}
  a {{ color: #58a6ff; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  .label {{ display: inline-block; padding: 0.15rem 0.5rem; border-radius: 1rem; font-size: 0.75rem; background: #1f6feb33; color: #58a6ff; margin-right: 0.25rem; margin-bottom: 0.15rem; }}
  .stars {{ color: #e3b341; }}
  .lang {{ color: #8b949e; font-size: 0.85rem; }}
  .age {{ color: #8b949e; }}
  .assessment {{ color: #8b949e; margin-top: 0.35rem; font-size: 0.85rem; }}
  .confidence-high {{ color: #3fb950; font-weight: 600; }}
  .confidence-medium {{ color: #d29922; font-weight: 600; }}
  .flag {{ display: inline-block; padding: 0.1rem 0.4rem; border-radius: 0.25rem; font-size: 0.7rem; margin-right: 0.2rem; }}
  .flag-abandoned {{ background: #f8514933; color: #f85149; }}
  .flag-investigating {{ background: #d2992233; color: #d29922; }}
  .flag-scope {{ background: #1f6feb33; color: #58a6ff; }}
  .flag-skill {{ background: #bc8cff33; color: #bc8cff; }}
  .flag-setup {{ background: #3fb95033; color: #3fb950; }}
  .flag-legal {{ background: #ff7b7233; color: #ff7b72; }}
  .filter-bar {{ margin-bottom: 1rem; display: flex; gap: 0.5rem; flex-wrap: wrap; align-items: center; }}
  .filter-bar input, .filter-bar select {{ background: #161b22; border: 1px solid #30363d; color: #c9d1d9; padding: 0.5rem; border-radius: 0.375rem; }}
  .filter-bar input {{ flex: 1; min-width: 200px; }}
  .filter-bar label {{ color: #8b949e; font-size: 0.85rem; display: flex; align-items: center; gap: 0.3rem; }}
  .filter-bar input[type="checkbox"] {{ width: auto; min-width: auto; }}
</style>
</head>
<body>
<h1>Issue Hunter</h1>
<p class="meta" id="meta"></p>
<div class="filter-bar">
  <input type="text" id="search" placeholder="Filter by repo, title, or language...">
  <select id="sort">
    <option value="confidence">Confidence</option>
    <option value="clarity">Best scoped</option>
    <option value="updated">Recently updated</option>
    <option value="age">Newest first</option>
    <option value="comments">Fewest comments</option>
    <option value="stars">Most stars</option>
  </select>
  <label><input type="checkbox" id="highOnly"> High confidence only</label>
</div>
<table>
<thead><tr><th>Repo</th><th>Issue</th><th>Labels</th><th>Assessment</th><th>Age</th></tr></thead>
<tbody id="tbody"></tbody>
</table>
<script>
const DATA = {json_blob};
const tbody = document.getElementById("tbody");
const meta = document.getElementById("meta");
const search = document.getElementById("search");
const sortEl = document.getElementById("sort");
const highOnly = document.getElementById("highOnly");

const profileAware = DATA.issues.some(issue => issue.profile_fit);
meta.textContent = DATA.unclaimed_count + " unclaimed issues across " + DATA.total_repos_scanned + " repos. Updated " + new Date(DATA.generated_at).toLocaleString() + (profileAware ? " · profile-aware triage enabled" : "");

function flagHtml(flags) {{
  return flags.map(f => {{
    if (f.startsWith("abandoned")) return '<span class="flag flag-abandoned">' + f + '</span>';
    if (f.startsWith("investigating")) return '<span class="flag flag-investigating">' + f + '</span>';
    if (f === "cla_required") return '<span class="flag flag-legal">' + f + '</span>';
    if (f === "manual_setup" || f === "dev_setup_unclear") return '<span class="flag flag-setup">' + f + '</span>';
    if (f === "vague_definition_of_done" || f === "needs_scope_check") return '<span class="flag flag-scope">' + f + '</span>';
    if (f === "requires_domain_knowledge" || f.startsWith("profile_")) return '<span class="flag flag-skill">' + f + '</span>';
    return '<span class="flag">' + f + '</span>';
  }}).join(" ");
}}

function assessmentText(issue) {{
  const parts = [
    'clarity: ' + issue.clarity,
    'expertise: ' + issue.required_expertise
  ];
  if (issue.profile_fit) parts.push('fit: ' + issue.profile_fit);
  if (issue.domains && issue.domains.length) parts.push('domains: ' + issue.domains.join(', '));
  return parts.join(' · ');
}}

function render(issues) {{
  tbody.innerHTML = "";
  issues.forEach(issue => {{
    const tr = document.createElement("tr");
    const labels = issue.labels.map(l => '<span class="label">' + l + '</span>').join("");
    const conf = '<span class="confidence-' + issue.confidence + '">' + issue.confidence + '</span>';
    const flags = flagHtml(issue.flags || []);
    tr.innerHTML =
      '<td><a href="https://github.com/' + issue.repo + '">' + issue.repo + '</a><br><span class="lang">' + issue.language + '</span> <span class="stars">\u2605 ' + issue.stars.toLocaleString() + '</span><br><span class="age">health: ' + issue.repo_health + (issue.merge_speed_days != null ? ' \u00b7 ' + issue.merge_speed_days + 'd merge' : '') + ' \u00b7 ' + issue.first_timer_merges + ' ext merges' + ' \u00b7 setup: ' + issue.setup_support + (issue.cla_required ? ' \u00b7 CLA' : '') + '</span></td>' +
      '<td><a href="' + issue.url + '">#' + issue.number + '</a> ' + issue.title + '<div class="assessment">' + assessmentText(issue) + '</div></td>' +
      '<td>' + labels + '</td>' +
      '<td>' + conf + ' ' + flags + '<br><span class="age">' + issue.comment_count + ' comments</span></td>' +
      '<td class="age">' + issue.age_days + 'd</td>';
    tbody.appendChild(tr);
  }});
}}

function filterAndSort() {{
  const q = search.value.toLowerCase();
  let filtered = DATA.issues.filter(i =>
    (i.repo.toLowerCase().includes(q) || i.title.toLowerCase().includes(q) || i.language.toLowerCase().includes(q)) &&
    (!highOnly.checked || i.confidence === "high")
  );
  const s = sortEl.value;
  const co = {{"high": 0, "medium": 1}};
  const clarityOrder = {{"high": 0, "medium": 1, "low": 2}};
  if (s === "confidence") filtered.sort((a, b) => (co[a.confidence]||2) - (co[b.confidence]||2) || b.updated_at.localeCompare(a.updated_at));
  else if (s === "clarity") filtered.sort((a, b) => (clarityOrder[a.clarity]||3) - (clarityOrder[b.clarity]||3) || (co[a.confidence]||2) - (co[b.confidence]||2));
  else if (s === "updated") filtered.sort((a, b) => b.updated_at.localeCompare(a.updated_at));
  else if (s === "age") filtered.sort((a, b) => a.age_days - b.age_days);
  else if (s === "comments") filtered.sort((a, b) => a.comment_count - b.comment_count);
  else if (s === "stars") filtered.sort((a, b) => b.stars - a.stars);
  render(filtered);
}}

search.addEventListener("input", filterAndSort);
sortEl.addEventListener("change", filterAndSort);
highOnly.addEventListener("change", filterAndSort);
filterAndSort();
</script>
</body>
</html>"""
    with open(path, "w") as f:
        f.write(html)


def main():
    config = load_config()
    unclaimed, repo_meta, repo_health = hunt(config)
    output = format_output(unclaimed, repo_meta, repo_health, len(config["repos"]))

    results_dir = Path("results")
    results_dir.mkdir(exist_ok=True)

    json_path = results_dir / "unclaimed.json"
    with open(json_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"Wrote {json_path} ({output['unclaimed_count']} issues)")

    html_path = Path("index.html")
    write_html(output, str(html_path))
    print(f"Wrote {html_path}")


if __name__ == "__main__":
    main()
