import unittest

from issue_hunter import (
    analyze_comments,
    analyze_issue_semantics,
    assess_issue_clarity,
    assess_required_expertise,
    assess_setup_support,
    compute_confidence,
    detect_cla_requirement,
)


def make_issue(title, body, labels=None, comments=0):
    return {
        "title": title,
        "body": body,
        "labels": {"nodes": [{"name": label} for label in (labels or [])]},
        "comments": {"totalCount": comments},
    }


class IssueHunterTests(unittest.TestCase):
    def test_analyze_comments_tracks_take_and_untake(self):
        comments = [
            {
                "body": "I'll take this.",
                "author": {"login": "alice"},
                "createdAt": "2026-04-01T12:00:00Z",
            },
            {
                "body": "untake",
                "author": {"login": "alice"},
                "createdAt": "2026-04-02T12:00:00Z",
            },
            {
                "body": "I can reproduce this on main.",
                "author": {"login": "bob"},
                "createdAt": "2026-04-03T12:00:00Z",
            },
        ]

        analysis = analyze_comments(comments)

        self.assertFalse(analysis["claimed"])
        self.assertIn("abandoned_1x", analysis["flags"])
        self.assertIn("investigating:bob", analysis["flags"])

    def test_clarity_flags_vague_issue(self):
        issue = make_issue(
            "Something is off",
            "This doesn't work somehow.",
            labels=["help wanted"],
        )

        clarity = assess_issue_clarity(issue)

        self.assertEqual(clarity["clarity"], "low")
        self.assertIn("vague_definition_of_done", clarity["flags"])

    def test_clarity_rewards_structured_issue(self):
        issue = make_issue(
            "Add --json output to stats command",
            """Steps to reproduce:
1. Run `tool stats`.
2. Observe there is no machine-readable output.

Expected behavior:
- `tool stats --json` emits valid JSON with the same counters shown in the table.
""",
            labels=["good first issue"],
        )

        clarity = assess_issue_clarity(issue)

        self.assertEqual(clarity["clarity"], "high")
        self.assertIn("clear_outcome", clarity["clarity_reasons"])

    def test_required_expertise_flags_specialized_work(self):
        issue = make_issue(
            "Fix parser regression in type inference",
            "The compiler parser produces the wrong AST during type inference in the language server.",
            labels=["help wanted"],
            comments=18,
        )

        expertise = assess_required_expertise(issue)

        self.assertEqual(expertise["required_expertise"], "specialized")
        self.assertIn("requires_domain_knowledge", expertise["flags"])
        self.assertIn("compiler", expertise["domains"])

    def test_profile_fit_marks_mismatch(self):
        issue = make_issue(
            "Investigate auth protocol mismatch",
            "Update the authentication protocol for the security handshake.",
            labels=["help wanted"],
            comments=4,
        )

        semantic = analyze_issue_semantics(
            issue,
            repo_language="Rust",
            contributor_profile={
                "languages": ["Go"],
                "domains": ["docs"],
                "avoid_domains": ["security"],
                "max_specialization": "moderate",
            },
        )

        self.assertEqual(semantic["profile_fit"], "poor")
        self.assertIn("profile_mismatch", semantic["flags"])

    def test_setup_and_cla_signals_are_detected(self):
        repo_data = {
            "devcontainerDir": {"__typename": "Tree"},
            "devcontainerFile": None,
            "dockerfile": None,
            "dockerCompose": None,
            "dockerComposeAlt": None,
            "makefile": {"__typename": "Blob"},
            "justfile": None,
            "cargoToml": {"__typename": "Blob"},
            "packageJson": None,
            "pyprojectToml": None,
            "goMod": None,
            "contributing": {"__typename": "Blob"},
            "githubContributing": None,
        }
        prs = [
            {
                "url": "https://github.com/acme/project/pull/1",
                "comments": {
                    "nodes": [
                        {
                            "body": "CLA Assistant Lite bot says the contributor license agreement is not signed.",
                            "author": {"login": "claassistantio"},
                        }
                    ]
                },
            }
        ]

        setup = assess_setup_support(repo_data)
        cla = detect_cla_requirement(prs)

        self.assertEqual(setup["setup_support"], "guided")
        self.assertTrue(cla["cla_required"])
        self.assertIn("cla_required", cla["flags"])

    def test_confidence_drops_for_scope_and_repo_friction(self):
        issue = make_issue(
            "Investigate planner bug",
            "Investigate why this doesn't work.",
            labels=["help wanted"],
            comments=22,
        )
        semantic = {
            "clarity": "low",
            "required_expertise": "specialized",
            "profile_fit": "poor",
        }
        comment_analysis = {
            "investigating": True,
            "claim_history": [],
        }
        repo_health = {
            "health_score": "poor",
            "first_timer_merges": 0,
            "setup_support": "unclear",
            "cla_required": True,
        }

        confidence = compute_confidence(issue, comment_analysis, semantic, repo_health)

        self.assertEqual(confidence, "low")


if __name__ == "__main__":
    unittest.main()
