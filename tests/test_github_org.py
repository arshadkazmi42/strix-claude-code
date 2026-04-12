"""Tests for github_org module."""

import json
from unittest.mock import MagicMock, patch

import pytest

from strix_cli_claude.github_org import fetch_org_repos, parse_org_from_url


class TestParseOrgFromUrl:
    """Tests for parse_org_from_url."""

    def test_https_org_url(self):
        assert parse_org_from_url("https://github.com/cloudflare") == "cloudflare"

    def test_https_org_url_trailing_slash(self):
        assert parse_org_from_url("https://github.com/cloudflare/") == "cloudflare"

    def test_http_org_url(self):
        assert parse_org_from_url("http://github.com/myorg") == "myorg"

    def test_bare_github_org_url(self):
        assert parse_org_from_url("github.com/myorg") == "myorg"

    def test_repo_url_returns_none(self):
        """Repo URLs (org/repo) should NOT be detected as org."""
        assert parse_org_from_url("https://github.com/cloudflare/agents") is None

    def test_repo_url_deep_path_returns_none(self):
        assert parse_org_from_url("https://github.com/user/repo/tree/main") is None

    def test_non_github_url_returns_none(self):
        assert parse_org_from_url("https://gitlab.com/myorg") is None

    def test_local_path_returns_none(self):
        assert parse_org_from_url("./myproject") is None

    def test_ssh_url_returns_none(self):
        assert parse_org_from_url("git@github.com:user/repo.git") is None

    def test_empty_string_returns_none(self):
        assert parse_org_from_url("") is None

    def test_just_github_returns_none(self):
        assert parse_org_from_url("https://github.com/") is None
        assert parse_org_from_url("https://github.com") is None


class TestFetchOrgRepos:
    """Tests for fetch_org_repos."""

    def _make_repo(self, name, **overrides):
        """Helper to create a repo dict."""
        repo = {
            "name": name,
            "full_name": f"testorg/{name}",
            "clone_url": f"https://github.com/testorg/{name}.git",
            "ssh_url": f"git@github.com:testorg/{name}.git",
            "html_url": f"https://github.com/testorg/{name}",
            "stargazers_count": 10,
            "language": "Python",
            "description": f"A {name} repo",
            "default_branch": "main",
            "archived": False,
            "disabled": False,
            "fork": False,
            "private": False,
            "size": 100,
        }
        repo.update(overrides)
        return repo

    def test_fetches_and_filters_repos(self):
        """Should fetch repos and filter out archived/disabled/etc."""
        repos = [
            self._make_repo("good-repo", stargazers_count=50),
            self._make_repo("archived-repo", archived=True),
            self._make_repo("disabled-repo", disabled=True),
            self._make_repo("example-app"),
            self._make_repo("demo-project"),
            self._make_repo("test-utils"),
            self._make_repo("sample-code"),
            self._make_repo("another-good-repo", stargazers_count=100),
        ]

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = repos
        mock_response.headers = {}

        with patch("strix_cli_claude.github_org.httpx.Client") as mock_client:
            mock_instance = MagicMock()
            mock_instance.get.return_value = mock_response
            mock_instance.__enter__ = MagicMock(return_value=mock_instance)
            mock_instance.__exit__ = MagicMock(return_value=False)
            mock_client.return_value = mock_instance

            result = fetch_org_repos("testorg")

        # Should only include good-repo and another-good-repo
        names = [r["name"] for r in result]
        assert "good-repo" in names
        assert "another-good-repo" in names
        assert "archived-repo" not in names
        assert "disabled-repo" not in names
        assert "example-app" not in names
        assert "demo-project" not in names
        assert "test-utils" not in names
        assert "sample-code" not in names

    def test_sorted_by_stars_descending(self):
        """Should sort results by stars, highest first."""
        repos = [
            self._make_repo("low-stars", stargazers_count=5),
            self._make_repo("high-stars", stargazers_count=500),
            self._make_repo("mid-stars", stargazers_count=50),
        ]

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = repos
        mock_response.headers = {}

        with patch("strix_cli_claude.github_org.httpx.Client") as mock_client:
            mock_instance = MagicMock()
            mock_instance.get.return_value = mock_response
            mock_instance.__enter__ = MagicMock(return_value=mock_instance)
            mock_instance.__exit__ = MagicMock(return_value=False)
            mock_client.return_value = mock_instance

            result = fetch_org_repos("testorg")

        assert result[0]["name"] == "high-stars"
        assert result[1]["name"] == "mid-stars"
        assert result[2]["name"] == "low-stars"

    def test_skips_empty_repos(self):
        """Should skip repos with size 0."""
        repos = [
            self._make_repo("empty-repo", size=0),
            self._make_repo("has-code", size=100),
        ]

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = repos
        mock_response.headers = {}

        with patch("strix_cli_claude.github_org.httpx.Client") as mock_client:
            mock_instance = MagicMock()
            mock_instance.get.return_value = mock_response
            mock_instance.__enter__ = MagicMock(return_value=mock_instance)
            mock_instance.__exit__ = MagicMock(return_value=False)
            mock_client.return_value = mock_instance

            result = fetch_org_repos("testorg")

        names = [r["name"] for r in result]
        assert "has-code" in names
        assert "empty-repo" not in names

    def test_min_stars_filter(self):
        """Should filter by minimum star count."""
        repos = [
            self._make_repo("popular", stargazers_count=100),
            self._make_repo("unpopular", stargazers_count=2),
        ]

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = repos
        mock_response.headers = {}

        with patch("strix_cli_claude.github_org.httpx.Client") as mock_client:
            mock_instance = MagicMock()
            mock_instance.get.return_value = mock_response
            mock_instance.__enter__ = MagicMock(return_value=mock_instance)
            mock_instance.__exit__ = MagicMock(return_value=False)
            mock_client.return_value = mock_instance

            result = fetch_org_repos("testorg", min_stars=10)

        names = [r["name"] for r in result]
        assert "popular" in names
        assert "unpopular" not in names

    def test_404_raises_value_error(self):
        """Should raise ValueError for unknown org."""
        mock_response = MagicMock()
        mock_response.status_code = 404

        with patch("strix_cli_claude.github_org.httpx.Client") as mock_client:
            mock_instance = MagicMock()
            mock_instance.get.return_value = mock_response
            mock_instance.__enter__ = MagicMock(return_value=mock_instance)
            mock_instance.__exit__ = MagicMock(return_value=False)
            mock_client.return_value = mock_instance

            with pytest.raises(ValueError, match="not found"):
                fetch_org_repos("nonexistent-org")

    def test_uses_github_token_env(self):
        """Should use GITHUB_TOKEN from env if available."""
        repos = [self._make_repo("repo1")]

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = repos
        mock_response.headers = {}

        with patch("strix_cli_claude.github_org.httpx.Client") as mock_client:
            mock_instance = MagicMock()
            mock_instance.get.return_value = mock_response
            mock_instance.__enter__ = MagicMock(return_value=mock_instance)
            mock_instance.__exit__ = MagicMock(return_value=False)
            mock_client.return_value = mock_instance

            with patch.dict("os.environ", {"GITHUB_TOKEN": "ghp_test123"}):
                fetch_org_repos("testorg")

            # Check that Authorization header was set
            call_kwargs = mock_client.call_args
            headers = call_kwargs.kwargs.get("headers") or call_kwargs[1].get("headers", {})
            assert "Bearer ghp_test123" in str(headers)

    def test_skips_template_repos(self):
        """Should skip repos with 'template' in name."""
        repos = [
            self._make_repo("worker-template"),
            self._make_repo("real-worker", stargazers_count=20),
        ]

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = repos
        mock_response.headers = {}

        with patch("strix_cli_claude.github_org.httpx.Client") as mock_client:
            mock_instance = MagicMock()
            mock_instance.get.return_value = mock_response
            mock_instance.__enter__ = MagicMock(return_value=mock_instance)
            mock_instance.__exit__ = MagicMock(return_value=False)
            mock_client.return_value = mock_instance

            result = fetch_org_repos("testorg")

        names = [r["name"] for r in result]
        assert "real-worker" in names
        assert "worker-template" not in names

    def test_result_shape(self):
        """Should return repos with expected keys."""
        repos = [self._make_repo("myrepo", language="Rust", stargazers_count=42)]

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = repos
        mock_response.headers = {}

        with patch("strix_cli_claude.github_org.httpx.Client") as mock_client:
            mock_instance = MagicMock()
            mock_instance.get.return_value = mock_response
            mock_instance.__enter__ = MagicMock(return_value=mock_instance)
            mock_instance.__exit__ = MagicMock(return_value=False)
            mock_client.return_value = mock_instance

            result = fetch_org_repos("testorg")

        assert len(result) == 1
        repo = result[0]
        assert repo["name"] == "myrepo"
        assert repo["full_name"] == "testorg/myrepo"
        assert repo["clone_url"] == "https://github.com/testorg/myrepo.git"
        assert repo["stars"] == 42
        assert repo["language"] == "Rust"


class TestClassifyTargetOrg:
    """Tests for classify_target with org URLs."""

    def test_classifies_org_url(self):
        from strix_cli_claude.main import classify_target
        result = classify_target("https://github.com/cloudflare")
        assert result["type"] == "github_org"
        assert result["org"] == "cloudflare"

    def test_classifies_org_url_trailing_slash(self):
        from strix_cli_claude.main import classify_target
        result = classify_target("https://github.com/cloudflare/")
        assert result["type"] == "github_org"
        assert result["org"] == "cloudflare"

    def test_repo_url_not_classified_as_org(self):
        from strix_cli_claude.main import classify_target
        result = classify_target("https://github.com/cloudflare/agents")
        assert result["type"] == "github"
        assert result["type"] != "github_org"
