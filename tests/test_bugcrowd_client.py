"""Tests for the Bugcrowd program source client."""

from unittest.mock import patch

import pytest

from strix_cli_claude import bugcrowd_client as bc
from strix_cli_claude.bugcrowd_client import (
    BugcrowdClient,
    BugcrowdError,
    _handle_from_brief,
    _offers_bounty,
    _transform_engagement,
    normalize_asset_type,
)


class TestHelpers:
    def test_handle_from_brief(self):
        assert _handle_from_brief("/engagements/acme-bb") == "acme-bb"
        assert _handle_from_brief("/engagements/acme-bb/") == "acme-bb"
        assert _handle_from_brief(None) is None
        assert _handle_from_brief("") is None

    def test_offers_bounty_true_shapes(self):
        assert _offers_bounty({"hasMonetaryReward": True}) is True
        assert _offers_bounty({"max": 5000}) is True
        assert _offers_bounty({"currency": "USD"}) is True
        assert _offers_bounty({"rewardRangeSummary": [{"max": 1000}]}) is True

    def test_offers_bounty_real_string_shape(self):
        # The actual Bugcrowd engagements feed uses string reward fields.
        assert _offers_bounty(
            {"summary": "$150 - $7,500", "minReward": "$150", "maxReward": "$7,500"}
        ) is True

    def test_offers_bounty_false_shapes(self):
        assert _offers_bounty({}) is False
        assert _offers_bounty({"max": 0}) is False
        assert _offers_bounty(None) is False
        assert _offers_bounty("nope") is False
        # points / VDP-style: no currency symbol -> not monetary
        assert _offers_bounty({"summary": "Points", "minReward": None, "maxReward": None}) is False

    def test_normalize_asset_type(self):
        assert normalize_asset_type("website") == "URL"
        assert normalize_asset_type("api") == "API"
        assert normalize_asset_type("android") == "MOBILE_ANDROID"
        assert normalize_asset_type("ios") == "MOBILE_IOS"
        assert normalize_asset_type(None) == "OTHER"


class TestTransformEngagement:
    def test_maps_fields(self):
        eng = {
            "name": "Acme BB",
            "briefUrl": "/engagements/acme-bb",
            "accessStatus": "open",
            "rewardSummary": {"max": 10000},
        }
        p = _transform_engagement(eng)
        assert p["handle"] == "acme-bb"
        assert p["name"] == "Acme BB"
        assert p["policy_url"] == "https://bugcrowd.com/engagements/acme-bb"
        assert p["submission_state"] == "open"
        assert p["offers_bounty"] is True
        assert p["id"] == "acme-bb"

    def test_offers_bounty_false_when_no_reward(self):
        p = _transform_engagement({"name": "VDP", "briefUrl": "/engagements/vdp", "rewardSummary": {}})
        assert p["offers_bounty"] is False

    @pytest.mark.parametrize("flag", ["isPrivate", "isDemo", "isBanned"])
    def test_skips_private_demo_banned(self, flag):
        eng = {"name": "X", "briefUrl": "/engagements/x", flag: True}
        assert _transform_engagement(eng) is None

    def test_skips_when_no_handle(self):
        assert _transform_engagement({"name": "X", "briefUrl": ""}) is None


class TestListPrograms:
    def _page(self, engagements, total, limit=24):
        return {"engagements": engagements, "paginationMeta": {"limit": limit, "totalCount": total}}

    def test_paginates_and_filters(self):
        # 2 pages of 2; one private entry is filtered out.
        page1 = self._page([
            {"name": "A", "briefUrl": "/engagements/a", "rewardSummary": {"max": 1}},
            {"name": "B", "briefUrl": "/engagements/b", "isPrivate": True},
        ], total=4, limit=2)
        page2 = self._page([
            {"name": "C", "briefUrl": "/engagements/c", "rewardSummary": {}},
            {"name": "D", "briefUrl": "/engagements/d", "rewardSummary": {"currency": "USD"}},
        ], total=4, limit=2)

        client = BugcrowdClient(page_sleep=0)
        with patch.object(client, "_get", side_effect=[page1, page2]) as mget:
            programs = client.list_programs()
        client.close()

        handles = [p["handle"] for p in programs]
        assert handles == ["a", "c", "d"]  # b (private) filtered
        assert mget.call_count == 2
        # 1-indexed pages
        assert mget.call_args_list[0].kwargs["params"]["page"] == 1
        assert mget.call_args_list[1].kwargs["params"]["page"] == 2

    def test_stops_on_short_page(self):
        page = self._page([
            {"name": "A", "briefUrl": "/engagements/a", "rewardSummary": {}},
        ], total=99, limit=24)  # only 1 < limit -> last page
        client = BugcrowdClient(page_sleep=0)
        with patch.object(client, "_get", side_effect=[page]) as mget:
            programs = client.list_programs()
        client.close()
        assert len(programs) == 1
        assert mget.call_count == 1


class TestAuthAndScope:
    def test_unauthenticated_by_default(self, monkeypatch):
        monkeypatch.delenv("BUGCROWD_TOKEN", raising=False)
        monkeypatch.delenv("BUGCROWD_SESSION", raising=False)
        client = BugcrowdClient(page_sleep=0)
        assert client.authenticated is False
        with pytest.raises(BugcrowdError):
            client.get_program_scope("acme-bb")
        client.close()

    def test_token_sets_authenticated(self, monkeypatch):
        monkeypatch.setenv("BUGCROWD_TOKEN", "secret")
        client = BugcrowdClient(page_sleep=0)
        assert client.authenticated is True
        # token must be sent as a bearer, never leaked elsewhere
        assert client._client.headers.get("Authorization") == "Bearer secret"
        client.close()

    def test_session_sets_cookie(self, monkeypatch):
        monkeypatch.delenv("BUGCROWD_TOKEN", raising=False)
        monkeypatch.setenv("BUGCROWD_SESSION", "abc123")
        client = BugcrowdClient(page_sleep=0)
        assert client.authenticated is True
        assert "_bugcrowd_session=abc123" in client._client.headers.get("Cookie", "")
        client.close()

    def test_scope_parses_target_groups(self, monkeypatch):
        monkeypatch.setenv("BUGCROWD_TOKEN", "secret")
        client = BugcrowdClient(page_sleep=0)
        data = {"groups": [{
            "name": "Web", "in_scope": True,
            "targets": [
                {"uri": "https://acme.com", "category": "website"},
                {"name": "com.acme.app", "category": "android"},
            ],
        }]}
        with patch.object(client, "_get", return_value=data):
            scope = client.get_program_scope("acme-bb")
        client.close()
        assert {s["asset_identifier"] for s in scope} == {"https://acme.com", "com.acme.app"}
        assert all(s["eligible_for_submission"] for s in scope)
