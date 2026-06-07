"""Tests that the SQLite layer treats 'bugcrowd' as a first-class source."""

import pytest

from strix_cli_claude import db


@pytest.fixture
def temp_db(tmp_path, monkeypatch):
    """Point the db module at an isolated SQLite file and init the schema."""
    d = tmp_path / ".strix"
    d.mkdir()
    monkeypatch.setattr(db, "DB_DIR", d)
    monkeypatch.setattr(db, "DB_PATH", d / "strix.db")
    db.init_db()
    return d


class TestBugcrowdSource:
    def test_bugcrowd_in_valid_sources(self):
        assert "bugcrowd" in db.VALID_SOURCES

    def test_upsert_and_list_program(self, temp_db):
        with db.get_conn() as conn:
            db.upsert_program(
                conn, handle="acme-bb", name="Acme BB",
                policy_url="https://bugcrowd.com/engagements/acme-bb",
                offers_bounty=True, submission_state="open", source="bugcrowd",
            )
        progs = db.list_programs(source="bugcrowd")
        assert len(progs) == 1
        assert progs[0]["handle"] == "acme-bb"
        assert progs[0]["source"] == "bugcrowd"
        assert progs[0]["offers_bounty"] == 1
        # source-agnostic listing includes it
        assert any(p["handle"] == "acme-bb" for p in db.list_programs())

    def test_upsert_is_idempotent(self, temp_db):
        for _ in range(3):
            with db.get_conn() as conn:
                db.upsert_program(
                    conn, handle="acme-bb", name="Acme BB", policy_url=None,
                    offers_bounty=False, source="bugcrowd",
                )
        assert len(db.list_programs(source="bugcrowd")) == 1

    def test_sources_are_isolated(self, temp_db):
        with db.get_conn() as conn:
            db.upsert_program(conn, handle="dup", name="BC", policy_url=None,
                              offers_bounty=True, source="bugcrowd")
            db.upsert_program(conn, handle="dup", name="IT", policy_url=None,
                              offers_bounty=True, source="intigriti")
        assert len(db.list_programs(source="bugcrowd")) == 1
        assert len(db.list_programs(source="intigriti")) == 1
        # same handle, different source -> both kept (PK is (source, handle))
        dups = [p for p in db.list_programs() if p["handle"] == "dup"]
        assert len(dups) == 2
        assert {p["source"] for p in dups} == {"bugcrowd", "intigriti"}

    def test_mark_archived_except(self, temp_db):
        with db.get_conn() as conn:
            for h in ("a", "b", "c"):
                db.upsert_program(conn, handle=h, name=h, policy_url=None,
                                  offers_bounty=True, source="bugcrowd")
        db.mark_programs_archived_except(["a", "b"], source="bugcrowd")
        live = {p["handle"] for p in db.list_programs(source="bugcrowd")}
        assert live == {"a", "b"}  # c archived (excluded from list)

    def test_targets_and_counts(self, temp_db):
        with db.get_conn() as conn:
            db.upsert_program(conn, handle="acme-bb", name="Acme", policy_url=None,
                              offers_bounty=True, source="bugcrowd")
            db.upsert_target(conn, program_handle="acme-bb", asset_type="URL",
                             identifier="https://acme.com", eligible_for_bounty=True,
                             max_severity=None, instruction=None, source="bugcrowd")
        counts = db.scan_status_counts(source="bugcrowd")
        assert counts.get("pending") == 1
        summary = db.scope_summary(source="bugcrowd")
        assert any(r["program_handle"] == "acme-bb" for r in summary)
