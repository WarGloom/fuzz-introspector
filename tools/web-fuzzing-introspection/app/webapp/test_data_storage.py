import os

from webapp import data_storage


def test_retrieve_functions_rejects_traversal_project(tmp_path, monkeypatch):
    monkeypatch.setattr(data_storage, "DB_ROOT", str(tmp_path.resolve()))

    assert data_storage.retrieve_functions("../outside", False) == []
    assert data_storage.retrieve_functions("project/name", True) == []


def test_project_reports_reject_traversal_project(tmp_path, monkeypatch):
    monkeypatch.setattr(data_storage, "DB_ROOT", str(tmp_path.resolve()))

    assert data_storage.get_project_debug_report("../outside") is None
    assert data_storage.get_project_branch_blockers("project/name") == []


def test_db_path_stays_under_db_root(tmp_path, monkeypatch):
    db_root = str(tmp_path.resolve())
    monkeypatch.setattr(data_storage, "DB_ROOT", db_root)

    db_path = data_storage._db_path("db-projects", "curl", "debug_report.json")

    assert os.path.commonpath([db_root, db_path]) == db_root
    assert db_path.endswith(
        os.path.join("db-projects", "curl", "debug_report.json"))
