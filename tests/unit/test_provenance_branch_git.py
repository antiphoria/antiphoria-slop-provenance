"""Tests for shared main-branch provenance git helpers."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import pygit2

from src.adapters.catalog import CatalogAdapter, _CATALOG_RELATIVE_PATH
from src.adapters.ots_queue import OtsQueueAdapter, _QUEUE_RELATIVE_PATH
from src.git_tree_utils import ensure_branch_exists, resolve_branch_init_parent, tree_get_blob


class ProvenanceBranchGitTest(unittest.TestCase):
    def test_init_main_from_master_preserves_provenance_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir)
            repo = pygit2.init_repository(str(repo_path), initial_head="master")
            sig = pygit2.Signature("Test", "test@example.com")

            catalog_line = json.dumps({"requestId": "a", "title": "Old"}, sort_keys=True)
            ots_line = json.dumps({"event": "pending", "request_id": "a"}, sort_keys=True)
            provenance_tb = repo.TreeBuilder()
            provenance_tb.insert(
                "catalog.jsonl",
                repo.create_blob((catalog_line + "\n").encode("utf-8")),
                pygit2.GIT_FILEMODE_BLOB,
            )
            provenance_tb.insert(
                "ots-queue.jsonl",
                repo.create_blob((ots_line + "\n").encode("utf-8")),
                pygit2.GIT_FILEMODE_BLOB,
            )
            root_tb = repo.TreeBuilder()
            root_tb.insert(".provenance", provenance_tb.write(), pygit2.GIT_FILEMODE_TREE)
            tree_oid = root_tb.write()
            repo.create_commit("refs/heads/master", sig, sig, "seed master", tree_oid, [])

            parent_ids, tree_oid = resolve_branch_init_parent(repo, "refs/heads/main")
            self.assertEqual(len(parent_ids), 1)
            repo.create_commit(
                "refs/heads/main",
                sig,
                sig,
                "init main from master",
                tree_oid,
                parent_ids,
            )

            main_commit = repo.lookup_reference("refs/heads/main").peel(pygit2.Commit)
            catalog_blob = tree_get_blob(repo, main_commit.tree, _CATALOG_RELATIVE_PATH)
            ots_blob = tree_get_blob(repo, main_commit.tree, _QUEUE_RELATIVE_PATH)
            self.assertIsNotNone(catalog_blob)
            self.assertIsNotNone(ots_blob)

    def test_catalog_upsert_syncs_worktree_and_clean_status(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir)
            repo = pygit2.init_repository(str(repo_path), initial_head="main")
            sig = pygit2.Signature("Test", "test@example.com")
            repo.create_commit("refs/heads/main", sig, sig, "empty main", repo.TreeBuilder().write(), [])

            catalog_path = repo_path / ".provenance" / "catalog.jsonl"
            catalog_path.parent.mkdir(parents=True, exist_ok=True)
            stale_line = json.dumps({"requestId": "stale", "title": "old"}, sort_keys=True)
            catalog_path.write_text(stale_line + "\n", encoding="utf-8")
            repo.index.add(".provenance/catalog.jsonl")
            repo.index.write()

            adapter = CatalogAdapter(repository_path=repo_path)
            adapter.upsert_entry(
                {
                    "requestId": "2495a2ca-3f14-4d24-afb8-ef454c830597",
                    "title": "Human story",
                    "timestamp": "2026-06-10T00:00:00+00:00",
                    "source": "human",
                }
            )

            repo = pygit2.Repository(str(repo_path))
            self.assertTrue(catalog_path.is_file())
            self.assertIn("Human story", catalog_path.read_text(encoding="utf-8"))
            self.assertEqual(len(list(repo.status())), 0)

    def test_ots_append_syncs_worktree_and_clean_status(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir)
            repo = pygit2.init_repository(str(repo_path), initial_head="main")
            sig = pygit2.Signature("Test", "test@example.com")
            repo.create_commit("refs/heads/main", sig, sig, "empty main", repo.TreeBuilder().write(), [])

            adapter = OtsQueueAdapter(repository_path=repo_path)
            adapter.append_pending(
                request_id="2495a2ca-3f14-4d24-afb8-ef454c830597",
                artifact_hash="a" * 64,
                pending_ots_b64="b64",
            )

            queue_path = repo_path / ".provenance" / "ots-queue.jsonl"
            self.assertTrue(queue_path.is_file())
            repo = pygit2.Repository(str(repo_path))
            self.assertEqual(len(list(repo.status())), 0)

    def test_catalog_upsert_preserves_ots_queue_on_main(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir)
            repo = pygit2.init_repository(str(repo_path), initial_head="main")
            sig = pygit2.Signature("Test", "test@example.com")

            ots_line = json.dumps({"event": "pending", "request_id": "x"}, sort_keys=True)
            provenance_tb = repo.TreeBuilder()
            provenance_tb.insert(
                "ots-queue.jsonl",
                repo.create_blob((ots_line + "\n").encode("utf-8")),
                pygit2.GIT_FILEMODE_BLOB,
            )
            root_tb = repo.TreeBuilder()
            root_tb.insert(".provenance", provenance_tb.write(), pygit2.GIT_FILEMODE_TREE)
            tree_oid = root_tb.write()
            repo.create_commit("refs/heads/main", sig, sig, "seed main", tree_oid, [])

            adapter = CatalogAdapter(repository_path=repo_path)
            adapter.upsert_entry(
                {
                    "requestId": "2495a2ca-3f14-4d24-afb8-ef454c830597",
                    "title": "Human story",
                    "timestamp": "2026-06-10T00:00:00+00:00",
                    "source": "human",
                }
            )

            repo = pygit2.Repository(str(repo_path))
            main_commit = repo.lookup_reference("refs/heads/main").peel(pygit2.Commit)
            self.assertIsNotNone(
                tree_get_blob(repo, main_commit.tree, _CATALOG_RELATIVE_PATH)
            )
            ots_blob = tree_get_blob(repo, main_commit.tree, _QUEUE_RELATIVE_PATH)
            self.assertIsNotNone(ots_blob)
            self.assertIn("pending", bytes(ots_blob.data).decode("utf-8"))

    def test_ots_append_preserves_catalog_on_main(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir)
            repo = pygit2.init_repository(str(repo_path), initial_head="main")
            sig = pygit2.Signature("Test", "test@example.com")

            catalog_line = json.dumps({"requestId": "a", "title": "Keep me"}, sort_keys=True)
            provenance_tb = repo.TreeBuilder()
            provenance_tb.insert(
                "catalog.jsonl",
                repo.create_blob((catalog_line + "\n").encode("utf-8")),
                pygit2.GIT_FILEMODE_BLOB,
            )
            root_tb = repo.TreeBuilder()
            root_tb.insert(".provenance", provenance_tb.write(), pygit2.GIT_FILEMODE_TREE)
            tree_oid = root_tb.write()
            repo.create_commit("refs/heads/main", sig, sig, "seed main", tree_oid, [])

            adapter = OtsQueueAdapter(repository_path=repo_path)
            adapter.append_pending(
                request_id="2495a2ca-3f14-4d24-afb8-ef454c830597",
                artifact_hash="a" * 64,
                pending_ots_b64="b64",
            )

            repo = pygit2.Repository(str(repo_path))
            main_commit = repo.lookup_reference("refs/heads/main").peel(pygit2.Commit)
            catalog_blob = tree_get_blob(repo, main_commit.tree, _CATALOG_RELATIVE_PATH)
            self.assertIsNotNone(catalog_blob)
            self.assertIn("Keep me", bytes(catalog_blob.data).decode("utf-8"))
            self.assertIsNotNone(
                tree_get_blob(repo, main_commit.tree, _QUEUE_RELATIVE_PATH)
            )

    def test_init_main_from_artifact_branch_uses_empty_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir)
            repo = pygit2.init_repository(str(repo_path), initial_head="main")
            sig = pygit2.Signature("Test", "test@example.com")
            request_id = "63185740-73df-46c7-9d09-28cb2b1d4441"
            artifact_ref = f"refs/heads/artifact/{request_id}"

            root_tb = repo.TreeBuilder()
            root_tb.insert(
                f"{request_id}.md",
                repo.create_blob(b"# artifact body\n"),
                pygit2.GIT_FILEMODE_BLOB,
            )
            root_tb.insert(
                f"{request_id}.c2pa",
                repo.create_blob(b"fake-c2pa"),
                pygit2.GIT_FILEMODE_BLOB,
            )
            tree_oid = root_tb.write()
            repo.create_commit(artifact_ref, sig, sig, "ledger: notarize", tree_oid, [])
            repo.references["HEAD"].set_target(artifact_ref)

            created = ensure_branch_exists(
                repo,
                "refs/heads/main",
                sig,
                "provenance: init catalog branch",
            )
            self.assertTrue(created)

            main_commit = repo.lookup_reference("refs/heads/main").peel(pygit2.Commit)
            self.assertEqual(len(main_commit.tree), 0)
            self.assertIsNone(tree_get_blob(repo, main_commit.tree, f"{request_id}.md"))

    def test_catalog_upsert_after_artifact_register_does_not_copy_artifact_blobs(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir)
            repo = pygit2.init_repository(str(repo_path), initial_head="main")
            sig = pygit2.Signature("Test", "test@example.com")
            request_id = "c0017dfb-1e2d-4eb0-b012-0530f0d3af80"
            artifact_ref = f"refs/heads/artifact/{request_id}"

            root_tb = repo.TreeBuilder()
            root_tb.insert(
                f"{request_id}.md",
                repo.create_blob(b"synthetic body\n"),
                pygit2.GIT_FILEMODE_BLOB,
            )
            tree_oid = root_tb.write()
            repo.create_commit(artifact_ref, sig, sig, "ledger: seal", tree_oid, [])

            adapter = CatalogAdapter(repository_path=repo_path)
            adapter.upsert_entry(
                {
                    "requestId": request_id,
                    "title": "Seal ceremony test",
                    "timestamp": "2026-06-10T00:00:00+00:00",
                    "source": "synthetic",
                }
            )

            repo = pygit2.Repository(str(repo_path))
            main_commit = repo.lookup_reference("refs/heads/main").peel(pygit2.Commit)
            self.assertIsNotNone(
                tree_get_blob(repo, main_commit.tree, _CATALOG_RELATIVE_PATH)
            )
            self.assertIsNone(tree_get_blob(repo, main_commit.tree, f"{request_id}.md"))


if __name__ == "__main__":
    unittest.main()
