"""SQLite registries for immutable Phase 1 records and evidence artifacts."""

import sqlite3
from contextlib import closing, contextmanager
from collections.abc import Iterator
from pathlib import Path

from .comparison import ManifestComparison, compare_manifests
from .evidence import EvaluationSuite, Evidence, verify_evidence
from .identity import sha256
from .manifests import Manifest


class RecordConflict(ValueError):
    """The registry key is already bound to a different record."""


class RecordMissing(LookupError):
    """The registry has no record with the requested identity."""


class Registry:
    def __init__(self, path: str | Path):
        if str(path) in {"", ":memory:"}:
            raise ValueError("Provide a SQLite file path")
        self.path = path
        with self._connect() as connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS manifests (
                    fingerprint TEXT PRIMARY KEY NOT NULL,
                    payload BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS suites (
                    fingerprint TEXT PRIMARY KEY NOT NULL,
                    id TEXT NOT NULL,
                    revision TEXT NOT NULL,
                    payload BLOB NOT NULL,
                    UNIQUE (id, revision)
                );
                CREATE TABLE IF NOT EXISTS evidence (
                    id TEXT PRIMARY KEY NOT NULL,
                    candidate_fingerprint TEXT NOT NULL REFERENCES manifests(fingerprint),
                    suite_fingerprint TEXT NOT NULL REFERENCES suites(fingerprint),
                    payload BLOB NOT NULL,
                    artifact BLOB NOT NULL
                );
            """)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute("PRAGMA foreign_keys = ON")
            yield connection

    def register_manifest(self, manifest: Manifest) -> str:
        payload = Manifest.from_json(manifest.canonical_bytes()).canonical_bytes()
        fingerprint = sha256(payload)
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO manifests VALUES (?, ?) ON CONFLICT DO NOTHING", (fingerprint, payload)
            )
            stored = connection.execute(
                "SELECT payload FROM manifests WHERE fingerprint = ?", (fingerprint,)
            ).fetchone()
            if stored != (payload,):
                raise RecordConflict(f"Manifest conflict for {fingerprint}")
        return fingerprint

    def get_manifest(self, fingerprint: str) -> Manifest:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM manifests WHERE fingerprint = ?", (fingerprint,)
            ).fetchone()
        if row is None:
            raise RecordMissing(f"Unknown manifest {fingerprint}")
        manifest = Manifest.from_json(row[0])
        if manifest.fingerprint != fingerprint:
            raise RecordConflict(f"Stored manifest fingerprint differs from {fingerprint}")
        return manifest

    def register_suite(self, suite: EvaluationSuite) -> str:
        payload = EvaluationSuite.from_json(suite.canonical_bytes()).canonical_bytes()
        fingerprint = sha256(payload)
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO suites VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING",
                (fingerprint, suite.id, suite.revision, payload),
            )
            stored = connection.execute(
                "SELECT fingerprint, payload FROM suites WHERE id = ? AND revision = ?",
                (suite.id, suite.revision),
            ).fetchone()
            if stored != (fingerprint, payload):
                raise RecordConflict(f"Suite revision {suite.id}/{suite.revision} already exists")
        return fingerprint

    def get_suite(self, fingerprint: str) -> EvaluationSuite:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM suites WHERE fingerprint = ?", (fingerprint,)
            ).fetchone()
        if row is None:
            raise RecordMissing(f"Unknown suite {fingerprint}")
        suite = EvaluationSuite.from_json(row[0])
        if suite.fingerprint != fingerprint:
            raise RecordConflict(f"Stored suite fingerprint differs from {fingerprint}")
        return suite

    def register_evidence(self, evidence: Evidence, artifact: bytes) -> None:
        evidence = Evidence.from_json(evidence.canonical_bytes())
        candidate = self.get_manifest(evidence.candidate_fingerprint)
        suite = self.get_suite(evidence.suite_fingerprint)
        verify_evidence(evidence, candidate_fingerprint=candidate.fingerprint, suite=suite, artifact=artifact)
        payload = evidence.canonical_bytes()
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO evidence VALUES (?, ?, ?, ?, ?) ON CONFLICT DO NOTHING",
                (evidence.id, evidence.candidate_fingerprint, evidence.suite_fingerprint, payload, artifact),
            )
            stored = connection.execute(
                "SELECT payload, artifact FROM evidence WHERE id = ?", (evidence.id,)
            ).fetchone()
            if stored != (payload, artifact):
                raise RecordConflict(f"Evidence ID {evidence.id} already exists")

    def get_verified_evidence(
        self, evidence_id: str, *, candidate_fingerprint: str, suite_fingerprint: str
    ) -> tuple[Evidence, bytes]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload, artifact FROM evidence WHERE id = ?", (evidence_id,)
            ).fetchone()
        if row is None:
            raise RecordMissing(f"Unknown evidence {evidence_id}")
        evidence = Evidence.from_json(row[0])
        if evidence.id != evidence_id:
            raise RecordConflict(f"Stored evidence ID differs from {evidence_id}")
        candidate = self.get_manifest(candidate_fingerprint)
        suite = self.get_suite(suite_fingerprint)
        verify_evidence(evidence, candidate_fingerprint=candidate.fingerprint, suite=suite, artifact=row[1])
        return evidence, row[1]

    def compare(self, baseline_fingerprint: str, candidate_fingerprint: str) -> ManifestComparison:
        return compare_manifests(
            self.get_manifest(baseline_fingerprint), self.get_manifest(candidate_fingerprint)
        )
