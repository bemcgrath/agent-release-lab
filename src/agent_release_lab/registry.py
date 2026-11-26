"""SQLite registries for immutable Phase 1 records and evidence artifacts."""

import sqlite3
from collections.abc import Iterator
from contextlib import closing, contextmanager
from pathlib import Path

from .comparison import ManifestComparison, compare_manifests
from .evidence import EvaluationSuite, Evidence, EvidenceMismatch, verify_evidence
from .identity import sha256
from .manifests import Manifest


class RecordConflict(ValueError):
    """The registry key is already bound to a different record."""


class RecordMissing(LookupError):
    """The registry has no record with the requested identity."""


class RecordIntegrityError(EvidenceMismatch):
    """Stored evidence metadata differs from its registration fingerprint."""


class Registry:
    def __init__(self, path: str | Path):
        if str(path) in {"", ":memory:"}:
            raise ValueError("Provide a SQLite file path")
        self.path = Path(path).resolve()
        with self._connect() as connection:
            connection.executescript("""
                BEGIN IMMEDIATE;
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
                    artifact BLOB NOT NULL,
                    record_fingerprint TEXT NOT NULL
                );
            """)
            columns = {column[1] for column in connection.execute("PRAGMA table_info(evidence)")}
            if "record_fingerprint" not in columns:
                connection.execute("ALTER TABLE evidence ADD COLUMN record_fingerprint TEXT")

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute("PRAGMA foreign_keys = ON")
            yield connection

    @contextmanager
    def transaction(self, *, write: bool = False) -> Iterator[sqlite3.Connection]:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
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

    def register_evidence(self, evidence: Evidence, artifact: bytes) -> str:
        evidence = Evidence.from_json(evidence.canonical_bytes())
        candidate = self.get_manifest(evidence.candidate_fingerprint)
        suite = self.get_suite(evidence.suite_fingerprint)
        verify_evidence(evidence, candidate_fingerprint=candidate.fingerprint, suite=suite, artifact=artifact)
        payload = evidence.canonical_bytes()
        fingerprint = sha256(payload)
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO evidence VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING",
                (evidence.id, evidence.candidate_fingerprint, evidence.suite_fingerprint,
                 payload, artifact, fingerprint),
            )
            stored = connection.execute(
                "SELECT payload, artifact, record_fingerprint FROM evidence WHERE id = ?", (evidence.id,)
            ).fetchone()
            if stored != (payload, artifact, fingerprint):
                raise RecordConflict(f"Evidence ID {evidence.id} already exists")
        return fingerprint

    def get_evidence(self, evidence_id: str) -> tuple[Evidence, bytes]:
        evidence, artifact = self._read_evidence(evidence_id)
        self._verify_binding(evidence, artifact, evidence.candidate_fingerprint, evidence.suite_fingerprint)
        return evidence, artifact

    def get_verified_evidence(
        self, evidence_id: str, *, candidate_fingerprint: str, suite_fingerprint: str,
        expected_record_fingerprint: str | None = None,
    ) -> tuple[Evidence, bytes]:
        evidence, artifact = self._read_evidence(evidence_id)
        if expected_record_fingerprint is not None and evidence.fingerprint != expected_record_fingerprint:
            raise EvidenceMismatch("Evidence record does not match the expected fingerprint")
        self._verify_binding(evidence, artifact, candidate_fingerprint, suite_fingerprint)
        return evidence, artifact

    def _read_evidence(self, evidence_id: str) -> tuple[Evidence, bytes]:
        with self._connect() as connection:
            row = connection.execute(
                """SELECT payload, artifact, record_fingerprint, candidate_fingerprint, suite_fingerprint
                   FROM evidence WHERE id = ?""", (evidence_id,)
            ).fetchone()
        if row is None:
            raise RecordMissing(f"Unknown evidence {evidence_id}")
        payload, artifact, fingerprint, candidate, suite = row
        if fingerprint is None:
            raise RecordIntegrityError("Legacy evidence has no registration fingerprint")
        if not isinstance(payload, bytes) or sha256(payload) != fingerprint:
            raise RecordIntegrityError("Stored evidence record fingerprint mismatch")
        if not isinstance(artifact, bytes):
            raise RecordIntegrityError("Stored evidence artifact is not binary")
        try:
            evidence = Evidence.from_json(payload)
        except ValueError as error:
            raise RecordIntegrityError("Stored evidence record is invalid") from error
        if (evidence.fingerprint, evidence.id, evidence.candidate_fingerprint, evidence.suite_fingerprint) != (
            fingerprint, evidence_id, candidate, suite
        ):
            raise RecordIntegrityError("Stored evidence metadata differs from its registry entry")
        return evidence, artifact

    def _verify_binding(
        self, evidence: Evidence, artifact: bytes, candidate_fingerprint: str, suite_fingerprint: str
    ) -> None:
        candidate = self.get_manifest(candidate_fingerprint)
        suite = self.get_suite(suite_fingerprint)
        verify_evidence(evidence, candidate_fingerprint=candidate.fingerprint, suite=suite, artifact=artifact)

    def compare(self, baseline_fingerprint: str, candidate_fingerprint: str) -> ManifestComparison:
        return compare_manifests(
            self.get_manifest(baseline_fingerprint), self.get_manifest(candidate_fingerprint)
        )
