#!/usr/bin/env python3
"""Durable VM40.10 Stage-1 replay receipt store.

DNAv1 transfer: retain VM40.20's SQLite WAL/FULL, bounded capacity,
transactional append and fail-closed recovery behavior.  VM identity,
paths, keys and installed-generation assumptions are deliberately excluded.
The receipt and key contract is owned by the accepted VM40.10 Stage-1
Gateway. Legacy installed paths remain deliberate compatibility surfaces
while Stage-2 continues to coexist beside that Gateway.
"""

from __future__ import annotations

import json
import os
import socket
import sqlite3
import stat
import struct
import sys
import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from replay_store import (
    VersionedKeyLifecycle, canonical_bytes, make_unused, receipt_hash, transition, verify_lifecycle,
)


def secure_socket_parent(path: Path, *, owner_uid: int, gateway_gid: int) -> None:
    """Bind the private socket directory to replay ownership and Gateway traversal."""
    state = path.lstat()
    if not stat.S_ISDIR(state.st_mode) or path.is_symlink():
        raise ValueError("private replay socket parent is not a nofollow directory")
    initial = (state.st_uid, state.st_gid, stat.S_IMODE(state.st_mode))
    admitted_initial = {
        (owner_uid, os.getgid(), 0o750),
        (owner_uid, gateway_gid, 0o750),
    }
    if initial not in admitted_initial:
        raise ValueError("private replay socket parent prestate drift")
    os.chown(path, owner_uid, gateway_gid, follow_symlinks=False)
    os.chmod(path, 0o750, follow_symlinks=False)
    state = path.lstat()
    if (state.st_uid, state.st_gid, stat.S_IMODE(state.st_mode)) != (
        owner_uid, gateway_gid, 0o750,
    ):
        raise ValueError("private replay socket parent ownership readback failed")


class PersistentReplayStore:
    def __init__(self, path: str | Path, *, descriptor: dict, key: bytes,
                 max_receipts: int = 4096, max_store_bytes: int = 1_048_576,
                 max_receipt_bytes: int = 16_384, retention_seconds: int = 600):
        if min(max_receipts, max_store_bytes, max_receipt_bytes, retention_seconds) < 1:
            raise ValueError("replay store limits are invalid")
        self.path = Path(path)
        self.descriptor = descriptor
        self.key = key
        self.max_receipts = max_receipts
        self.max_store_bytes = max_store_bytes
        self.max_receipt_bytes = max_receipt_bytes
        self.retention_seconds = retention_seconds
        self.connection: sqlite3.Connection | None = None

    def open(self, *, current_time: str) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.path.parent, 0o700)
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("""CREATE TABLE IF NOT EXISTS receipts(
            chain_id TEXT NOT NULL,
            revision INTEGER NOT NULL,
            receipt_sha256 TEXT NOT NULL UNIQUE,
            canonical_json BLOB NOT NULL,
            PRIMARY KEY(chain_id, revision)
        )""")
        connection.commit()
        self.connection = connection
        self.recover(current_time=current_time)

    def close(self) -> None:
        if self.connection is not None:
            self.connection.close()
            self.connection = None

    def _require(self) -> sqlite3.Connection:
        if self.connection is None:
            raise RuntimeError("replay store is closed")
        return self.connection

    def receipts(self, chain_id: str | None = None) -> list[dict]:
        if chain_id is None:
            rows = self._require().execute(
                "SELECT chain_id,revision,receipt_sha256,canonical_json FROM receipts ORDER BY chain_id,revision"
            ).fetchall()
        else:
            rows = self._require().execute(
                "SELECT chain_id,revision,receipt_sha256,canonical_json FROM receipts WHERE chain_id=? ORDER BY revision",
                (chain_id,),
            ).fetchall()
        values = []
        expected_by_chain: dict[str, int] = {}
        for row in rows:
            expected = expected_by_chain.get(row["chain_id"], 0)
            if int(row["revision"]) != expected:
                raise ValueError("receipt revision continuity is broken")
            expected_by_chain[row["chain_id"]] = expected + 1
            value = json.loads(bytes(row["canonical_json"]))
            if receipt_hash(value) != row["receipt_sha256"]:
                raise ValueError("receipt hash integrity failed")
            values.append(value)
        return values

    def recover(self, *, current_time: str) -> dict | None:
        chain_ids = [row[0] for row in self._require().execute("SELECT DISTINCT chain_id FROM receipts")]
        results = []
        for chain_id in chain_ids:
            values = self.receipts(chain_id)
            validation_time = values[-1]["body"]["observed_at"] if len(values) == 3 else current_time
            results.append(verify_lifecycle(values, descriptor=self.descriptor, key=self.key,
                           current_time=validation_time, require_consumed=len(values) == 3))
        return {"chains": results} if results else None

    def initialize(self, receipt: dict, *, current_time: str) -> None:
        chain_id = receipt["body"]["action_nonce"]
        if self.receipts(chain_id):
            raise ValueError("replay store is already initialized")
        verify_lifecycle([receipt], descriptor=self.descriptor, key=self.key,
                         current_time=current_time, require_consumed=False)
        self._append(chain_id, receipt)

    def cas(self, *, chain_id: str | None = None, expected_hash: str, operation: str, receipt_id: str,
            at: str, current_time: str) -> dict:
        connection = self._require()
        try:
            connection.execute("BEGIN IMMEDIATE")
            if chain_id is None:
                ids=[row[0] for row in connection.execute("SELECT DISTINCT chain_id FROM receipts")]
                if len(ids)!=1: raise ValueError("chain id required")
                chain_id=ids[0]
            values = self.receipts(chain_id)
            if not values or receipt_hash(values[-1]) != expected_hash:
                raise ValueError("CAS expected hash conflict")
            candidate = transition(values[-1], expected_hash=expected_hash,
                                   operation=operation, receipt_id=receipt_id,
                                   at=at, key=self.key)
            verify_lifecycle(values + [candidate], descriptor=self.descriptor,
                             key=self.key, current_time=current_time,
                             require_consumed=len(values) + 1 == 3)
            self._insert(chain_id, candidate)
            connection.commit()
            return candidate
        except Exception:
            connection.rollback()
            raise

    def reserve_request(self, *, request_id: str, at: str, current_time: str) -> tuple[str, dict]:
        request_id = canonical_request_id(request_id)
        chain_id = hashlib.sha256(request_id.encode("utf-8")).hexdigest()
        connection = self._require()
        try:
            connection.execute("BEGIN IMMEDIATE")
            if self.receipts(chain_id):
                raise ValueError("duplicate replay request")
            observed = datetime.fromisoformat(at.replace("Z", "+00:00"))
            unused = make_unused(self.descriptor, key=self.key,
                receipt_id=str(uuid5(NAMESPACE_URL, f"{request_id}:unused")),
                run_id=str(uuid5(NAMESPACE_URL, f"{request_id}:run")),
                action_nonce=str(uuid5(NAMESPACE_URL, f"{request_id}:action")),
                observed_at=(observed-timedelta(microseconds=1)).isoformat().replace("+00:00","Z"),
                expires_at=(observed+timedelta(seconds=self.retention_seconds)).isoformat().replace("+00:00","Z"))
            reserved = transition(unused, expected_hash=receipt_hash(unused), operation="RESERVE",
                receipt_id=str(uuid5(NAMESPACE_URL, f"{request_id}:reserve")), at=at, key=self.key)
            verify_lifecycle([unused,reserved], descriptor=self.descriptor, key=self.key,
                             current_time=current_time, require_consumed=False)
            self._insert(chain_id, unused); self._insert(chain_id, reserved); connection.commit()
            return chain_id, reserved
        except Exception:
            connection.rollback(); raise

    def _append(self, chain_id: str, receipt: dict) -> None:
        connection = self._require()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._insert(chain_id, receipt)
            connection.commit()
        except Exception:
            connection.rollback()
            raise

    def _insert(self, chain_id: str, receipt: dict) -> None:
        encoded = canonical_bytes(receipt)
        if len(encoded) > self.max_receipt_bytes:
            raise ValueError("replay receipt size limit exceeded")
        connection = self._require()
        count, used = connection.execute(
            "SELECT COUNT(*),COALESCE(SUM(length(canonical_json)),0) FROM receipts"
        ).fetchone()
        if int(count) >= self.max_receipts or int(used) + len(encoded) > self.max_store_bytes:
            raise ValueError("replay store capacity exhausted")
        connection.execute(
            "INSERT INTO receipts(chain_id,revision,receipt_sha256,canonical_json) VALUES(?,?,?,?)",
            (chain_id, receipt["body"]["revision"], receipt_hash(receipt), encoded),
        )


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def canonical_request_id(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 128 or "\x00" in value \
            or value != value.strip() or any(ord(char) < 0x20 or ord(char) > 0x7e for char in value):
        raise ValueError("request id invalid")
    return value


def peer_is_allowed(connection: socket.socket, *, allowed_uid: int, allowed_gid: int) -> bool:
    peer_pid, peer_uid, peer_gid = struct.unpack(
        "3i", connection.getsockopt(socket.SOL_SOCKET, getattr(socket, "SO_PEERCRED", 17), 12)
    )
    del peer_pid
    return peer_uid == allowed_uid and peer_gid == allowed_gid


def secure_socket_path(socket_path: Path, *, owner_uid: int, gateway_gid: int) -> None:
    os.chown(socket_path, owner_uid, gateway_gid, follow_symlinks=False)
    os.chmod(socket_path, 0o660, follow_symlinks=False)
    state = socket_path.lstat()
    if (state.st_uid, state.st_gid, state.st_mode & 0o777) != (owner_uid, gateway_gid, 0o660):
        raise ValueError("private replay socket ownership readback failed")


def handle_connection(connection: socket.socket, *, store: PersistentReplayStore,
                      allowed_uid: int, allowed_gid: int,
                      current_time: str | None = None) -> None:
    if not peer_is_allowed(connection, allowed_uid=allowed_uid, allowed_gid=allowed_gid):
        connection.sendall(canonical_bytes({"ok": False, "error": "peer_denied"}))
        return
    request = connection.recv(16_385)
    if not request or len(request) > 16_384 or b"\x00" in request:
        response = {"ok": False, "error": "request_size_invalid"}
    else:
        try:
            value = json.loads(request)
            if not isinstance(value, dict) or value.get("operation") not in {
                "INITIALIZE", "WITNESS", "RESERVE", "CONSUME"
            }:
                raise ValueError("request schema invalid")
            operation = value["operation"]
            now = _utc_now() if current_time is None else current_time
            if operation == "WITNESS":
                if set(value) != {"operation", "request_id"}:
                    raise ValueError("request schema invalid")
                request_id = canonical_request_id(value["request_id"])
                chain_id = hashlib.sha256(request_id.encode("utf-8")).hexdigest()
                receipts = store.receipts(chain_id)
                response = {"ok": True, "chain_id": chain_id,
                            "receipt_sha256": receipt_hash(receipts[-1]) if receipts else None,
                            "state": receipts[-1]["body"]["state"] if receipts else "ABSENT",
                            "high_water": receipts[-1]["body"]["revision"] if receipts else None}
            elif operation == "INITIALIZE":
                if set(value) != {"operation", "receipt"}:
                    raise ValueError("request schema invalid")
                store.initialize(value["receipt"], current_time=now)
                response = {"ok": True, "receipt_sha256": receipt_hash(value["receipt"])}
            elif operation == "RESERVE":
                if set(value) != {"operation", "request_id", "at"}:
                    raise ValueError("request schema invalid")
                request_id = canonical_request_id(value["request_id"])
                chain_id, receipt = store.reserve_request(request_id=request_id, at=value["at"], current_time=now)
                response = {"ok": True, "chain_id": chain_id, "receipt_sha256": receipt_hash(receipt), "state":"RESERVED", "high_water":receipt["body"]["revision"]}
            else:
                if set(value) != {"expected_hash", "operation", "request_id", "chain_id", "at"}:
                    raise ValueError("request schema invalid")
                request_id = canonical_request_id(value["request_id"])
                expected_chain = hashlib.sha256(request_id.encode("utf-8")).hexdigest()
                if value["chain_id"] != expected_chain: raise ValueError("chain mismatch")
                receipt = store.cas(chain_id=expected_chain, expected_hash=value["expected_hash"], operation=operation,
                    receipt_id=str(uuid5(NAMESPACE_URL,f"{request_id}:consume")), at=value["at"], current_time=now)
                response = {"ok": True, "chain_id": expected_chain, "receipt_sha256": receipt_hash(receipt), "state":"CONSUMED", "high_water":receipt["body"]["revision"]}
        except (ValueError, TypeError, json.JSONDecodeError):
            response = {"ok": False, "error": "request_rejected"}
    connection.sendall(canonical_bytes(response))


def serve(*, database: Path, descriptor_path: Path, key_path: Path,
          socket_path: Path, allowed_peer_uid: int | None = None,
          allowed_peer_gid: int | None = None) -> None:
    descriptor = json.loads(descriptor_path.read_text(encoding="utf-8"))
    key = key_path.read_bytes()
    if len(key) != 32:
        raise ValueError("active replay key must be exactly 32 bytes")
    key_version = 1
    key_policy = VersionedKeyLifecycle(
        version=key_version, key=key,
        receipt_id=descriptor["body"]["trusted_key_receipt"],
    )
    if key_policy.receipt(key_version)["state"] != "ACTIVE":
        raise ValueError("active replay key receipt is invalid")
    # Multi-version rotate/revoked transitions are deliberately not selected by v3.
    store = PersistentReplayStore(database, descriptor=descriptor, key=key)
    store.open(current_time=_utc_now())
    socket_path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    secure_socket_parent(
        socket_path.parent,
        owner_uid=os.getuid(),
        gateway_gid=os.getgid() if allowed_peer_gid is None else allowed_peer_gid,
    )
    if socket_path.exists() or socket_path.is_symlink():
        raise ValueError("private replay socket path is not absent")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(str(socket_path))
        secure_socket_path(
            socket_path, owner_uid=os.getuid(),
            gateway_gid=os.getgid() if allowed_peer_gid is None else allowed_peer_gid,
        )
        server.listen(8)
        while True:
            connection, _ = server.accept()
            with connection:
                try:
                    handle_connection(
                        connection, store=store,
                        allowed_uid=os.getuid() if allowed_peer_uid is None else allowed_peer_uid,
                        allowed_gid=os.getgid() if allowed_peer_gid is None else allowed_peer_gid,
                    )
                except Exception:
                    try: connection.sendall(canonical_bytes({"ok":False,"error":"request_rejected"}))
                    except OSError: pass
    finally:
        server.close()
        store.close()
        if socket_path.exists() and not socket_path.is_symlink():
            socket_path.unlink()


if __name__ == "__main__":
    if len(sys.argv) != 7:
        raise SystemExit("usage: replay-store DATABASE DESCRIPTOR KEY SOCKET PEER_UID PEER_GID")
    serve(database=Path(sys.argv[1]), descriptor_path=Path(sys.argv[2]),
          key_path=Path(sys.argv[3]), socket_path=Path(sys.argv[4]),
          allowed_peer_uid=int(sys.argv[5]), allowed_peer_gid=int(sys.argv[6]))
