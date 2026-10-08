"""Private durable replay state; no service startup, dispatch or admission.

ADAPT sfos-public 0dca6bd7 / blob 69c7aad8ed4f0e825ff52b8bc2bb761c5da11fcb:
retain bounded SQLite FULL transactions and signed receipt CAS. Reject the
donor's permission repair, unverified recovery, socket management and startup.
The caller supplies independently bound current target/generation expectations.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
import types
from pathlib import Path
from urllib.parse import quote
from datetime import timedelta
from uuid import NAMESPACE_URL, uuid5

CONTRACT_PATH = Path('/usr/lib/serein/kernel/replay_store.py')
CONTRACT_SHA256 = 'ddb9a320bb5955f648c18b6c2a5c445ab4f10d5f79f544ce4f3eccbcee40c48f'


def canonical_request_id(value):
    # Same bounded request identifier contract as the recorded donor road.
    if (not isinstance(value, str) or not value or len(value) > 128 or value != value.strip()
            or any(ord(char) < 0x20 or ord(char) > 0x7e for char in value)):
        raise ValueError('request id invalid')
    return value


def _contract_bytes():
    """Execute only captured bytes of the existing pinned runtime contract."""
    path = CONTRACT_PATH
    handles = []
    try:
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        handles.append(fd)
        for part in path.parts[1:-1]:
            fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            handles.append(fd)
        file_fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(file_fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or before.st_uid != 0 or before.st_gid != 0
                    or stat.S_IMODE(before.st_mode) != 0o644 or before.st_size > 65536):
                raise ValueError('replay contract custody denied')
            raw = stream.read(65537)
            after = os.fstat(stream.fileno())
            named = os.stat(path.name, dir_fd=fd, follow_symlinks=False)
            def identity(info):
                return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                        info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
            if (identity(before) != identity(after) or identity(before) != identity(named)
                    or len(raw) != before.st_size or hashlib.sha256(raw).hexdigest() != CONTRACT_SHA256):
                raise ValueError('replay contract source denied')
            return raw, identity(before)
    finally:
        for fd in reversed(handles): os.close(fd)


class PersistentReplayStore:
    TABLE_SQL = ('CREATE TABLE receipts('
        'chain_id TEXT NOT NULL,revision INTEGER NOT NULL,'
        'receipt_sha256 TEXT NOT NULL UNIQUE,canonical_json BLOB NOT NULL,'
        'PRIMARY KEY(chain_id, revision))')
    DISPATCH_SQL = ('CREATE TABLE dispatches('
        'chain_id TEXT PRIMARY KEY NOT NULL,binding BLOB NOT NULL,outcome BLOB)')

    def __init__(self, path, *, descriptor, key, expected_target, expected_generation,
                 input_guard=None, conversation_context=None):
        self.path = Path(path)
        self.connection = None
        self._parent_fd = None
        if input_guard is not None and not callable(input_guard):
            raise ValueError('replay input guard denied')
        self._input_guard = input_guard
        self._conversation_context = None
        if conversation_context is not None:
            fields={'source_generation','policy_sha256','plan_sha256','canonical_manifest_digest',
                    'kernel_instance','identity_checkpoint','boot_id'}
            if (not callable(input_guard) or not isinstance(conversation_context,dict)
                    or set(conversation_context)!=fields):
                raise ValueError('installed conversation context denied')
            self._conversation_context=json.loads(json.dumps(conversation_context,allow_nan=False))
        if not self.path.is_absolute() or '..' in self.path.parts:
            raise ValueError('replay path denied')
        if not isinstance(key, bytes) or len(key) != 32:
            raise ValueError('replay key denied')
        self._contract_prestate = _contract_bytes()
        self.contract = types.ModuleType('_bound_replay_contract')
        exec(compile(self._contract_prestate[0], str(CONTRACT_PATH), 'exec'), self.contract.__dict__)
        body = descriptor['body']
        self.contract.verify_descriptor(descriptor, key=key,
            expected_store_id=body['store_id'], expected_backend_identity='SEREIN_KERNEL_REPLAY',
            expected_issuer='KERNEL_AUTHORITY', expected_observer='OUTPOST',
            expected_key_fingerprint=hashlib.sha256(key).hexdigest(),
            expected_key_receipt=body['trusted_key_receipt'],
            expected_target=expected_target, expected_generation=expected_generation)
        # Capture caller-owned mutable inputs; later caller changes are not authority.
        self.descriptor = json.loads(self.contract.canonical_bytes(descriptor))
        self.key = key

    @staticmethod
    def _identity(info):
        return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode)

    def _stable(self):
        self._inputs_current()
        self._custody_stable()
        if _contract_bytes() != self._contract_prestate:
            raise ValueError('replay custody changed')

    def _inputs_current(self):
        # Trusted owning code supplies this check; no request can select it.
        if self._input_guard is not None:
            self._input_guard()

    def _custody_stable(self):
        parent = os.fstat(self._parent_fd)
        named_parent = self.path.parent.stat(follow_symlinks=False)
        named = os.stat(self.path.name, dir_fd=self._parent_fd, follow_symlinks=False)
        if (self._identity(parent) != self._parent_identity
                or self._identity(named_parent) != self._parent_identity
                or self._identity(named) != self._database_identity
                or named.st_nlink != 1):
            raise ValueError('replay custody changed')

    def _no_recovery_artifacts(self):
        for suffix in ('-journal', '-wal', '-shm'):
            try:
                os.stat(self.path.name + suffix, dir_fd=self._parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise ValueError('replay recovery artifact requires separate recovery')

    def _schema(self):
        expected = {('table', 'receipts', 'receipts', self.TABLE_SQL),
                    ('index', 'sqlite_autoindex_receipts_1', 'receipts', None),
                    ('index', 'sqlite_autoindex_receipts_2', 'receipts', None),
                    ('table', 'dispatches', 'dispatches', self.DISPATCH_SQL),
                    ('index', 'sqlite_autoindex_dispatches_1', 'dispatches', None)}
        if set(self.connection.execute('SELECT type,name,tbl_name,sql FROM sqlite_master')) != expected:
            raise ValueError('replay schema denied')

    def open(self, *, current_time, read_only=False):
        if type(read_only) is not bool:
            raise ValueError('replay read-only mode denied')
        if self.connection is not None:
            raise ValueError('replay store already open')
        created = False
        try:
            self._inputs_current()
            fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            self._parent_fd = fd
            for part in self.path.parts[1:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd); fd = child; self._parent_fd = fd
            parent = os.fstat(fd)
            if parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) != 0o700:
                raise ValueError('private replay parent required')
            self._parent_identity = self._identity(parent)
            self._no_recovery_artifacts()
            if not read_only:
                try:
                    file_fd = os.open(self.path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                      0o600, dir_fd=fd)
                except FileExistsError:
                    pass
                else:
                    created = True
                    try: os.fsync(file_fd)
                    finally: os.close(file_fd)
                    os.fsync(fd)
            info = os.stat(self.path.name, dir_fd=fd, follow_symlinks=False)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600):
                raise ValueError('private replay database required')
            self._database_identity = self._identity(info)
            # The private parent anchors the SQLite connection. No URI query can
            # come from the filename; only one literal final component is allowed.
            uri = f'file:/proc/self/fd/{fd}/{quote(self.path.name, safe="")}?mode=rw'
            self._no_recovery_artifacts()
            if not created:
                # WAL is persistent in SQLite's file header even after clean
                # sidecar removal. This bounded store uses rollback journaling;
                # never convert an existing WAL generation during open.
                header_fd = os.open(self.path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    header = os.read(header_fd, 20)
                finally:
                    os.close(header_fd)
                if len(header) >= 20 and header[18:20] != b'\x01\x01':
                    raise ValueError('replay journal mode requires separate recovery')
                if read_only:
                    # A witness never creates a database or requests a writer
                    # transaction. Use SQLite's real read snapshot/locking,
                    # not immutable caching over a live writer's database.
                    self.connection = sqlite3.connect(uri.replace('?mode=rw','?mode=ro'),
                                                      uri=True, isolation_level=None)
                    self.connection.execute('BEGIN')
                    self._history(current_time=current_time)
                    self._stable(); self._no_recovery_artifacts()
                    self.connection.execute('COMMIT')
                    return
                # immutable read-only never recovers a journal or creates a
                # WAL/SHM file. Sidecars are an explicit separate recovery case.
                self.connection = sqlite3.connect(uri.replace('?mode=rw', '?mode=ro&immutable=1'),
                                                  uri=True, isolation_level=None)
                try:
                    self._history(current_time=current_time)
                    self._stable(); self._no_recovery_artifacts()
                finally:
                    self.connection.close(); self.connection = None
            self.connection = sqlite3.connect(uri, uri=True, isolation_level=None)
            self.connection.execute('PRAGMA synchronous=FULL')
            self.connection.execute('BEGIN IMMEDIATE')
            if created:
                self.connection.execute(self.TABLE_SQL)
                self.connection.execute(self.DISPATCH_SQL)
            self._schema()
            self._history(current_time=current_time)
            self._stable()
            self.connection.execute('COMMIT')
        except Exception:
            try:
                if self.connection is not None:
                    self.connection.close(); self.connection = None
                if created and hasattr(self, '_database_identity'):
                    # Compensate only this invocation's exact uncommitted creation.
                    # Existing databases and unrelated entries are never removed.
                    self._custody_stable(); self._no_recovery_artifacts()
                    os.unlink(self.path.name, dir_fd=self._parent_fd)
                    os.fsync(self._parent_fd)
            finally:
                self.close()
            raise

    def _history(self, *, current_time):
        self._schema()
        if self.connection.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise ValueError('replay database integrity denied')
        rows = self.connection.execute('SELECT chain_id,revision,receipt_sha256,canonical_json '
                                       'FROM receipts ORDER BY chain_id,revision LIMIT 4096').fetchall()
        if len(rows) >= 4096:
            raise ValueError('replay capacity exceeded')
        chains = {}
        used = 0
        for chain_id, revision, digest, raw in rows:
            if (not isinstance(raw, bytes) or len(raw) > 16384
                    or not isinstance(chain_id, str) or not chain_id or len(chain_id) > 128
                    or type(revision) is not int):
                raise ValueError('replay row malformed')
            used += len(raw)
            if used > 1048576:
                raise ValueError('replay capacity exceeded')
            receipt = json.loads(raw)
            if (self.contract.canonical_bytes(receipt) != raw or self.contract.receipt_hash(receipt) != digest
                    or type(receipt['body']['revision']) is not int
                    or receipt['body']['revision'] != revision
                    or receipt['body']['action_nonce'] != chain_id):
                raise ValueError('replay row integrity denied')
            chains.setdefault(chain_id, []).append(receipt)
        summary = self.contract.verify_stored_history(list(chains.values()), descriptor=self.descriptor,
                                        key=self.key, current_time=current_time)
        _, binding_bytes = self._bindings(chains)
        if used + binding_bytes > 1048576:
            raise ValueError('replay capacity exceeded')
        return chains, summary

    def _binding(self, binding, chain_id):
        if (isinstance(binding,dict) and binding.get('schema') == self.contract.CONVERSATION_BINDING_SCHEMA
                and self._conversation_context is not None):
            self._inputs_current()
            if any(binding.get(k)!=v for k,v in self._conversation_context.items()):
                raise ValueError('installed conversation context denied')
            return self.contract.verify_conversation_binding(binding,chain_id,
                descriptor=self.descriptor,
                expected_generation=self._conversation_context['source_generation'])
        return self.contract.verify_dispatch_binding(binding, chain_id, descriptor=self.descriptor)

    def _bindings(self, chains):
        rows = self.connection.execute('SELECT chain_id,binding,outcome FROM dispatches LIMIT 4096').fetchall()
        return self.contract.verify_dispatch_bindings(rows, chains, descriptor=self.descriptor, key=self.key,
            allow_conversation_history=self._conversation_context is not None)

    def recover(self, *, current_time=None, clock=None):
        if ((clock is None) == (current_time is None)
                or (clock is not None and not callable(clock))):
            raise ValueError('one recovery time source is required')
        self._stable(); self.connection.execute('BEGIN')
        try:
            if clock is not None:
                # BEGIN alone does not establish a SQLite read snapshot.
                # Sample time after the first read, so a concurrent valid
                # reservation cannot look newer than this observation.
                self.connection.execute('SELECT COUNT(*) FROM receipts').fetchone()
                current_time = clock()
            _, summary = self._history(current_time=current_time)
            self._stable(); self.connection.execute('COMMIT')
            return summary
        except Exception:
            if self.connection.in_transaction:
                self.connection.execute('ROLLBACK')
            raise

    def _insert(self, chain_id, receipt):
        raw = self.contract.canonical_bytes(receipt)
        count, used = self.connection.execute(
            'SELECT COUNT(*),COALESCE(SUM(length(canonical_json)),0) FROM receipts').fetchone()
        if len(raw) > 16384 or count + 1 >= 4096 or used + len(raw) > 1048576:
            raise ValueError('replay capacity exceeded')
        self.connection.execute('INSERT INTO receipts VALUES(?,?,?,?)',
            (chain_id, receipt['body']['revision'], self.contract.receipt_hash(receipt), raw))

    def initialize(self, receipt, *, current_time):
        self._stable(); self.connection.execute('BEGIN IMMEDIATE')
        try:
            chains, _ = self._history(current_time=current_time)
            self.contract.verify_lifecycle([receipt], descriptor=self.descriptor, key=self.key,
                             current_time=current_time, require_consumed=False)
            chain_id = receipt['body']['action_nonce']
            if chain_id in chains:
                raise ValueError('replay chain already exists')
            self._insert(chain_id, receipt)
            self._history(current_time=current_time)
            self._stable(); self.connection.execute('COMMIT')
            return {'chain_id': chain_id, 'receipt_sha256': self.contract.receipt_hash(receipt),
                    'authority_effect': 'NONE'}
        except Exception:
            if self.connection.in_transaction:
                self.connection.execute('ROLLBACK')
            raise

    def cas(self, *, chain_id, expected_hash, operation, receipt_id, at, current_time,
            result_sha256=None):
        self._stable(); self.connection.execute('BEGIN IMMEDIATE')
        try:
            chains, _ = self._history(current_time=current_time)
            values = chains.get(chain_id)
            if not values or self.contract.receipt_hash(values[-1]) != expected_hash:
                raise ValueError('CAS expected hash conflict')
            candidate = self.contract.transition(values[-1], expected_hash=expected_hash, operation=operation,
                                   receipt_id=receipt_id, at=at, key=self.key)
            self.contract.verify_lifecycle(values + [candidate], descriptor=self.descriptor, key=self.key,
                             current_time=current_time, require_consumed=False)
            bound = self.connection.execute('SELECT binding FROM dispatches WHERE chain_id=?', (chain_id,)).fetchone()
            if bound:
                if (operation != 'CONSUME' or not isinstance(result_sha256,str)
                        or not self.contract.HEX64.fullmatch(result_sha256)):
                    raise ValueError('dispatch result binding required')
                outcome = self.contract.signed({'schema':'SereinKernelDispatchOutcome/v1',
                    'chain_id':chain_id, 'binding_sha256':hashlib.sha256(bound[0]).hexdigest(),
                    'result_sha256':result_sha256, 'completed_at':at,
                    'authority_effect':'NONE', 'physical_effect':'UNVERIFIED'}, self.key)
                self.connection.execute('UPDATE dispatches SET outcome=? WHERE chain_id=?',
                                        (self.contract.canonical_bytes(outcome),chain_id))
            elif result_sha256 is not None:
                raise ValueError('dispatch binding absent')
            self._insert(chain_id, candidate)
            self._history(current_time=current_time)
            self._stable(); self.connection.execute('COMMIT')
            return candidate
        except Exception:
            if self.connection.in_transaction:
                self.connection.execute('ROLLBACK')
            raise

    def request_receipts(self, request_id, *, current_time):
        """Authenticated history, not authorization or a claim of execution."""
        request_id = canonical_request_id(request_id)
        chain_id = str(uuid5(NAMESPACE_URL, f'{request_id}:action'))
        self._stable(); self.connection.execute('BEGIN')
        try:
            chains, _ = self._history(current_time=current_time)
            values = chains.get(chain_id, [])
            self._stable(); self.connection.execute('COMMIT')
            return values
        except Exception:
            if self.connection.in_transaction:
                self.connection.execute('ROLLBACK')
            raise

    def reserve_request(self, *, request_id, at, expires_at, current_time, binding=None):
        """Adapt donor atomic two-row reservation, with explicit authority TTL.

        Use its deterministic action UUID consistently as the internal chain
        key; the donor mixed a request hash key with a different signed nonce.
        This is a local store API, not the donor's external socket protocol.
        Expired reservations remain evidence and never become reusable work.
        """
        request_id = canonical_request_id(request_id)
        observed = self.contract.utc(at)
        expiry = self.contract.utc(expires_at)
        now = self.contract.utc(current_time)
        if not observed <= now < expiry:
            raise ValueError('request reservation freshness denied')
        chain_id = str(uuid5(NAMESPACE_URL, f'{request_id}:action'))
        binding_raw = None
        if binding is not None:
            binding = json.loads(self.contract.canonical_bytes(binding))
            self._binding(binding, chain_id)
            if binding.get('schema') == self.contract.CONVERSATION_BINDING_SCHEMA:
                requested = self.contract.utc(binding['observed_at'])
                # Existing conversation freshness (120s / 5s future skew),
                # not a CP worker lease. This only bounds replay retention.
                if requested > now + timedelta(seconds=5) or expiry > requested + timedelta(seconds=120):
                    raise ValueError('conversation replay freshness denied')
            envelope = self.contract.signed({'schema':'SereinKernelDispatchBinding/v1',
                'chain_id':chain_id, 'binding':binding, 'authority_effect':'NONE'}, self.key)
            binding_raw = self.contract.canonical_bytes(envelope)
        unused = self.contract.make_unused(self.descriptor, key=self.key,
            receipt_id=str(uuid5(NAMESPACE_URL, f'{request_id}:unused')),
            run_id=str(uuid5(NAMESPACE_URL, f'{request_id}:run')), action_nonce=chain_id,
            observed_at=(observed-timedelta(microseconds=1)).isoformat().replace('+00:00','Z'),
            expires_at=expires_at, binding_sha256=(hashlib.sha256(binding_raw).hexdigest()
                                                  if binding_raw is not None else None))
        reserved = self.contract.transition(unused,
            expected_hash=self.contract.receipt_hash(unused), operation='RESERVE',
            receipt_id=str(uuid5(NAMESPACE_URL, f'{request_id}:reserve')), at=at, key=self.key)
        self._stable(); self.connection.execute('BEGIN IMMEDIATE')
        try:
            chains, _ = self._history(current_time=current_time)
            if chain_id in chains:
                raise ValueError('duplicate replay request')
            if binding is not None:
                existing, _ = self._bindings(chains)
                if binding.get('schema') != self.contract.CONVERSATION_BINDING_SCHEMA:
                    active = sum(row.get('schema') != self.contract.CONVERSATION_BINDING_SCHEMA
                                 and row['route'] == binding['route'] and len(chains[nonce]) == 2
                                 for nonce,row in existing.items())
                    # Generic route-capacity semantics are unchanged. Ordinary
                    # policy attempts carry no invented capacity authorization.
                    if active + binding['external_active_count'] >= binding['capacity']:
                        raise ValueError('dispatch route capacity reserved')
                self.connection.execute('INSERT INTO dispatches VALUES(?,?,NULL)',
                                        (chain_id,binding_raw))
            self.contract.verify_lifecycle([unused,reserved], descriptor=self.descriptor,
                key=self.key, current_time=current_time, require_consumed=False)
            self._insert(chain_id, unused); self._insert(chain_id, reserved)
            self._history(current_time=current_time)
            self._stable(); self.connection.execute('COMMIT')
            return chain_id, reserved
        except Exception:
            if self.connection.in_transaction:
                self.connection.execute('ROLLBACK')
            raise

    def dispatch_evidence(self, request_id, *, current_time):
        request_id = canonical_request_id(request_id)
        chain_id = str(uuid5(NAMESPACE_URL, f'{request_id}:action'))
        self._stable(); self.connection.execute('BEGIN')
        try:
            chains, _ = self._history(current_time=current_time)
            row = self.connection.execute('SELECT binding,outcome FROM dispatches WHERE chain_id=?',
                                          (chain_id,)).fetchone()
            result = None if row is None else {'binding':json.loads(row[0]),
                'outcome':None if row[1] is None else json.loads(row[1]), 'receipts':chains[chain_id]}
            self._stable(); self.connection.execute('COMMIT')
            return result
        except Exception:
            if self.connection.in_transaction:
                self.connection.execute('ROLLBACK')
            raise

    def consume_request(self, *, request_id, expected_hash, at, current_time, result_sha256=None):
        """Consume once before a caller's effect; consumption is not effect proof."""
        request_id = canonical_request_id(request_id)
        return self.cas(chain_id=str(uuid5(NAMESPACE_URL, f'{request_id}:action')),
            expected_hash=expected_hash, operation='CONSUME',
            receipt_id=str(uuid5(NAMESPACE_URL, f'{request_id}:consume')),
            at=at, current_time=current_time, result_sha256=result_sha256)

    def close(self):
        if self.connection is not None:
            self.connection.close(); self.connection = None
        if self._parent_fd is not None:
            os.close(self._parent_fd); self._parent_fd = None
