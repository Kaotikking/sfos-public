"""Boot-bound replay observations for Kernel OPERATIONS.

Adapted from public 0dca6bd7. These observations do not establish scheduler
decisions, task-queue health, task-lease validity or recovery readiness.
Those responsibilities require their own evidence before Operations can pass.
"""
from __future__ import annotations

import hashlib
import http.client
import importlib.util
import json
import os
import pwd
import signal
import socket
import sqlite3
import ssl
import stat
import tempfile
import threading
import time
from datetime import datetime, timezone
from contextlib import contextmanager
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5
from urllib.parse import quote

SCHEMA = "SEREIN/KernelOperationsHeartbeat/v1"
# PRO-136 permits a faster bounded cadence. Schedule with headroom for real
# collection/wakeup jitter; acceptance still measures the exact 60-BPM floor.
INTERVAL_SECONDS = 0.5
HEARTBEAT_FLOOR_SECONDS = 1.0
MAX_RECEIPTS = 4096
REPLAY_CONTRACT = Path('/usr/lib/serein/kernel/replay_store.py')
REPLAY_CONTRACT_SHA256 = 'ddb9a320bb5955f648c18b6c2a5c445ab4f10d5f79f544ce4f3eccbcee40c48f'
VITALS_HOST = 'serein.sardonyxsapphire.us'
VITALS_PATH = '/v1/runtime/status'
VITALS_MAX_BYTES = 2 * 1024 * 1024
VITALS_TIMEOUT_SECONDS = 2.0
_VITALS_READ_SLOT = threading.Lock()

# PRO-136 / 4ae7de33: the evaluator produces telemetry only. The window is an
# explicit profile input, not a silently selected production default.
EXCLUDED_TASK_STATES = frozenset({
    "BLOCKED", "UNAUTHORIZED", "REVOKED", "STALE", "HELD", "SUPERSEDED",
    "DEPENDENCY_UNSATISFIED",
})


class SchedulerMetrics:
    """Bounded, non-mutating interpretation of an attributable queue snapshot.

    No task transitions, leases, dispatches or lanes are created here.
    Caller-provided snapshots require their own Authority/source verification;
    this metric cannot turn them into work or authority evidence.
    """

    def __init__(self, *, floor_bpm: int, window_length: int):
        if type(floor_bpm) is not int or floor_bpm < 60:
            raise OperationsDenied("SCHEDULER_FLOOR_DENIED")
        if type(window_length) is not int or not 1 <= window_length <= 4096:
            raise OperationsDenied("SCHEDULER_WINDOW_DENIED")
        self.floor_bpm = floor_bpm
        self.ceiling_ns = 60_000_000_000 // floor_bpm
        if self.ceiling_ns < 1:
            raise OperationsDenied("SCHEDULER_FLOOR_DENIED")
        self.window_length = window_length
        self._previous = None
        self._window = []

    def remeasure(self) -> None:
        """A separately authorized capacity change invalidates all old samples."""
        self._previous = None
        self._window.clear()

    def observe(self, *, sequence: int, monotonic_ns: int, identity: tuple[str, ...],
                members: list[dict], slots: list[dict], complete: bool,
                dispatch_observed: bool, snapshot_epoch: str, page_plan_digest: str) -> dict:
        if (type(sequence) is not int or sequence < 1 or type(monotonic_ns) is not int
                or monotonic_ns < 0 or type(complete) is not bool
                or type(dispatch_observed) is not bool):
            self.remeasure()
            raise OperationsDenied("SCHEDULER_SNAPSHOT_DENIED")
        # lane, boot, profile/version/digest, policy, authorization, lease heads.
        if (not isinstance(identity, tuple) or len(identity) != 8
                or any(not isinstance(item, str) or not item for item in identity)):
            self.remeasure()
            raise OperationsDenied("SCHEDULER_IDENTITY_DENIED")
        if (not isinstance(snapshot_epoch, str) or not snapshot_epoch
                or not isinstance(page_plan_digest, str) or len(page_plan_digest) != 64
                or any(char not in "0123456789abcdef" for char in page_plan_digest)):
            self.remeasure()
            raise OperationsDenied("SCHEDULER_SNAPSHOT_IDENTITY_DENIED")
        demand, capacity, exclusions, valid = self._population(members, slots)
        valid = valid and complete

        def population_digest(rows):
            # Input ordering is not membership identity. Bind all exact member
            # facts (including authority/state), not merely demand/capacity counts.
            encoded = sorted(json.dumps(row, sort_keys=True, separators=(",", ":"),
                                        allow_nan=False) for row in rows)
            return hashlib.sha256(json.dumps(encoded, separators=(",", ":")).encode()).hexdigest()

        member_digest = population_digest(members) if valid else None
        capacity_digest = population_digest(slots) if valid else None
        window_identity = (identity, snapshot_epoch, page_plan_digest, member_digest, capacity_digest)
        interval = None
        heartbeat = "UNKNOWN"
        if self._previous is not None:
            old_identity, old_sequence, old_ns = self._previous
            if identity == old_identity[0] and (monotonic_ns <= old_ns or sequence <= old_sequence):
                self.remeasure()
                raise OperationsDenied("SCHEDULER_MONOTONICITY_DENIED")
            if window_identity == old_identity:
                interval = monotonic_ns - old_ns
                if interval <= 0 or sequence <= old_sequence:
                    self.remeasure()
                    raise OperationsDenied("SCHEDULER_MONOTONICITY_DENIED")
                if sequence != old_sequence + 1:
                    heartbeat = "MISSING"
                else:
                    heartbeat = "ON_TIME" if interval <= self.ceiling_ns else "LATE"
            else:
                self._window.clear()
        self._previous = (window_identity, sequence, monotonic_ns)
        if not valid:
            pressure, disposition = "UNKNOWN", "UNKNOWN"
        elif capacity == 0:
            pressure = "ZERO_CAPACITY_DEMAND" if demand else "UNDEFINED_IDLE"
            disposition = "CONGESTED" if demand else "HEALTHY_IDLE"
        else:
            high = 10 * demand >= 9 * capacity
            pressure = "AT_OR_ABOVE_90" if high else "BELOW_90"
            disposition = ("CONGESTED" if high else
                           "UNDER_DISPATCH" if demand and not dispatch_observed else
                           "OBSERVED" if demand else "HEALTHY_IDLE")
        if heartbeat != "ON_TIME" or not valid:
            self._window.clear()
        elif pressure == "AT_OR_ABOVE_90":
            self._window.append((window_identity, sequence))
            self._window = self._window[-self.window_length:]
        else:
            self._window.clear()
        evaluation = ("UNKNOWN" if not valid else "ELIGIBLE_FOR_EVALUATION"
                      if len(self._window) == self.window_length else "INELIGIBLE")
        return {
            "contract_reference": "serein.scheduler-vital-sign-observation.v1",
            "classification": "LOCAL_METRIC_COMPONENT_NOT_ADMITTED_TELEMETRY",
            "sequence": sequence,
            "observed_monotonic_ns": monotonic_ns,
            "identity": list(identity),
            "snapshot_epoch": snapshot_epoch,
            "page_plan_digest": page_plan_digest,
            "member_set_digest": member_digest,
            "capacity_set_digest": capacity_digest,
            "configured_floor_bpm": self.floor_bpm,
            "decision_interval_ceiling_ns": self.ceiling_ns,
            "observed_interval_ns": interval,
            "heartbeat_state": heartbeat,
            "health_event": "SCHEDULER_DEGRADED" if heartbeat in {"LATE", "MISSING"} else None,
            "eligible_runnable_count": demand if valid else None,
            "admitted_available_capacity": capacity if valid else None,
            "excluded_count_by_reason": exclusions,
            "pressure_numerator": demand if valid else None,
            "pressure_denominator": capacity if valid else None,
            "pressure_state": pressure,
            "disposition": disposition,
            "evaluation_state": evaluation,
            "qualifying_observations": len(self._window),
            "window_length": self.window_length,
            "authority_effect": "NONE",
            "dispatch_effect": "NONE",
            "lane_count_delta": 0,
            "work_proof": False,
        }

    @staticmethod
    def _population(members, slots):
        if (not isinstance(members, list) or not isinstance(slots, list)
                or len(members) > 4096 or len(slots) > 4096):
            return 0, 0, {}, False
        member_fields = {"task_id", "owner_domain", "lifecycle_state", "authority_digest",
                         "policy_digest", "dependency_digest", "dedupe_key", "runnable_reason"}
        slot_fields = {"slot_id", "platform_capability_digest", "health", "qualification",
                       "isolation", "reservation", "compatible_lease", "freshness"}
        tasks, dedupe, capacities, exclusions = {}, {}, {}, {}
        demand = capacity = 0
        valid = True

        def excluded(reason):
            exclusions[reason] = exclusions.get(reason, 0) + 1

        def text_fields(row, fields):
            return all(isinstance(row.get(name), str) and row[name] for name in fields)

        def digest(value):
            return (isinstance(value, str) and len(value) == 64
                    and all(char in "0123456789abcdef" for char in value))

        for row in members:
            if (not isinstance(row, dict) or not member_fields <= set(row)
                    or set(row) - member_fields - {"exclusion_reason"}
                    or not text_fields(row, member_fields)
                    or ("exclusion_reason" in row and not isinstance(row["exclusion_reason"], str))):
                valid = False
                continue
            if any(not digest(row[name]) for name in
                   ("authority_digest", "policy_digest", "dependency_digest")):
                valid = False
                continue
            previous = tasks.get(row["task_id"]) or dedupe.get(row["dedupe_key"])
            if previous is not None:
                if previous != row:
                    valid = False
                excluded("DUPLICATE")
                continue
            tasks[row["task_id"]] = row
            dedupe[row["dedupe_key"]] = row
            state = row["lifecycle_state"]
            if state in EXCLUDED_TASK_STATES:
                excluded(state)
            elif state in {"READY", "RUNNABLE"} and not row.get("exclusion_reason"):
                demand += 1
            elif state == "QUEUED_CURRENT":
                excluded("QUEUED_CURRENT")
            else:
                valid = False
        for row in slots:
            if (not isinstance(row, dict) or set(row) != slot_fields
                    or not text_fields(row, {"slot_id", "platform_capability_digest"})
                    or not digest(row["platform_capability_digest"])):
                valid = False
                continue
            if row["slot_id"] in capacities:
                if capacities[row["slot_id"]] != row:
                    valid = False
                excluded("DUPLICATE_CAPACITY")
                continue
            capacities[row["slot_id"]] = row
            checks = [row[name] for name in slot_fields - {"slot_id", "platform_capability_digest"}]
            if any(type(value) is not bool for value in checks):
                valid = False
            elif all(checks):
                capacity += 1
            else:
                excluded("UNAVAILABLE_CAPACITY")
        return demand, capacity, exclusions, valid


class OperationsDenied(RuntimeError):
    pass


@contextmanager
def installed_replay_owner(*, root, database_path, clock, read_only=False):
    """Own the existing durable store using actual installed, bound inputs.

    No guessed database location, directory creation, key generation, service
    startup or admission. The complete-domain owner supplies its private path;
    the existing store retains its exact custody/recovery checks. Secret bytes
    stay inside this process and must never become an observation or receipt.
    """
    from .authority_contract import canonical, read_consumer_installed_policy_evidence
    root=Path(root);database_path=Path(database_path)
    if (not root.is_absolute() or '..' in root.parts
            or not database_path.is_absolute() or '..' in database_path.parts
            or not database_path.is_relative_to(root/'var/lib/serein/kernel')):
        raise OperationsDenied('REPLAY_OWNER_PATH_DENIED')
    account=pwd.getpwnam('serein-stage1')
    if (os.geteuid(),os.getegid())!=(account.pw_uid,account.pw_gid):
        raise OperationsDenied('REPLAY_OWNER_IDENTITY_DENIED')
    installed=read_consumer_installed_policy_evidence(root=root)
    captured={}
    def read(relative, custody):
        path=root/relative
        value=_regular_bytes(path,custody=custody,include_fact=True)
        captured[relative]=(value,custody)
        return value[0]
    descriptor=_strict_json(read('var/lib/serein/kernel/authority/replay-descriptor.json',(0,0,0o644)))
    key=read('var/lib/serein/kernel/authority/replay.key',(account.pw_uid,account.pw_gid,0o600))
    if len(key)!=32:
        raise OperationsDenied('REPLAY_OWNER_KEY_DENIED')
    rows=installed['evidence']['payload']
    modules={}
    for name in ('replay_store.py','persistent_replay_store.py'):
        target='/usr/lib/serein/kernel/'+name
        bound=[row for row in rows if row['source']=='payload/runtime/'+name]
        if (len(bound)!=1 or bound[0]['target']!=target
                or bound[0]['branch']!='OPERATIONS' or bound[0]['mode']!='0644'):
            raise OperationsDenied('REPLAY_OWNER_SOURCE_DENIED')
        raw=read(target.lstrip('/'),(0,0,0o644))
        if len(raw)!=bound[0]['bytes'] or hashlib.sha256(raw).hexdigest()!=bound[0]['sha256']:
            raise OperationsDenied('REPLAY_OWNER_SOURCE_DENIED')
        modules[name]=raw
    # Installer derives these identities from the exact signed plan bytes.
    # A different, still MAC-valid descriptor is not this installation.
    body=descriptor['body']
    origin=installed.get('replay_origin',{'plan_sha256':installed['plan_sha256'],
        'source_generation':installed['evidence']['source_generation']})
    plan_digest=origin['plan_sha256']
    if (body['store_id']!=str(uuid5(NAMESPACE_URL,'serein-kernel-store:'+plan_digest))
            or body['trusted_key_receipt']!=str(uuid5(NAMESPACE_URL,'serein-kernel-key:'+plan_digest))):
        raise OperationsDenied('REPLAY_OWNER_INSTALL_BINDING_DENIED')
    path=root/'usr/lib/serein/kernel/persistent_replay_store.py'
    spec=importlib.util.spec_from_file_location('_installed_kernel_replay_owner',path)
    module=importlib.util.module_from_spec(spec)
    exec(compile(modules['persistent_replay_store.py'],str(path),'exec'),module.__dict__)
    module.CONTRACT_PATH=root/'usr/lib/serein/kernel/replay_store.py'
    def unchanged():
        if (canonical(read_consumer_installed_policy_evidence(root=root))!=canonical(installed)
                or any(_regular_bytes(root/name,custody=custody,include_fact=True)!=value
                       for name,(value,custody) in captured.items())):
            raise OperationsDenied('REPLAY_OWNER_INPUT_CHANGED')
    store=module.PersistentReplayStore(database_path,descriptor=descriptor,key=key,
        expected_target={'vm_id':'VM4010','boot_id':installed['boot_id']},
        expected_generation=origin['source_generation'],input_guard=unchanged,
        conversation_context={
            'source_generation':{'commit':installed['source_commit'],'tree':installed['source_tree']},
            'policy_sha256':installed['policy_sha256'],'plan_sha256':installed['plan_sha256'],
            'canonical_manifest_digest':installed['canonical_manifest_digest'],
            'kernel_instance':installed['native_identity']['instance_id'],
            'identity_checkpoint':installed['native_identity']['checkpoint'],'boot_id':installed['boot_id']})
    opened=False
    try:
        unchanged()
        now=clock()
        if not isinstance(now,datetime) or now.tzinfo is None or now.utcoffset() is None:
            raise OperationsDenied('REPLAY_OWNER_CLOCK_DENIED')
        store.open(current_time=now.astimezone(timezone.utc).isoformat().replace('+00:00','Z'),
                   read_only=read_only)
        opened=True
        unchanged()
        yield store
    finally:
        try:
            if opened:
                unchanged()
        finally:
            store.close()


def read_current_host_evidence(*, root=Path('/')):
    """Read existing Outpost HTTPS evidence, without a new grant or listener.

    The installer's signed public payload closure binds the packaged canonical
    Outpost validator before/after the read. No private files or selectors.
    Default system CA validation and exact hostname are mandatory; there is
    no caller URL, trust override, proxy, redirect, cache or credential input.
    """
    from serein_stage1.authority_contract import read_consumer_installed_policy_evidence
    root = Path(root)
    try:
        installed = read_consumer_installed_policy_evidence(root=root)
    except (OSError, ValueError) as exc:
        raise OperationsDenied('CURRENT_HOST_API_EVIDENCE_DENIED') from exc
    boot_id_path = root/'proc/sys/kernel/random/boot_id'
    # DNS and slow-drip headers are not covered by a socket's per-read
    # timeout. Bound the caller's whole observation and retain a single slot
    # until the read actually exits, so a stuck resolver cannot spawn more
    # threads on repeated requests. This worker only performs one public GET.
    if not _VITALS_READ_SLOT.acquire(blocking=False):
        raise OperationsDenied('CURRENT_HOST_API_EVIDENCE_DENIED')
    cancelled = threading.Event()
    outcome = []
    connections = []
    deadline = time.monotonic() + VITALS_TIMEOUT_SECONDS
    def read():
        try:
            value = _read_current_host_evidence(boot_id_path=boot_id_path,
                cancelled=cancelled, deadline=deadline, connections=connections,
                expected_generation=installed['evidence']['outpost_generation'])
            if not cancelled.is_set(): outcome.append((True, value))
        except Exception as exc:
            if not cancelled.is_set(): outcome.append((False, exc))
        finally:
            _VITALS_READ_SLOT.release()
    worker = threading.Thread(target=read, name='kernel-outpost-host-read', daemon=True)
    try:
        worker.start()
    except Exception:
        _VITALS_READ_SLOT.release()
        raise
    worker.join(max(0.0, deadline-time.monotonic()))
    if worker.is_alive() or time.monotonic() > deadline or not outcome:
        cancelled.set()
        # Wake an in-flight TLS/HTTP read when available. A blocked resolver
        # keeps the slot occupied until it returns; it cannot send a GET after
        # returning past the deadline.
        for connection in connections:
            sock = connection.sock
            if sock is not None:
                try: sock.shutdown(socket.SHUT_RDWR)
                except OSError: pass
        raise OperationsDenied('CURRENT_HOST_API_EVIDENCE_DENIED')
    successful, value = outcome[0]
    if not successful:
        raise OperationsDenied('CURRENT_HOST_API_EVIDENCE_DENIED') from value
    try:
        fresh = read_consumer_installed_policy_evidence(root=root)
        if (fresh != installed or value['boot_id'] != installed['boot_id']):
            raise ValueError('installed evidence changed during API read')
    except (OSError, ValueError) as exc:
        raise OperationsDenied('CURRENT_HOST_API_EVIDENCE_DENIED') from exc
    value['installed_evidence_sha256'] = installed['evidence_sha256']
    return value


def _read_current_host_evidence(*, boot_id_path, cancelled, deadline, connections, expected_generation):
    connection = None
    response = None
    try:
        from serein_stage1.outpost_evidence.vitals_edge import current_host_evidence
        boot_raw, boot_fact = _regular_bytes(boot_id_path, include_fact=True)
        boot_id = boot_raw.decode('ascii').strip()
        context = ssl.create_default_context()
        context.set_alpn_protocols(['http/1.1'])
        if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
            raise ValueError('TLS authentication required')
        requested_at = time.time()
        connection = http.client.HTTPSConnection(VITALS_HOST, 443,
            timeout=VITALS_TIMEOUT_SECONDS, context=context)
        connections.append(connection)
        connection.connect()
        if cancelled.is_set() or time.monotonic() >= deadline:
            raise ValueError('Vitals connection deadline')
        connection.request('GET', VITALS_PATH, headers={
            'Accept': 'application/json', 'Cache-Control': 'no-cache, no-store',
            'Pragma': 'no-cache', 'Connection': 'close'})
        response = connection.getresponse()
        # The canonical edge emits one unencoded, length-bounded JSON body.
        headers = response.headers
        lengths = headers.get_all('Content-Length', [])
        types = headers.get_all('Content-Type', [])
        cache = headers.get_all('Cache-Control', [])
        if (response.status != 200 or len(lengths) != 1
                or not lengths[0].isascii() or not lengths[0].isdigit()
                or not 0 < int(lengths[0]) <= VITALS_MAX_BYTES
                or types != ['application/json'] or len(cache) != 1
                or 'no-store' not in {v.strip().lower() for v in cache[0].split(',')}
                or headers.get('Age') is not None
                or headers.get('Location') is not None
                or headers.get('Content-Encoding') is not None
                or headers.get('Transfer-Encoding') is not None):
            raise ValueError('noncanonical Vitals response')
        size = int(lengths[0]); chunks = []; total = 0
        while total < size:
            remaining = deadline - time.monotonic()
            if cancelled.is_set() or remaining <= 0:
                raise ValueError('Vitals read deadline')
            # HTTP/1.1 close responses can detach the socket from connection;
            # the response retains it. Its initial per-read timeout remains
            # bounded, and read1 returns after one underlying buffered read.
            chunk = response.read1(min(65536, size - total))
            if not chunk:
                raise ValueError('truncated Vitals response')
            chunks.append(chunk); total += len(chunk)
        if time.monotonic() > deadline:
            raise ValueError('Vitals read deadline')
        received_at = time.time()
        if _regular_bytes(boot_id_path, include_fact=True) != (boot_raw, boot_fact):
            raise ValueError('boot changed during Vitals read')
        result = current_host_evidence(b''.join(chunks), current_boot_id=boot_id,
                                      expected_generation=expected_generation,
                                      requested_at=requested_at, received_at=received_at)
        result['endpoint'] = 'https://' + VITALS_HOST + VITALS_PATH
        result['transport'] = 'TLS_CERTIFICATE_AND_HOSTNAME_VERIFIED'
        return result
    except (ImportError, OSError, ValueError, TypeError, UnicodeError, http.client.HTTPException) as exc:
        raise OperationsDenied('CURRENT_HOST_API_EVIDENCE_DENIED') from exc
    finally:
        if response is not None:
            response.close()
        if connection is not None:
            connection.close()


def reserve_installed_conversation(payload, *, authenticated_caller, root, replay_store, clock):
    """Reserve the exact installed-policy attempt; never forward or admit.

    Read the real installed closure before and after reservation, in the
    owning consumer's unprivileged context. A changed closure leaves durable
    evidence and cannot be retried. Whole-domain current predicates and the
    private runtime invocation remain separate, mandatory owning operations.
    """
    from .authority_contract import canonical, match_installed_stage1_conversation

    def observed():
        value = clock()
        if (not isinstance(value, datetime) or value.tzinfo is None
                or value.utcoffset() is None):
            raise OperationsDenied('CONVERSATION_REPLAY_CLOCK_DENIED')
        return value

    matched = match_installed_stage1_conversation(payload,
        authenticated_caller=authenticated_caller, root=root, now=observed())
    binding = matched['replay_binding']
    descriptor = replay_store.descriptor['body']
    installed = matched['installed_policy']
    origin = installed.get('replay_origin',{'source_generation':installed['evidence']['source_generation']})
    if (descriptor['target'].get('vm_id') != 'VM4010'
            or descriptor['target']['boot_id'] != binding['boot_id']
            or {key: descriptor['source_generation'][key] for key in ('commit','tree')}
               != {key:origin['source_generation'][key] for key in ('commit','tree')}):
        raise OperationsDenied('CONVERSATION_REPLAY_SCOPE_DENIED')
    def host_observation(policy):
        host = read_current_host_evidence(root=root)
        if (host['state'] != 'CURRENT_HOST_EVIDENCE_ONLY'
                or host['boot_id'] != policy['boot_id']
                or host['installed_evidence_sha256'] != policy['evidence_sha256']
                or host['outpost_generation'] != policy['evidence']['outpost_generation']):
            raise OperationsDenied('CONVERSATION_HOST_BINDING_DENIED')
        return host

    host_before = host_observation(matched['installed_policy'])
    at = observed().astimezone(timezone.utc).isoformat().replace('+00:00','Z')
    chain, reservation = replay_store.reserve_request(request_id=matched['request_id'],
        at=at, current_time=at, expires_at=matched['replay_expires_at'], binding=binding)
    try:
        fresh = match_installed_stage1_conversation(payload,
            authenticated_caller=authenticated_caller, root=root, now=observed())
        if canonical(fresh) != canonical(matched):
            raise OperationsDenied('CONVERSATION_POLICY_CHANGED_AFTER_RESERVATION')
        host_after = host_observation(fresh['installed_policy'])
        if (host_after['host_facts_sha256'] != host_before['host_facts_sha256']
                or host_after['observed_at'] < host_before['observed_at']
                or host_after['claim'] not in {host_before['claim'], 'CURRENT_BOOT_STABLE'}):
            raise OperationsDenied('CONVERSATION_HOST_CHANGED_AFTER_RESERVATION')
    except Exception as exc:
        error = OperationsDenied('CONVERSATION_RESERVED_EVIDENCE_PRESERVED')
        error.evidence = {'chain_id':chain, 'reservation':reservation, 'forward_attempted':False}
        raise error from exc
    return {'matched':matched, 'chain_id':chain, 'reservation':reservation,
            'host_before':host_before, 'host_after':host_after,
            'state':'RESERVED_PENDING_CURRENT_DOMAIN_GATES', 'forward_attempted':False,
            'authority_effect':'NONE', 'admission_effect':'NONE', 'dispatch_effect':'NONE'}


def verify_installed_conversation_boundary(matched, *, root, clock):
    """Current installed Kernel predicate, never a new runtime grant.

    Whole-domain Outpost startup still verifies Authority and Operations before
    opening ingress. Runtime reuses that exact source/boot binding and private
    Operations/Audit facts, plus current service process identity, so a saved
    healthy heartbeat cannot conceal a stopped or restarted owner. Host and
    replay checks remain in the surrounding existing reservation transaction.
    """
    from .authority_contract import canonical
    from .kernel_branch_api import read_installed_operations_observation
    from .supervision import operations_service_controls
    before=operations_service_controls()
    installed,event=read_installed_operations_observation(root=root)
    after=operations_service_controls()
    now=clock()
    at=datetime.fromisoformat(event['observed_at'].replace('Z','+00:00'))
    required={('/etc/systemd/system/'+name,'payload/systemd/'+name) for name in before}
    present={(row['target'],row['source']) for row in installed['evidence']['payload']}
    if (canonical(installed)!=canonical(matched['installed_policy']) or not required<=present
            or not isinstance(now,datetime) or now.utcoffset() is None
            or at.utcoffset() is None or not 0<=(now-at).total_seconds()<=30
            or event['sequence']<2 or event['cadence_state']!='OBSERVED' or event['event']!='HEARTBEAT'
            or 'replay_continuity' not in event
            or any(event['monotonic_ns']<=int(row['ExecMainStartTimestampMonotonic'])*1000
                for row in before.values()) or after!=before):
        raise OperationsDenied('CONVERSATION_CURRENT_OPERATIONS_DENIED')


def dispatch_installed_conversation(payload, *, authenticated_caller, root, replay_store,
                                    boundary, clock):
    """One ordinary-conversation forward inside the installed Kernel owner.

    PRO-132/84e2d00d: use the exact installed conversation policy, not a new
    generic grant or CP worker lease. The owning service must supply its actual
    current constituent boundary; no default pass or uploaded gate receipt is
    accepted here. This function does not open/admit an ingress or start a
    service. The fixed private runtime and its existing response validator are
    the only forward road. Tools and consequential actions remain excluded.
    """
    from .authority_contract import canonical,match_installed_stage1_conversation
    from .conversation_runtime import call_expected
    from .kernel import exchange_private_service
    if not callable(boundary) or not callable(clock):
        raise OperationsDenied('CONVERSATION_CURRENT_BOUNDARY_REQUIRED')
    matched=match_installed_stage1_conversation(payload,
        authenticated_caller=authenticated_caller,root=root,now=clock())
    def current():
        fresh=match_installed_stage1_conversation(payload,
            authenticated_caller=authenticated_caller,root=root,now=clock())
        if canonical(fresh)!=canonical(matched):
            raise OperationsDenied('CONVERSATION_INSTALLED_SCOPE_CHANGED')
        # Snapshot the boundary input. An owning verifier cannot accidentally
        # edit the matched payload that is about to cross the private socket.
        supplied=json.loads(canonical(matched))
        if boundary(supplied) is not None or canonical(supplied)!=canonical(matched):
            raise OperationsDenied('CONVERSATION_CURRENT_BOUNDARY_DENIED')
    current()
    attempt=reserve_installed_conversation(payload,authenticated_caller=authenticated_caller,
        root=root,replay_store=replay_store,clock=clock)
    evidence={'chain_id':attempt['chain_id'],'reservation':attempt['reservation'],
              'forward_attempted':False,'result_sha256':None}
    try:
        if canonical(attempt['matched'])!=canonical(matched):
            raise OperationsDenied('CONVERSATION_INSTALLED_SCOPE_CHANGED')
        current()
        runtime_payload=canonical(matched['runtime_request'])
        expires=datetime.fromisoformat(matched['replay_expires_at'].replace('Z','+00:00'))
        def forward(value):
            remaining=(expires-clock()).total_seconds()
            if remaining<=0:
                raise OperationsDenied('CONVERSATION_FORWARD_EXPIRED')
            evidence['forward_attempted']=True
            return exchange_private_service('CONVERSATION',value,timeout_seconds=min(remaining,30.0),root=root)
        result=call_expected(runtime_payload,runtime_call=forward,clock=clock)
        evidence['result_sha256']=hashlib.sha256(result).hexdigest()
        returned=json.loads(result)
        if returned['status']=='ANSWERED' and any(
                returned['compute_observation'][name]['boot_id']!=matched['installed_policy']['boot_id']
                for name in ('gpu_before','gpu_after')):
            raise OperationsDenied('CONVERSATION_COMPUTE_BOOT_DENIED')
        # An unknown outcome or changed gate never becomes a retry. Preserve
        # the reservation/result digest and let the owning recovery observe it.
        current()
        host=read_current_host_evidence(root=root)
        prior=attempt['host_after']
        if (any(host[key]!=prior[key] for key in ('state','boot_id','installed_evidence_sha256',
                'outpost_generation','host_facts_sha256'))
                or host['observed_at']<prior['observed_at']
                or host['claim'] not in {prior['claim'],'CURRENT_BOOT_STABLE'}):
            raise OperationsDenied('CONVERSATION_HOST_CHANGED_AFTER_FORWARD')
        completed=clock().astimezone(timezone.utc).isoformat().replace('+00:00','Z')
        consumption=replay_store.consume_request(request_id=matched['request_id'],
            expected_hash=replay_store.contract.receipt_hash(attempt['reservation']),
            at=completed,current_time=completed,result_sha256=evidence['result_sha256'])
    except Exception as exc:
        error=OperationsDenied('CONVERSATION_RESERVED_EVIDENCE_PRESERVED')
        error.evidence=evidence
        raise error from exc
    return {'result':result,'result_sha256':evidence['result_sha256'],
            'replay':[attempt['reservation'],consumption],
            'state':'DESTINATION_RESULT_RETURNED_NOT_INDEPENDENTLY_VERIFIED',
            'authority_effect':'NONE','admission_effect':'NONE'}


def dispatch_once(request, payload, *, context_reader, replay_store, forward, clock):
    """Bind Authority policy to existing durable replay and one private forward.

    ADAPT the recorded gateway_runtime.handle_client_payload sequence. This
    internal integration opens no listener and selects no URL, service or key.
    context_reader supplies independently authenticated/current route facts;
    forward is the owning destination's already-bound private API adapter.
    Destination semantics and real effects require separate acceptance. A
    failure after reservation preserves that reservation; it never retries.
    """
    from .authority_contract import canonical, evaluate_dispatch
    if not isinstance(payload, bytes) or len(payload) > 128 * 1024:
        raise OperationsDenied('DISPATCH_PAYLOAD_DENIED')
    request = json.loads(canonical(request))
    payload_digest = hashlib.sha256(payload).hexdigest()

    def read_clock():
        observed = clock()
        if (not isinstance(observed, datetime) or observed.tzinfo is None
                or observed.utcoffset() is None):
            raise OperationsDenied('DISPATCH_CLOCK_DENIED')
        return observed

    def evaluate():
        context = context_reader()
        if context['expected']['scope'].get('payload_sha256') != payload_digest:
            raise OperationsDenied('DISPATCH_PAYLOAD_BINDING_DENIED')
        observed = read_clock()
        decision = evaluate_dispatch(request, **context, now=observed)
        return decision, observed, context

    decision, observed, context = evaluate()
    if decision['disposition'] != 'VALIDATED_PENDING_REPLAY':
        # A queue disposition is not a durable OperationsQueue entry. The
        # caller must separately preserve/revalidate it; never forward here.
        return {'decision':decision, 'result':None, 'replay':[],
                'authority_effect':'NONE', 'admission_effect':'NONE'}
    body = request['authority_contract']['body']
    descriptor = replay_store.descriptor['body']
    if (descriptor['target']['boot_id'] != body['boot_id']
            or any(descriptor['source_generation'][field] != body['source_generation'][field]
                   for field in ('commit', 'tree'))):
        raise OperationsDenied('DISPATCH_REPLAY_SCOPE_DENIED')
    expires = datetime.fromisoformat(body['expires_at'].replace('Z','+00:00'))
    at = observed.astimezone(timezone.utc).isoformat().replace('+00:00','Z')
    binding = {name:decision[name] for name in ('request_id','conversation_id','route','owner','plane',
        'request_sha256','contract_sha256','registered_route_sha256','identity_checkpoint','kernel_instance')}
    binding.update(payload_sha256=payload_digest, capacity=context['registered_route']['qos']['capacity'],
                   external_active_count=context['active_count'], ump_sha256=context['ump_sha256'])
    binding.update({name:body[name] for name in ('boot_id','source_generation','policy_digest',
        'policy_version','trust_identity','predecessor_evidence_digest')})
    chain_id, reservation = replay_store.reserve_request(request_id=request['request_id'],
        at=at, expires_at=expires.astimezone(timezone.utc).isoformat().replace('+00:00','Z'),
        current_time=at, binding=binding)
    evidence = {'request_sha256':decision['request_sha256'], 'payload_sha256':payload_digest,
                'route':decision['route'], 'reservation':reservation,
                'forward_attempted':False, 'result_sha256':None}
    try:
        if (chain_id != decision['replay_identity']['action_nonce']
                or reservation['body']['action_nonce'] != chain_id
                or reservation['body']['run_id'] != decision['replay_identity']['run_id']):
            raise OperationsDenied('DISPATCH_REPLAY_IDENTITY_DENIED')
        fresh, _, _ = evaluate()
        if (fresh['disposition'] != 'VALIDATED_PENDING_REPLAY'
                or any(fresh[field] != decision[field] for field in
                       ('request_sha256','contract_sha256','registered_route_sha256',
                        'kernel_instance','identity_checkpoint','replay_identity'))):
            raise OperationsDenied('DISPATCH_CURRENTNESS_CHANGED')
        evidence['forward_attempted'] = True
        result = forward(decision['route'], payload)
        if not isinstance(result, bytes) or len(result) > 256 * 1024:
            raise OperationsDenied('DISPATCH_RESULT_SHAPE_DENIED')
        evidence['result_sha256'] = hashlib.sha256(result).hexdigest()
        completed = read_clock().astimezone(timezone.utc).isoformat().replace('+00:00','Z')
        consumption = replay_store.consume_request(request_id=request['request_id'],
            expected_hash=replay_store.contract.receipt_hash(reservation),
            at=completed, current_time=completed, result_sha256=evidence['result_sha256'])
    except Exception as exc:
        error = OperationsDenied('DISPATCH_RESERVED_EVIDENCE_PRESERVED')
        error.evidence = evidence
        raise error from exc
    return {'decision':decision, 'payload_sha256':payload_digest,
            'replay':[reservation,consumption], 'result':result,
            'result_sha256':evidence['result_sha256'],
            'state':'DESTINATION_RESULT_RETURNED_NOT_INDEPENDENTLY_VERIFIED',
            'authority_effect':'NONE', 'admission_effect':'NONE'}


def dispatch_pending_once(queue, request, payload, *, current_dependency_reader,
                          context_reader, replay_store, forward, clock):
    """Drain at most the exact pending head through the existing dispatch road.

    Both readers are trusted, already-bound local adapters, never ingress
    fields. The dependency reader independently supplies the current task,
    owner, dedupe, request and dependency identities. Queue hashes preserve
    metadata integrity; they grant no authority. No payload is stored here.
    Authenticated consumption permits metadata cleanup, not another inference.
    """
    from .authority_contract import canonical, evaluate_dispatch
    request = json.loads(canonical(request))
    if not isinstance(payload, bytes) or len(payload) > 128 * 1024:
        raise OperationsDenied('DISPATCH_PAYLOAD_DENIED')
    rows = queue.snapshot()['pending']
    if not rows:
        return {'state':'QUEUE_EMPTY', 'authority_effect':'NONE', 'admission_effect':'NONE'}
    head = rows[0]
    record = head['record']
    if record['resume_condition'] != 'CAPACITY_AVAILABLE_AFTER_CURRENT_AUTHORITY_CHECK':
        return {'state':'RESUME_CONDITION_UNKNOWN_PENDING_PRESERVED',
                'authority_effect':'NONE', 'admission_effect':'NONE'}
    request_digest = hashlib.sha256(canonical(request)).hexdigest()
    payload_digest = hashlib.sha256(payload).hexdigest()

    def now():
        observed = clock()
        if (not isinstance(observed, datetime) or observed.tzinfo is None
                or observed.utcoffset() is None):
            raise OperationsDenied('DISPATCH_CLOCK_DENIED')
        return observed

    def current_context():
        fresh_rows = queue.snapshot()['pending']
        if not fresh_rows or fresh_rows[0] != head:
            raise OperationsDenied('QUEUE_HEAD_CHANGED')
        fields = ('task_id','owner_domain','dedupe_key','request_digest','dependency_digest')
        dependencies = current_dependency_reader()
        if (not isinstance(dependencies, dict) or set(dependencies) != set(fields)
                or any(dependencies[name] != record[name] for name in fields)
                or request_digest != record['request_digest']):
            raise OperationsDenied('QUEUE_CURRENT_DEPENDENCY_DENIED')
        context = context_reader()
        if (context['expected']['scope'].get('payload_sha256') != payload_digest
                or record['authority_digest'] != hashlib.sha256(
                    canonical(request['authority_contract']['body'])).hexdigest()
                or record['policy_digest'] != context['expected']['policy_digest']
                or record['owner_domain'] != context['registered_route']['owner']):
            raise OperationsDenied('QUEUE_CURRENT_AUTHORITY_DENIED')
        return context

    context = current_context()
    decision = evaluate_dispatch(request, **context, now=now())

    def authenticated_completion():
        evidence = replay_store.dispatch_evidence(request['request_id'],
            current_time=now().astimezone(timezone.utc).isoformat().replace('+00:00','Z'))
        if evidence is None:
            return None
        # dispatch_evidence authenticates the whole signed chain and binding.
        binding = evidence['binding']['body']['binding']
        expected = {name:decision[name] for name in ('request_id','conversation_id',
            'route','owner','plane','request_sha256','contract_sha256',
            'registered_route_sha256','identity_checkpoint','kernel_instance')}
        expected.update(payload_sha256=payload_digest, policy_digest=record['policy_digest'])
        if any(binding.get(name) != value for name,value in expected.items()):
            raise OperationsDenied('QUEUE_REPLAY_BINDING_DENIED')
        if evidence['outcome'] is None:
            return {'state':'RECOVERY_REQUIRED_RESERVED_PRESERVED',
                    'authority_effect':'NONE', 'admission_effect':'NONE'}
        if evidence['receipts'][-1]['body']['state'] != 'CONSUMED':
            raise OperationsDenied('QUEUE_REPLAY_COMPLETION_DENIED')
        queue.complete_head(head)
        return {'state':'CONSUMED_HEAD_RECONCILED', 'position':head['position'],
                'result_sha256':evidence['outcome']['body']['result_sha256'],
                'physical_effect':'UNVERIFIED', 'authority_effect':'NONE',
                'admission_effect':'NONE'}

    completed = authenticated_completion()
    if completed is not None:
        return completed
    result = dispatch_once(request, payload, context_reader=current_context,
        replay_store=replay_store, forward=forward, clock=clock)
    if result['result'] is None:
        return {'state':'PENDING_REVALIDATION', 'dispatch':result,
                'authority_effect':'NONE', 'admission_effect':'NONE'}
    completed = authenticated_completion()
    if completed is None or completed['state'] != 'CONSUMED_HEAD_RECONCILED':
        raise OperationsDenied('QUEUE_REPLAY_COMPLETION_DENIED')
    return {**completed, 'dispatch':result}


class OperationsQueue:
    """Durable pending-work metadata, not a dispatch or authorization surface.

    PRO-136: preserve exact identity, authority/policy/dependency references,
    attributable queue order and deterministic resume condition. A persisted
    request remains pending; current authority must be revalidated separately.
    No startup hook, service action, task execution or age-based expiry exists.
    """

    FIELDS = frozenset({'task_id','owner_domain','dedupe_key','request_digest',
                        'authority_digest','policy_digest','dependency_digest',
                        'queued_at','resume_condition'})
    DIGESTS = frozenset({'request_digest','authority_digest','policy_digest','dependency_digest'})
    TABLE_SQL = ('CREATE TABLE pending ('
        'position INTEGER PRIMARY KEY AUTOINCREMENT,task_id TEXT UNIQUE NOT NULL,'
        'dedupe_key TEXT UNIQUE NOT NULL,record BLOB NOT NULL,record_sha256 TEXT NOT NULL,'
        'entry_sha256 TEXT NOT NULL)')

    def __init__(self, path: Path):
        self.path=Path(path)
        self._parent_fd=None
        self.connection=None
        if not self.path.is_absolute() or '..' in self.path.parts:
            raise OperationsDenied('QUEUE_PATH_DENIED')
        try:
            fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            self._parent_fd=fd
            for part in self.path.parts[1:-1]:
                child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                os.close(fd);fd=child;self._parent_fd=fd
            parent=os.fstat(fd)
            if parent.st_uid!=os.geteuid() or stat.S_IMODE(parent.st_mode)!=0o700:
                raise OperationsDenied('QUEUE_PRIVATE_PARENT_REQUIRED')
            self._parent_identity=(parent.st_dev,parent.st_ino,parent.st_uid,parent.st_gid,parent.st_mode)
            try:
                created=os.open(self.path.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,
                                0o600,dir_fd=fd)
            except FileExistsError:
                pass
            else:
                os.fsync(created);os.close(created);os.fsync(fd)
            self._database_identity=self._identity()
            self.connection=sqlite3.connect(f'file:/proc/self/fd/{fd}/{quote(self.path.name, safe="")}?mode=rw',
                                           uri=True,isolation_level=None)
            self.connection.execute('PRAGMA synchronous=FULL')
            self.connection.execute('BEGIN IMMEDIATE')
            if not self.connection.execute('SELECT 1 FROM sqlite_master LIMIT 1').fetchone():
                self.connection.execute(self.TABLE_SQL)
            self._schema()
            self._stable();self.connection.execute('COMMIT')
        except (OSError,sqlite3.Error,OperationsDenied):
            self.close()
            raise

    def _identity(self):
        info=os.stat(self.path.name,dir_fd=self._parent_fd,follow_symlinks=False)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_uid!=os.geteuid()
                or stat.S_IMODE(info.st_mode)!=0o600):
            raise OperationsDenied('QUEUE_DATABASE_CUSTODY_DENIED')
        return (info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode)

    def _stable(self):
        parent=self.path.parent.stat(follow_symlinks=False)
        if ((parent.st_dev,parent.st_ino,parent.st_uid,parent.st_gid,parent.st_mode)!=self._parent_identity
                or self._identity()!=self._database_identity):
            raise OperationsDenied('QUEUE_DATABASE_CHANGED')

    def _schema(self):
        expected={('table','pending','pending',self.TABLE_SQL),
                  ('table','sqlite_sequence','sqlite_sequence','CREATE TABLE sqlite_sequence(name,seq)'),
                  ('index','sqlite_autoindex_pending_1','pending',None),
                  ('index','sqlite_autoindex_pending_2','pending',None)}
        actual=set(self.connection.execute('SELECT type,name,tbl_name,sql FROM sqlite_master'))
        if actual!=expected:raise OperationsDenied('QUEUE_SCHEMA_DENIED')

    @staticmethod
    def _entry_digest(position,record_digest):
        return hashlib.sha256(json.dumps({'position':position,'record_sha256':record_digest},
                              sort_keys=True,separators=(',',':')).encode()).hexdigest()

    @classmethod
    def _encode(cls, record):
        if (not isinstance(record,dict) or set(record)!=cls.FIELDS
                or any(not isinstance(value,str) or not value or len(value)>512 for value in record.values())
                or any(len(record[name])!=64 or any(c not in '0123456789abcdef' for c in record[name])
                       for name in cls.DIGESTS)):
            raise OperationsDenied('QUEUE_RECORD_DENIED')
        try:
            when=datetime.fromisoformat(record['queued_at'].replace('Z','+00:00'))
            if not record['queued_at'].endswith('Z') or when.utcoffset().total_seconds()!=0:
                raise ValueError('queue time is not UTC')
        except (ValueError,AttributeError) as exc:
            raise OperationsDenied('QUEUE_RECORD_DENIED') from exc
        return json.dumps(record,sort_keys=True,separators=(',',':'),allow_nan=False).encode()

    def enqueue(self,record):
        raw=self._encode(record);digest=hashlib.sha256(raw).hexdigest()
        self._stable();self.connection.execute('BEGIN IMMEDIATE')
        try:
            self._schema()
            rows=self.connection.execute('SELECT position,record,record_sha256,entry_sha256 FROM pending '
                'WHERE task_id=? OR dedupe_key=?',(record['task_id'],record['dedupe_key'])).fetchall()
            if rows:
                if (len(rows)!=1 or rows[0][1:3]!=(raw,digest)
                        or rows[0][3]!=self._entry_digest(rows[0][0],digest)):
                    raise OperationsDenied('QUEUE_IDENTITY_CONFLICT')
                position=rows[0][0]
            else:
                if self.connection.execute('SELECT COUNT(*) FROM pending').fetchone()[0]>=4096:
                    raise OperationsDenied('QUEUE_CAPACITY_REACHED')
                position=self.connection.execute('INSERT INTO pending(task_id,dedupe_key,record,record_sha256,entry_sha256) '
                    'VALUES (?,?,?,?,?)',(record['task_id'],record['dedupe_key'],raw,digest,'')).lastrowid
                self.connection.execute('UPDATE pending SET entry_sha256=? WHERE position=?',
                                        (self._entry_digest(position,digest),position))
            self._stable();self.connection.execute('COMMIT')
            return {'position':position,'record_sha256':digest,'state':'PENDING_REVALIDATION',
                    'authority_effect':'NONE','dispatch_effect':'NONE'}
        except Exception:
            if self.connection.in_transaction:
                self.connection.execute('ROLLBACK')
            raise

    def snapshot(self):
        self._stable();self.connection.execute('BEGIN')
        try:
            self._schema()
            rows=self.connection.execute('SELECT position,task_id,dedupe_key,record,record_sha256,entry_sha256 '
                                         'FROM pending ORDER BY position LIMIT 4097').fetchall()
            if len(rows)>4096:raise OperationsDenied('QUEUE_CAPACITY_REACHED')
            result=[]
            for position,task_id,dedupe_key,raw,digest,entry_digest in rows:
                record=_strict_json(raw)
                if (self._encode(record)!=raw or hashlib.sha256(raw).hexdigest()!=digest
                        or record['task_id']!=task_id or record['dedupe_key']!=dedupe_key
                        or type(position) is not int or position<1
                        or entry_digest!=self._entry_digest(position,digest)):
                    raise OperationsDenied('QUEUE_RECORD_INTEGRITY_DENIED')
                result.append({'position':position,'record':record,'record_sha256':digest,'entry_sha256':entry_digest,
                               'currentness':'UNKNOWN_REQUIRES_AUTHORITY_REVALIDATION'})
            self._stable();self.connection.execute('COMMIT')
            return {'pending':result,'authority_effect':'NONE','dispatch_effect':'NONE',
                    'work_proof':False,'scheduler_state':'UNPROVEN'}
        except Exception:
            if self.connection.in_transaction:
                self.connection.execute('ROLLBACK')
            raise

    def complete_head(self, expected):
        """CAS metadata only; caller must first authenticate exact consumption."""
        self._stable();self.connection.execute('BEGIN IMMEDIATE')
        try:
            self._schema()
            row=self.connection.execute('SELECT position,record,record_sha256,entry_sha256,task_id,dedupe_key '
                'FROM pending ORDER BY position LIMIT 1').fetchone()
            if (row is None or row[0]!=expected['position']
                    or row[1]!=self._encode(expected['record'])
                    or row[2]!=expected['record_sha256'] or row[3]!=expected['entry_sha256']
                    or hashlib.sha256(row[1]).hexdigest()!=row[2]
                    or self._entry_digest(row[0],row[2])!=row[3]
                    or row[4]!=expected['record']['task_id']
                    or row[5]!=expected['record']['dedupe_key']):
                raise OperationsDenied('QUEUE_HEAD_CHANGED')
            self.connection.execute('DELETE FROM pending WHERE position=? AND record_sha256=? '
                'AND entry_sha256=?',(row[0],row[2],row[3]))
            self._stable();self.connection.execute('COMMIT')
        except Exception:
            if self.connection.in_transaction:
                self.connection.execute('ROLLBACK')
            raise

    def select_installed_conversation(self, *, root, now, payload=None,
                                      authenticated_caller=None):
        """Make one FIFO decision from actual queue and installed policy.

        Pending metadata is not an executable request. Missing material stays
        held; supplied material must match the exact head and current signed
        policy. Selection neither removes work nor forwards/admit anything.
        Caller identity comes from the owning authenticated ingress, not JSON.
        """
        from .authority_contract import (canonical, read_consumer_installed_policy_evidence,
                                         match_installed_stage1_conversation)
        policy=read_consumer_installed_policy_evidence(root=root)
        before=self.snapshot()
        head=before['pending'][0] if before['pending'] else None
        matched=None
        if head is None:
            state='IDLE_NO_PENDING_WORK'
        elif payload is None:
            state='HELD_REQUEST_MATERIAL_REQUIRED'
        else:
            matched=match_installed_stage1_conversation(payload,
                authenticated_caller=authenticated_caller,root=root,now=now)
            record=head['record']
            # These are provenance references, never a grant derived from a
            # digest. Recovered metadata cannot manufacture a request/client.
            if (record['owner_domain']!='KERNEL'
                    or record['task_id']!=matched['request_id']
                    or record['request_digest']!=matched['request_sha256']
                    or record['policy_digest']!=matched['installed_policy']['policy_sha256']
                    or record['authority_digest']!=matched['installed_policy']['evidence_sha256']):
                state='HELD_QUEUE_INPUT_MISMATCH'
                matched=None
            else:
                state='SELECTED_PENDING_CURRENT_DOMAIN_GATES'
        fresh=read_consumer_installed_policy_evidence(root=root)
        if (canonical(fresh)!=canonical(policy) or self.snapshot()!=before
                or matched is not None and canonical(matched['installed_policy'])!=canonical(policy)):
            raise OperationsDenied('SCHEDULER_SELECTION_INPUT_CHANGED')
        return {'state':state,'head':head,'matched':matched,
                'pending_count':len(before['pending']),
                'queue_sha256':hashlib.sha256(canonical(before)).hexdigest(),
                'boot_id':policy['boot_id'],'installed_evidence_sha256':policy['evidence_sha256'],
                'authority_effect':'NONE','admission_effect':'NONE','dispatch_effect':'NONE',
                'work_proof':False}

    def close(self):
        if self.connection is not None:
            self.connection.close();self.connection=None
        if self._parent_fd is not None:
            os.close(self._parent_fd);self._parent_fd=None


def _regular_bytes(path: Path, *, expected_size: int | None = None,
                   custody=None, include_fact=False, identity_only=False):
    """Adapt Authority's fd/nofollow reader; never fix permissions while reading."""
    path=Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise OperationsDenied('REPLAY_INPUT_PATH_DENIED')
    def identity(info):
        custody_identity=(info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,
                          info.st_nlink)
        # SQLite is a live database, not an immutable source artifact. Its
        # contents are authenticated inside a read snapshot below.
        return (custody_identity if identity_only else custody_identity +
                (info.st_size,info.st_mtime_ns,info.st_ctime_ns))
    def directory(info):
        return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid)
    handles=[]
    try:
        fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        handles.append((fd,None,None,directory(os.fstat(fd))))
        for part in path.parts[1:-1]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            handles.append((child,fd,part,directory(os.fstat(child))));fd=child
        file_fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
        with os.fdopen(file_fd,'rb') as stream:
            before=os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink!=1
                    or before.st_size>16*1024*1024
                    or (expected_size is not None and before.st_size!=expected_size)
                    or (custody is not None and
                        (before.st_uid,before.st_gid,stat.S_IMODE(before.st_mode))!=custody)):
                raise OperationsDenied('REPLAY_INPUT_CUSTODY_DENIED')
            # procfs boot identity has nominal size zero; bound that read too.
            bound=before.st_size+1 if before.st_size else 4096
            raw=b'' if identity_only else stream.read(bound)
            if not identity_only:
                stream.seek(0)
                if stream.read(bound)!=raw or (before.st_size and len(raw)!=before.st_size):
                    raise OperationsDenied('REPLAY_INPUT_CHANGED')
            after=os.fstat(stream.fileno());named=os.stat(path.name,dir_fd=fd,follow_symlinks=False)
            if (identity(before)!=identity(after) or identity(before)!=identity(named)
                    or after.st_size>16*1024*1024 or named.st_size>16*1024*1024):
                raise OperationsDenied('REPLAY_INPUT_CHANGED')
        for child,parent,name,captured in handles:
            named=os.stat('/',follow_symlinks=False) if parent is None else os.stat(name,dir_fd=parent,follow_symlinks=False)
            if directory(os.fstat(child))!=captured or directory(named)!=captured:
                raise OperationsDenied('REPLAY_PARENT_CHANGED')
        return (raw,identity(before)) if include_fact else raw
    except OSError as exc:
        raise OperationsDenied('IMMUTABLE_REPLAY_INPUT_DENIED') from exc
    finally:
        for handle,_,_,_ in reversed(handles):os.close(handle)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _replay_contract():
    """Use the existing manifest-installed contract, without changing sys.path."""
    raw,fact = _regular_bytes(REPLAY_CONTRACT,custody=(0,0,0o644),include_fact=True)
    if hashlib.sha256(raw).hexdigest()!=REPLAY_CONTRACT_SHA256:
        raise OperationsDenied('REPLAY_CONTRACT_SOURCE_DENIED')
    spec = importlib.util.spec_from_file_location('_kernel_replay_contract', REPLAY_CONTRACT)
    module = importlib.util.module_from_spec(spec)
    exec(compile(raw, str(REPLAY_CONTRACT), 'exec'), module.__dict__)
    return module,raw,fact


def _strict_json(raw):
    def pairs(items):
        result = {}
        for name, value in items:
            if name in result:
                raise ValueError('duplicate replay field')
            result[name] = value
        return result
    def constant(value):
        raise ValueError('nonfinite replay value')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def observe(*, boot_id_path: Path, descriptor_path: Path, key_path: Path,
            database_path: Path, sequence: int, monotonic_ns: int | None = None,
            observed_at: str | None = None, previous: dict[str, object] | None = None,
            queue: OperationsQueue | None = None, installed_root: Path | None = None) -> dict[str, object]:
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
        raise OperationsDenied("HEARTBEAT_SEQUENCE_DENIED")
    # The owning process supplies its existing durable queue, never ingress
    # metadata, an arbitrary readiness callback or a guessed storage path.
    # Snapshot integrity establishes pending metadata, not current authority.
    if queue is not None and type(queue) is not OperationsQueue:
        raise OperationsDenied('OPERATIONS_QUEUE_OWNER_DENIED')
    queued = None if queue is None else queue.snapshot()
    replay_owner=pwd.getpwnam('serein-stage1')
    key_custody=(replay_owner.pw_uid,replay_owner.pw_gid,0o600)
    boot_raw,boot_fact = _regular_bytes(boot_id_path,include_fact=True)
    boot_id = boot_raw.decode("ascii").strip()
    descriptor_raw,descriptor_fact = _regular_bytes(descriptor_path,custody=(0,0,0o644),include_fact=True)
    key,key_fact = _regular_bytes(key_path,expected_size=32,custody=key_custody,include_fact=True)
    try:
        descriptor = _strict_json(descriptor_raw)
        trusted_key_receipt = descriptor["body"]["trusted_key_receipt"]
    except (UnicodeError, ValueError, KeyError, TypeError) as exc:
        raise OperationsDenied("IMMUTABLE_REPLAY_INPUT_DENIED") from exc
    if not isinstance(trusted_key_receipt, str) or not trusted_key_receipt:
        raise OperationsDenied("IMMUTABLE_REPLAY_INPUT_DENIED")
    installed = None
    if installed_root is not None:
        from .authority_contract import read_consumer_installed_policy_evidence, canonical
        installed = read_consumer_installed_policy_evidence(root=installed_root)
        origin = installed.get('replay_origin',{'plan_sha256':installed['plan_sha256'],
            'source_generation':installed['evidence']['source_generation']})
        body = descriptor['body']
        if (installed['boot_id']!=boot_id or body['source_generation']!=origin['source_generation']
                or body['store_id']!=str(uuid5(NAMESPACE_URL,'serein-kernel-store:'+origin['plan_sha256']))
                or body['trusted_key_receipt']!=str(uuid5(NAMESPACE_URL,'serein-kernel-key:'+origin['plan_sha256']))):
            raise OperationsDenied('REPLAY_OWNER_INSTALL_BINDING_DENIED')
    contract,contract_raw,contract_fact = _replay_contract()
    try:
        body = descriptor['body']
        contract.verify_descriptor(descriptor, key=key,
            expected_store_id=body['store_id'], expected_backend_identity='SEREIN_KERNEL_REPLAY',
            expected_issuer='KERNEL_AUTHORITY', expected_observer='OUTPOST',
            expected_key_fingerprint=hashlib.sha256(key).hexdigest(),
            expected_key_receipt=trusted_key_receipt,
            expected_target={'vm_id':'VM4010', 'boot_id':boot_id},
            expected_generation=body['source_generation'])
    except (ValueError, KeyError, TypeError) as exc:
        raise OperationsDenied('REPLAY_DESCRIPTOR_AUTHENTICITY_DENIED') from exc
    _,database_fact=_regular_bytes(database_path,custody=key_custody,include_fact=True,identity_only=True)
    try:
        uri = f"file:{quote(database_path.as_posix(), safe='/')}?mode=ro"
        with sqlite3.connect(uri, uri=True) as connection:
            connection.execute('PRAGMA query_only=ON')
            connection.execute('BEGIN')
            schema = {(kind,name,table,None if sql is None else ''.join(sql.split()))
                      for kind,name,table,sql in connection.execute(
                          'SELECT type,name,tbl_name,sql FROM sqlite_master')}
            expected_schema = {
                ('table','receipts','receipts','CREATETABLEreceipts(chain_idTEXTNOTNULL,'
                 'revisionINTEGERNOTNULL,receipt_sha256TEXTNOTNULLUNIQUE,canonical_jsonBLOBNOTNULL,'
                 'PRIMARYKEY(chain_id,revision))'),
                ('index','sqlite_autoindex_receipts_1','receipts',None),
                ('index','sqlite_autoindex_receipts_2','receipts',None)}
            dispatch_schema = {
                ('table','dispatches','dispatches','CREATETABLEdispatches('
                 'chain_idTEXTPRIMARYKEYNOTNULL,bindingBLOBNOTNULL,outcomeBLOB)'),
                ('index','sqlite_autoindex_dispatches_1','dispatches',None)}
            if schema not in (expected_schema, expected_schema | dispatch_schema):
                raise OperationsDenied('REPLAY_DATABASE_SCHEMA_DENIED')
            if _regular_bytes(database_path,custody=key_custody,include_fact=True,identity_only=True)[1]!=database_fact:
                raise OperationsDenied('REPLAY_DATABASE_CHANGED')
            integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
            receipt_count = int(connection.execute("SELECT COUNT(*) FROM receipts").fetchone()[0])
            if integrity != 'ok' or not 0 <= receipt_count < MAX_RECEIPTS:
                raise OperationsDenied('OPERATIONS_RECOVERY_DENIED')
            records = connection.execute(
                'SELECT chain_id,revision,canonical_json,receipt_sha256 FROM receipts ORDER BY chain_id,revision LIMIT ?',
                (MAX_RECEIPTS,)).fetchall()
            has_bindings = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='dispatches'").fetchone()
            binding_rows = (connection.execute(
                'SELECT chain_id,binding,outcome FROM dispatches LIMIT ?', (MAX_RECEIPTS,)).fetchall()
                if has_bindings else [])
            effective_observed_at = observed_at or _utc_now()
    except (sqlite3.Error, TypeError, ValueError) as exc:
        raise OperationsDenied("REPLAY_DATABASE_DENIED") from exc
    try:
        chains = {}
        for chain_id, revision, raw, receipt_digest in records:
            if not isinstance(chain_id, str) or not chain_id or type(revision) is not int:
                raise ValueError('replay database identity is malformed')
            receipt = _strict_json(bytes(raw))
            if (not isinstance(raw, bytes) or len(raw) > 16384
                    or contract.canonical_bytes(receipt) != raw
                    or contract.receipt_hash(receipt) != receipt_digest
                    or receipt['body']['action_nonce'] != chain_id
                    or type(receipt['body']['revision']) is not int
                    or receipt['body']['revision'] != revision):
                raise ValueError('replay database revision differs from signed receipt')
            chains.setdefault(chain_id, []).append(receipt)
        replay_history = contract.verify_stored_history(list(chains.values()), descriptor=descriptor,
                                                       key=key, current_time=effective_observed_at)
        bindings, binding_bytes = contract.verify_dispatch_bindings(
            binding_rows, chains, descriptor=descriptor, key=key,
            allow_conversation_history=installed is not None)
        if binding_bytes + sum(len(row[2]) for row in records) > 1048576:
            raise ValueError('replay observation capacity exceeded')
        dispatch_history = {
            'integrity': ('AUTHENTICATED_DISPATCH_CORRELATION' if bindings
                          else 'EMPTY_NO_AUTHENTICATED_DISPATCHES'),
            'reserved': sum(len(chains[nonce]) == 2 for nonce in bindings),
            'completed_results': sum(len(chains[nonce]) == 3 for nonce in bindings),
            'authority_effect':'NONE', 'physical_effect':'UNVERIFIED'}
        # Authenticated expired attempts remain recovery evidence, not active
        # work. Their immutable RESERVED heads never authorize retry/consume.
        # Keep the observer alive: unrelated lease expiry must not stop the
        # scheduler's cadence or conceal its truthful recovery/UNKNOWN state.
        active_leases = replay_history['active_reservations']
    except (UnicodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise OperationsDenied("REPLAY_LEASE_STATE_DENIED") from exc
    healthy = integrity == "ok" and 0 <= receipt_count < MAX_RECEIPTS
    if not healthy:
        raise OperationsDenied("OPERATIONS_RECOVERY_DENIED")
    if (_regular_bytes(REPLAY_CONTRACT,custody=(0,0,0o644),include_fact=True)!=(contract_raw,contract_fact)
            or _regular_bytes(boot_id_path,include_fact=True)!=(boot_raw,boot_fact)
            or _regular_bytes(descriptor_path,custody=(0,0,0o644),include_fact=True)!=(descriptor_raw,descriptor_fact)
            or _regular_bytes(key_path,expected_size=32,custody=key_custody,include_fact=True)!=(key,key_fact)
            or _regular_bytes(database_path,custody=key_custody,include_fact=True,identity_only=True)[1]!=database_fact):
        raise OperationsDenied('REPLAY_OBSERVATION_CHANGED')
    current_ns = time.monotonic_ns() if monotonic_ns is None else monotonic_ns
    if type(current_ns) is not int or current_ns < 0:
        raise OperationsDenied("HEARTBEAT_CLOCK_DENIED")
    bpm = 0
    cadence_state = "UNPROVEN"
    missed = 0
    missed_total = 0
    last_missed = None
    previous_sequence = None
    if previous is not None and previous.get("schema") == SCHEMA and previous.get("boot_id") == boot_id:
        try:
            previous_ns = int(previous["monotonic_ns"])
            previous_sequence = int(previous["sequence"])
            if sequence != previous_sequence + 1:
                raise ValueError("heartbeat sequence is not monotonic and contiguous")
            missed_total = int(previous.get("missed_heartbeats_total", 0))
            last_missed = previous.get("last_missed_heartbeat_at")
            gap = current_ns - previous_ns
            if gap <= 0:
                raise ValueError("monotonic clock did not advance")
            bpm = 60_000_000_000 / gap
            cadence_state = "OBSERVED" if bpm >= 60 else "DEGRADED"
            missed = max(0, gap // int(HEARTBEAT_FLOOR_SECONDS * 1_000_000_000) - 1)
            if missed:
                missed_total += missed
                last_missed = effective_observed_at
        except (KeyError, TypeError, ValueError) as exc:
            raise OperationsDenied("HEARTBEAT_PREDECESSOR_DENIED") from exc
    if installed is not None and canonical(read_consumer_installed_policy_evidence(root=installed_root))!=canonical(installed):
        raise OperationsDenied('REPLAY_OWNER_INPUT_CHANGED')
    result = {
        "schema": SCHEMA,
        "boot_id": boot_id,
        "sequence": sequence,
        "observed_at": effective_observed_at,
        "monotonic_ns": current_ns,
        "bpm": bpm,
        "cadence_state": cadence_state,
        "heartbeat_scope": "REPLAY_OBSERVER_ONLY" if queued is None else "REPLAY_AND_QUEUE_OBSERVER_ONLY",
        "scheduler_state": "UNPROVEN",
        "queues": "UNKNOWN" if queued is None else "PENDING_METADATA_OBSERVED",
        "queue_depth": None if queued is None else len(queued['pending']),
        "replay_receipts": receipt_count,
        "leases": "UNKNOWN",
        "active_leases": active_leases,
        "replay_history": replay_history,
        "dispatch_history": dispatch_history,
        "recovery": "UNKNOWN",
        "unproven": ["task_queues", "lease_authenticity", "recovery_controls", "scheduler_decisions"],
        "event": "MISSED_HEARTBEAT" if missed else ("BOOT_BOUND_START" if previous_sequence is None else "HEARTBEAT"),
        "previous_sequence": previous_sequence,
        "missed_heartbeats_current": missed,
        "missed_heartbeats_total": missed_total,
        "last_missed_heartbeat_at": last_missed,
        "replay_inputs": {
            "contract_sha256": hashlib.sha256(contract_raw).hexdigest(),
            "descriptor_sha256": hashlib.sha256(descriptor_raw).hexdigest(),
            "key_sha256": hashlib.sha256(key).hexdigest(),
            "trusted_key_receipt": trusted_key_receipt,
            "database_integrity": integrity,
        },
        "authority_effect": "NONE",
    }
    if queue is not None:
        # Reject an intervening queue change instead of presenting the two
        # stores as one coherent snapshot. Neither store is repaired here.
        if queue.snapshot() != queued:
            raise OperationsDenied('OPERATIONS_QUEUE_OBSERVATION_CHANGED')
        result['queue_observation'] = queued
    return result


def atomic_write(path: Path, value: dict[str, object]) -> None:
    path=Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise OperationsDenied('OPERATIONS_OUTPUT_PATH_DENIED')
    payload = (json.dumps(value, sort_keys=True, separators=(",", ":"),allow_nan=False) + "\n").encode()
    if len(payload)>16*1024*1024:
        raise OperationsDenied('OPERATIONS_OUTPUT_SIZE_DENIED')
    handles=[];temporary=None;descriptor=-1;created=None
    def identity(info):
        return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid)
    try:
        fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        handles.append((fd,None,None,identity(os.fstat(fd))))
        for part in path.parts[1:-1]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            handles.append((child,fd,part,identity(os.fstat(child))));fd=child
        parent=os.fstat(fd)
        if parent.st_uid!=os.geteuid() or stat.S_IMODE(parent.st_mode)!=0o700:
            raise OperationsDenied('OPERATIONS_OUTPUT_PARENT_DENIED')
        def stable():
            for opened,ancestor,name,captured in handles:
                named=os.stat('/',follow_symlinks=False) if ancestor is None else os.stat(name,dir_fd=ancestor,follow_symlinks=False)
                if identity(os.fstat(opened))!=captured or identity(named)!=captured:
                    raise OperationsDenied('OPERATIONS_OUTPUT_PARENT_CHANGED')
        try:
            before=os.stat(path.name,dir_fd=fd,follow_symlinks=False)
        except FileNotFoundError:
            before=None
        if before is not None and (not stat.S_ISREG(before.st_mode) or before.st_nlink!=1
                or (before.st_uid,before.st_gid,stat.S_IMODE(before.st_mode))!=(os.geteuid(),os.getegid(),0o600)):
            raise OperationsDenied('OPERATIONS_OUTPUT_CUSTODY_DENIED')
        descriptor,temporary_path=tempfile.mkstemp(prefix='.kernel-operations-',dir=f'/proc/self/fd/{fd}')
        temporary=Path(temporary_path).name
        created=identity(os.fstat(descriptor))
        with os.fdopen(descriptor, "w+b") as stream:
            descriptor = -1
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
            def owned_bytes(name):
                opened=os.fstat(stream.fileno())
                named=os.stat(name,dir_fd=fd,follow_symlinks=False)
                return (identity(opened)==created==identity(named)
                    and opened.st_nlink==named.st_nlink==1
                    and opened.st_size==named.st_size==len(payload)
                    and os.pread(stream.fileno(),len(payload)+1,0)==payload)
            stable()
            try:current=os.stat(path.name,dir_fd=fd,follow_symlinks=False)
            except FileNotFoundError:current=None
            # Readers legitimately update atime. Bind every custody/content
            # metadata field instead, retaining nanosecond mutation precision.
            def prestate(info):
                if info is None:return None
                return (*identity(info),info.st_nlink,info.st_size,
                        info.st_mtime_ns,info.st_ctime_ns)
            if prestate(current)!=prestate(before):
                raise OperationsDenied('OPERATIONS_OUTPUT_PRESTATE_CHANGED')
            if not owned_bytes(temporary):
                raise OperationsDenied('OPERATIONS_OUTPUT_TEMP_CHANGED')
            os.replace(temporary,path.name,src_dir_fd=fd,dst_dir_fd=fd)
            temporary=None
            os.fsync(fd)
            stable()
            if not owned_bytes(path.name):
                raise OperationsDenied('OPERATIONS_OUTPUT_PUBLICATION_CHANGED')
    finally:
        try:
            if descriptor != -1:
                os.close(descriptor)
            if temporary is not None and created is not None:
                try:named=os.stat(temporary,dir_fd=fd,follow_symlinks=False)
                except FileNotFoundError:pass
                else:
                    if identity(named)==created and named.st_nlink==1:
                        os.unlink(temporary,dir_fd=fd)
        finally:
            for opened,_,_,_ in reversed(handles):os.close(opened)


def serve_installed(*, root, database_path, queue_path, output_path, clock, stop=None):
    """Own the installed Operations resources for one process lifetime.

    The complete-domain launcher supplies exact private paths. This does not
    install a service, create directories, change privilege, start Interface,
    dispatch queued work or promote its telemetry into admission evidence.
    Failed/restarted attempts retain the same durable queue and replay store.
    """
    root=Path(root)
    paths=tuple(Path(value) for value in (database_path,queue_path,output_path))
    if (not root.is_absolute() or '..' in root.parts
            or any(not path.is_absolute() or '..' in path.parts
                   or not path.is_relative_to(root/'var/lib/serein/kernel') for path in paths)
            or len({path.parent for path in paths})!=1 or len(set(paths))!=3
            or any(path.name.endswith(('-journal','-wal','-shm')) for path in paths)):
        raise OperationsDenied('OPERATIONS_OWNER_PATH_DENIED')
    database_path,queue_path,output_path=paths
    # Opening this owner proves installed inputs and actual uid before any
    # queue/output effect; its per-operation/final guards remain in force.
    with installed_replay_owner(root=root,database_path=database_path,clock=clock) as replay_store:
        queue=OperationsQueue(queue_path)
        try:
            if output_path.exists() or output_path.is_symlink():
                _regular_bytes(output_path,custody=(os.geteuid(),os.getegid(),0o600))
            serve(output_path=output_path,boot_id_path=root/'proc/sys/kernel/random/boot_id',
                descriptor_path=root/'var/lib/serein/kernel/authority/replay-descriptor.json',
                key_path=root/'var/lib/serein/kernel/authority/replay.key',
                database_path=database_path,stop=stop,queue=queue,installed_root=root,
                replay_store=replay_store)
        finally:
            queue.close()


def record_operations_observation(value, *, root):
    """Actual fixed private Audit round trip; recording grants no authority."""
    from .audit import operations_event, EXCHANGE_TIMEOUT_SECONDS
    from .authority_contract import canonical
    from .conversation_runtime import _decode
    from .kernel import exchange_private_service
    event=operations_event(value)
    payload=canonical(event)
    raw=exchange_private_service('AUDIT',payload,
        timeout_seconds=EXCHANGE_TIMEOUT_SECONDS,root=root)
    if _decode(raw,4096)!={'status':'RECORDED'}:
        raise OperationsDenied('OPERATIONS_AUDIT_DENIED')
    return {'state':'OBSERVATION_RECORDED_ONLY',
            'event_sha256':hashlib.sha256(payload).hexdigest(),'authority_effect':'NONE'}


def _replay_progression(prior, current):
    # The existing same-boot lifecycle only appends receipts/chains. Active
    # reservations may decrease on consumption, these totals may not.
    for field in ('chains','receipts','consumed_chains'):
        before=prior.get(field);after=current.get(field)
        if (type(before) is not int or type(after) is not int or before<0
                or after<before):
            raise OperationsDenied('OPERATIONS_REPLAY_HISTORY_REGRESSED')


def serve(*, output_path: Path, boot_id_path: Path, descriptor_path: Path,
          key_path: Path, database_path: Path, stop: threading.Event | None = None,
          queue: OperationsQueue | None = None, installed_root: Path | None = None,
          replay_store=None) -> None:
    if installed_root is not None and type(queue) is not OperationsQueue:
        raise OperationsDenied('SCHEDULER_QUEUE_OWNER_REQUIRED')
    if replay_store is not None and (installed_root is None
            or replay_store.path!=Path(database_path) or replay_store.connection is None):
        raise OperationsDenied('OPERATIONS_REPLAY_OWNER_REQUIRED')
    stopped = stop or threading.Event()
    if stop is None:
        signal.signal(signal.SIGTERM, lambda *_: stopped.set())
        signal.signal(signal.SIGINT, lambda *_: stopped.set())
    previous = None
    if output_path.exists() or output_path.is_symlink():
        candidate=_strict_json(_regular_bytes(output_path,custody=(os.geteuid(),os.getegid(),0o600)))
        if (not isinstance(candidate,dict) or candidate.get('schema')!=SCHEMA
                or type(candidate.get('sequence')) is not int or candidate['sequence']<1
                or type(candidate.get('monotonic_ns')) is not int or candidate['monotonic_ns']<0):
            raise OperationsDenied('OPERATIONS_PREDECESSOR_DENIED')
        previous=candidate
    current_boot = _regular_bytes(boot_id_path).decode("ascii").strip()
    if previous is not None and previous.get("boot_id") != current_boot:
        previous = None
    sequence = int(previous.get("sequence", 0)) if previous else 0
    deadline = time.monotonic()
    def next_tick():
        nonlocal deadline
        deadline += INTERVAL_SECONDS
        stopped.wait(max(0.0, deadline - time.monotonic()))

    while not stopped.is_set():
        next_sequence = sequence + 1
        selection=None
        if installed_root is not None:
            selection=queue.select_installed_conversation(root=installed_root,
                now=datetime.now(timezone.utc))
        value=observe(
            boot_id_path=boot_id_path, descriptor_path=descriptor_path,
            key_path=key_path, database_path=database_path, sequence=next_sequence,
            previous=previous, queue=queue, installed_root=installed_root,
        )
        if previous is not None:
            _replay_progression(previous['replay_history'],value['replay_history'])
        if selection is not None:
            from .authority_contract import canonical
            if replay_store is not None:
                # Existing recover() authenticates retained state inside a
                # read transaction; it never resumes or replays an effect.
                continuity=replay_store.recover(clock=_utc_now)
                _replay_progression(value['replay_history'],continuity)
                if canonical(continuity)!=canonical(value['replay_history']):
                    # Both snapshots authenticated; legitimate concurrent
                    # work invalidates this sample, not the process owner.
                    next_tick()
                    continue
                value['replay_continuity']=continuity
            fresh=queue.select_installed_conversation(root=installed_root,
                now=datetime.now(timezone.utc))
            if (selection['boot_id']!=value['boot_id']
                    or canonical(fresh)!=canonical(selection)
                    or selection['queue_sha256']!=hashlib.sha256(canonical(value['queue_observation'])).hexdigest()):
                raise OperationsDenied('SCHEDULER_OBSERVATION_CHANGED')
            # A real FIFO decision, but no material was supplied to this
            # sampler. It must not advertise dispatch or complete Phase B.
            value['scheduler_decision']=selection
            value['scheduler_state']='QUEUE_SELECTION_OBSERVED_NOT_DISPATCH'
            value['audit_observation']=record_operations_observation(value,root=installed_root)
            # Audit is a bounded socket wait. Preserve its actual record on
            # subsequent drift, but never publish it as current latest proof.
            after_audit=queue.select_installed_conversation(root=installed_root,
                now=datetime.now(timezone.utc))
            if (canonical(after_audit)!=canonical(selection)
                    or _regular_bytes(boot_id_path).decode('ascii').strip()!=selection['boot_id']):
                raise OperationsDenied('SCHEDULER_OBSERVATION_CHANGED_AFTER_AUDIT')
            if replay_store is not None:
                continuity=replay_store.recover(clock=_utc_now)
                _replay_progression(value['replay_continuity'],continuity)
                if canonical(continuity)!=canonical(value['replay_continuity']):
                    # Preserve the Audit record but do not publish stale proof.
                    next_tick()
                    continue
        atomic_write(output_path,value)
        sequence = next_sequence
        # Keep this process's actual observation, not an untrusted replacement
        # of the output pathname between publication and the next cycle.
        previous = _strict_json(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode())
        next_tick()
