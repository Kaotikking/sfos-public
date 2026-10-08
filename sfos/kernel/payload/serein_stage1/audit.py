"""Append-only JSON-lines audit writer for Stage-1 decisions."""

from __future__ import annotations

import json
import hashlib
import math
import os
import socket
import stat
import time
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from .supervision import inherited_systemd_socket, ready_and_watch

# Preserve the existing HAOS Gateway's 64KiB response contract. Tool rounds
# permit 32KiB of arguments; the old 16KiB audit cap rejected valid answers.
# This is still bounded and does not change event authority or acknowledgements.
MAX_EVENT_BYTES = 64 * 1024
EXCHANGE_TIMEOUT_SECONDS = 2.0
REQUIRED_EVENT_FIELDS = frozenset({"schema", "request_id", "status", "reason", "timestamp"})
OPERATIONS_SCHEMA = 'SEREIN/KernelOperationsHeartbeat/v1'
OPERATIONS_FIELDS = frozenset({'schema','boot_id','sequence','observed_at','monotonic_ns',
    'bpm','cadence_state','heartbeat_scope','scheduler_state','queues','queue_depth',
    'leases','active_leases','recovery','event','authority_effect','unproven',
    'installed_evidence_sha256','queue_sha256','observation_sha256','scheduler_decision'})


def operations_event(observation: dict[str, Any]) -> dict[str, Any]:
    """Reduced private observation, not a response, global EVT or work proof."""
    from .authority_contract import canonical
    selected = observation['scheduler_decision']
    extra = {'installed_evidence_sha256','queue_sha256','observation_sha256','scheduler_decision'}
    event = {name: observation[name] for name in OPERATIONS_FIELDS - extra}
    event.update(installed_evidence_sha256=selected['installed_evidence_sha256'],
        queue_sha256=selected['queue_sha256'], scheduler_decision=selected['state'],
        observation_sha256=hashlib.sha256(canonical(observation)).hexdigest())
    if 'replay_continuity' in observation:
        event['replay_continuity']=observation['replay_continuity']
    return decode_event(canonical(event))


def _validate_operations_event(event):
    if set(event) not in (OPERATIONS_FIELDS,OPERATIONS_FIELDS|{'replay_continuity'}):
        raise ValueError('invalid_operations_event_shape')
    if 'replay_continuity' in event:
        continuity=event['replay_continuity']
        counts=('chains','receipts','active_reservations','expired_reservations','consumed_chains')
        if (not isinstance(continuity,dict) or set(continuity)!=set(counts)|{'integrity','authority_effect','work_proof'}
                or any(type(continuity[key]) is not int or not 0<=continuity[key]<4096 for key in counts)
                or not continuity['chains']<=continuity['receipts']<=3*continuity['chains']
                or sum(continuity[key] for key in counts[2:])>continuity['chains']
                or continuity['active_reservations']!=event['active_leases']
                or continuity['integrity']!=('AUTHENTICATED_REPLAY_HISTORY' if continuity['chains'] else 'EMPTY_NO_AUTHENTICATED_RECEIPTS')
                or continuity['authority_effect']!='NONE' or continuity['work_proof'] is not False):
            raise ValueError('invalid_operations_continuity')
        # Expired reservations are authenticated historical evidence. Record
        # their separate count; never turn it into active work, recovery success
        # or admission, and never stop Audit merely because work timed out.
    try:
        if str(UUID(event['boot_id'])) != event['boot_id']:
            raise ValueError('invalid_boot')
        at = datetime.fromisoformat(event['observed_at'].replace('Z','+00:00'))
        if at.tzinfo is None or at.utcoffset() is None:
            raise ValueError('invalid_time')
    except (AttributeError, TypeError, ValueError) as error:
        raise ValueError('invalid_operations_event_identity') from error
    for name in ('sequence','monotonic_ns','queue_depth','active_leases'):
        if type(event[name]) is not int or event[name] < (1 if name == 'sequence' else 0):
            raise ValueError('invalid_operations_event_count')
    for name in ('installed_evidence_sha256','queue_sha256','observation_sha256'):
        value = event[name]
        if not isinstance(value,str) or len(value)!=64 or any(c not in '0123456789abcdef' for c in value):
            raise ValueError('invalid_operations_event_digest')
    if (type(event['bpm']) not in (int,float) or event['bpm'] < 0 or event['bpm'] > 60_000_000_000
            or not math.isfinite(event['bpm'])
            or event['cadence_state'] not in ('UNPROVEN','OBSERVED','DEGRADED')
            or event['heartbeat_scope'] != 'REPLAY_AND_QUEUE_OBSERVER_ONLY'
            or event['scheduler_state'] != 'QUEUE_SELECTION_OBSERVED_NOT_DISPATCH'
            or event['queues'] != 'PENDING_METADATA_OBSERVED'
            or event['leases'] != 'UNKNOWN' or event['recovery'] != 'UNKNOWN'
            or event['unproven'] != ['task_queues','lease_authenticity','recovery_controls','scheduler_decisions']
            or event['authority_effect'] != 'NONE'
            or event['event'] not in ('BOOT_BOUND_START','HEARTBEAT','MISSED_HEARTBEAT')
            or event['scheduler_decision'] != ('IDLE_NO_PENDING_WORK' if event['queue_depth']==0
                                               else 'HELD_REQUEST_MATERIAL_REQUIRED')):
        raise ValueError('operations_event_not_observation_only')
    if ((event['cadence_state']=='UNPROVEN' and event['bpm']!=0)
            or (event['cadence_state']=='OBSERVED' and event['bpm']<60)
            or (event['cadence_state']=='DEGRADED' and not 0<event['bpm']<60)):
        raise ValueError('operations_event_cadence_contradiction')
    return event


def append_event(path: Path, event: dict[str, Any]) -> None:
    """Append privately, adopting only this writer's exact legacy 0644 inode.

    Never replace, truncate, rotate or chmod a pathname. Descriptor-anchored
    custody checks precede adoption and append; failed persistence gets no ACK.
    """
    path=Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('audit_write_path_denied')
    raw=(json.dumps(event,sort_keys=True,separators=(',',':'))+'\n').encode('utf-8')
    uid,gid=os.geteuid(),os.getegid()
    def directory(info):
        return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid)
    def identity(info):
        return (*directory(info),info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
    handles=[];created_parents=[];file_fd=None;created=False
    try:
        fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        handles.append((fd,None,None,directory(os.fstat(fd))))
        for part in path.parts[1:-1]:
            try:child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            except FileNotFoundError:
                os.mkdir(part,0o700,dir_fd=fd);created_parents.append(fd)
                child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            handles.append((child,fd,part,directory(os.fstat(child))));fd=child
        parent=os.fstat(fd)
        if (parent.st_uid,parent.st_gid,stat.S_IMODE(parent.st_mode))!=(uid,gid,0o700):
            raise ValueError('audit_parent_custody_denied')
        def stable_parents():
            for child,parent,name,captured in handles:
                named=os.stat('/',follow_symlinks=False) if parent is None else os.stat(name,dir_fd=parent,follow_symlinks=False)
                if directory(os.fstat(child))!=captured or directory(named)!=captured:
                    raise ValueError('audit_parent_changed')
        stable_parents()
        flags=os.O_WRONLY|os.O_APPEND|os.O_NOFOLLOW|os.O_NONBLOCK
        try:file_fd=os.open(path.name,flags,dir_fd=fd)
        except FileNotFoundError:
            file_fd=os.open(path.name,flags|os.O_CREAT|os.O_EXCL,0o600,dir_fd=fd)
            created=True
        before=os.fstat(file_fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink!=1
                or (before.st_uid,before.st_gid)!=(uid,gid)
                or (stat.S_IMODE(before.st_mode)&~0o600 if created else
                    stat.S_IMODE(before.st_mode) not in (0o600,0o644))):
            raise ValueError('audit_file_custody_denied')
        def stable_file(expected):
            stable_parents()
            if (identity(os.fstat(file_fd))!=identity(expected)
                    or identity(os.stat(path.name,dir_fd=fd,follow_symlinks=False))!=identity(expected)):
                raise ValueError('audit_file_changed')
        stable_file(before)
        if stat.S_IMODE(before.st_mode)!=0o600:
            # Only the verified owner inode is tightened, preserving all log
            # bytes and inode identity; no blanket permission repair.
            os.fchmod(file_fd,0o600)
            after=os.fstat(file_fd)
            if ((after.st_dev,after.st_ino,after.st_uid,after.st_gid,after.st_nlink,
                    after.st_size,after.st_mtime_ns)!=(before.st_dev,before.st_ino,
                    before.st_uid,before.st_gid,before.st_nlink,before.st_size,before.st_mtime_ns)
                    or stat.S_IMODE(after.st_mode)!=0o600):
                raise ValueError('audit_adoption_changed')
            before=after
        stable_file(before)
        remaining=memoryview(raw)
        while remaining:
            count=os.write(file_fd,remaining)
            if count<=0:raise OSError('audit_append_incomplete')
            remaining=remaining[count:]
        os.fsync(file_fd)
        after=os.fstat(file_fd)
        if (directory(after)!=directory(before) or after.st_nlink!=1
                or after.st_size!=before.st_size+len(raw)):
            raise ValueError('audit_append_changed')
        stable_file(after)
        # File fsync alone does not make its first directory entry durable.
        for directory_fd in (fd,*reversed(created_parents)):os.fsync(directory_fd)
        stable_file(after)
    finally:
        try:
            if file_fd is not None:os.close(file_fd)
        finally:
            for handle,_,_,_ in reversed(handles):os.close(handle)


def decode_event(payload: bytes) -> dict[str, Any]:
    if not isinstance(payload, bytes) or not payload or len(payload) > MAX_EVENT_BYTES:
        raise ValueError("event_too_large")
    def pairs(items):
        result = {}
        for name, value in items:
            if name in result:
                raise ValueError('duplicate_event_field')
            result[name] = value
        return result
    def constant(value):
        raise ValueError('nonfinite_event_value')
    try:
        event = json.loads(payload.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("invalid_event_json") from error
    if isinstance(event,dict) and event.get('schema') == OPERATIONS_SCHEMA:
        return _validate_operations_event(event)
    if not isinstance(event, dict) or not REQUIRED_EVENT_FIELDS.issubset(event):
        raise ValueError("invalid_event_shape")
    if (event["schema"] != "SereinStage1Response/v1" or not isinstance(event["status"], str)
            or event["status"] not in {"ANSWERED", "DENIED", "UNAVAILABLE"}):
        raise ValueError("event_not_admitted")
    return event


def read_recent_terminal(path: Path, request_id: str, *, custody) -> dict[str, Any]:
    """Read one bounded retained terminal event, never create or repair a log.

    This is custody-checked evidence, not authentication. The caller must
    compare the retained response with authenticated durable replay evidence.
    Concurrent append is allowed; replacement, truncation and changed sampled
    bytes are not. An older event outside the 1MiB window is unavailable.
    """
    path=Path(path)
    if (not path.is_absolute() or '..' in path.parts or not isinstance(request_id,str)
            or not 0<len(request_id)<=128 or '\x00' in request_id):
        raise ValueError('audit_read_identity_denied')
    def identity(info):
        return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink)
    def directory(info):
        return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid)
    handles=[]
    try:
        fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        handles.append((fd,None,None,directory(os.fstat(fd))))
        for part in path.parts[1:-1]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            handles.append((child,fd,part,directory(os.fstat(child))));fd=child
        parent=os.fstat(fd)
        if (parent.st_uid,parent.st_gid,stat.S_IMODE(parent.st_mode))!=(*custody[:2],0o700):
            raise ValueError('audit_parent_custody_denied')
        file_fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
        try:
            before=os.fstat(file_fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink!=1
                    or (before.st_uid,before.st_gid,stat.S_IMODE(before.st_mode))!=custody):
                raise ValueError('audit_file_custody_denied')
            offset=max(0,before.st_size-1024*1024)
            raw=os.pread(file_fd,before.st_size-offset,offset)
            after=os.fstat(file_fd);named=os.stat(path.name,dir_fd=fd,follow_symlinks=False)
            if (len(raw)!=before.st_size-offset or identity(before)!=identity(after)
                    or identity(before)!=identity(named) or after.st_size<before.st_size
                    or named.st_size<before.st_size
                    or os.pread(file_fd,len(raw),offset)!=raw):
                raise ValueError('audit_snapshot_changed')
        finally:os.close(file_fd)
        for child,parent,name,captured in handles:
            named=os.stat('/',follow_symlinks=False) if parent is None else os.stat(name,dir_fd=parent,follow_symlinks=False)
            if directory(os.fstat(child))!=captured or directory(named)!=captured:
                raise ValueError('audit_parent_changed')
    finally:
        for handle,_,_,_ in reversed(handles):os.close(handle)
    lines=raw.split(b'\n')
    if offset:lines=lines[1:]
    # Final unterminated append is not yet a durable event.
    lines=lines[:-1]
    matches=[]
    for line in lines:
        event=decode_event(line)
        if event.get('schema')=='SereinStage1Response/v1' and event.get('request_id')==request_id:
            matches.append(event)
    if len(matches)!=1:
        raise ValueError('audit_terminal_unavailable_or_ambiguous')
    return matches[0]


def serve_socket(server: socket.socket, audit_path: Path, *, max_events: int | None = None) -> None:
    handled = 0
    while max_events is None or handled < max_events:
        connection, _ = server.accept()
        with connection:
            deadline = time.monotonic() + EXCHANGE_TIMEOUT_SECONDS
            payload = b''
            try:
                while not payload.endswith(b'\n') and len(payload) <= MAX_EVENT_BYTES:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError('event_exchange_timeout')
                    connection.settimeout(remaining)
                    block = connection.recv(MAX_EVENT_BYTES + 1 - len(payload))
                    if not block:
                        break
                    payload += block
                if not payload.endswith(b'\n') or len(payload) > MAX_EVENT_BYTES:
                    raise ValueError('invalid_event_frame')
                event = decode_event(payload)
            except (ValueError, OSError):
                response = b'{"status":"DENIED","reason":"invalid_event_exchange"}\n'
            else:
                # Preserve storage failure as failure: never acknowledge a
                # failed append/fsync, retry it, or hide it as a peer error.
                append_event(audit_path, event)
                response = b'{"status":"RECORDED"}\n'
            try:
                connection.settimeout(EXCHANGE_TIMEOUT_SECONDS)
                connection.sendall(response)
            except OSError:
                # A disconnected peer does not erase a durably recorded event.
                pass
        handled += 1


def serve(audit_path: Path) -> None:
    with inherited_systemd_socket() as inherited:
        ready_and_watch()
        serve_socket(inherited, audit_path)
