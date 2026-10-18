"""Canonical archive verification and read-only existing-target prestate.

The historical selector, custody-repair, rollback and activation functions are
not included. Archive verification returns bytes, never extracts to disk.
"""
import io
import gzip
import hashlib
import ipaddress
import base64
import json
import math
import os
import re
import socket
import errno
import stat
import struct
import subprocess
import time
import tarfile
from dataclasses import dataclass
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key, Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from .public_installer_cli import MAX_ARCHIVE_BYTES
from .transaction import TransactionError, canonical, sha, strict_json, nofollow_ancestors

_VERIFIED = object()
# Immutable identity, not donor candidate code. Private authority evidence
# is retained in the governed transaction ledger, not public source comments.
# Rebuilding Outpost does not rotate or invalidate this preserved identity.
CANONICAL_AUTHORITY_SHA256 = "1f7533bbd5e2645f52a0d7e17502166f079a76c8c1fd31c8feaa0fc057a48652"
CANONICAL_AUTHORITY_PATH = Path("/usr/share/serein/outpost/cognition-verification.pem")
IMMUTABLE_POLICY = {
    "/etc/serein-outpost/readonly.token": "0640",
    "/etc/serein-outpost/admission.token": "0640",
    "/etc/serein-outpost/cognition-signing.pem": "0640",
    "/usr/share/serein/outpost/cognition-verification.pem": "0644",
    "/etc/serein/tls/serein-backend-cert.pem": "0600",
    "/etc/serein/tls/serein-backend-key.pem": "0600",
}

# Exact Outpost image. The legacy-named TLS unit hosts only read-only Vitals;
# the old Serein Gateway executable and downstream files are never replaced.
IMAGE_FILES = {
    'install/generation_launcher.py': ('/usr/libexec/serein/outpost-generation-launcher', '0755'),
    'systemd/serein-outpost-host-witness.service': ('/etc/systemd/system/serein-outpost-host-witness.service', '0644'),
    'systemd/serein-outpost-host-witness.timer': ('/etc/systemd/system/serein-outpost-host-witness.timer', '0644'),
    'systemd/serein-outpost.service': ('/etc/systemd/system/serein-outpost.service', '0644'),
    'systemd/serein-outpost-presentation.service': ('/etc/systemd/system/serein-outpost-presentation.service', '0644'),
    'systemd/serein-https-gateway-adapter.service': ('/etc/systemd/system/serein-https-gateway-adapter.service', '0644'),
    'systemd/serein-outpost.target': ('/etc/systemd/system/serein-outpost.target', '0644'),
}
IMAGE_UNITS = ('serein-outpost-host-witness.service', 'serein-outpost-host-witness.timer', 'serein-outpost.service',
               'serein-outpost-presentation.service', 'serein-https-gateway-adapter.service',
               'serein-outpost.target')
VITALS_UNITS = ('serein-outpost-presentation.service', 'serein-https-gateway-adapter.service')
INSTALL_OBSERVATION = '/var/lib/serein-outpost/generation-state/install-observation.json'
UNIT_PROPERTIES = ('Id', 'LoadState', 'ActiveState', 'SubState', 'UnitFileState',
                   'FragmentPath', 'DropInPaths', 'NeedDaemonReload')

# Site values remain in the signed private installation plan, never in the
# public recipe. This is the existing Debian daemon, not another time client.
HOST_TIME_CONFIG = '/etc/systemd/timesyncd.conf'
HOST_TIME_UNIT = 'systemd-timesyncd.service'


def host_time_configuration(policy):
    """Render only the explicitly bound pfSense source; confer no effects.

    Both lists are reset and bound to the same source. In particular, no
    compiled-in public fallback is implicitly accepted. Endpoint identity and
    live synchronization must still be independently verified before admission.
    """
    if (not isinstance(policy, dict) or set(policy) != {'authority', 'server'}
            or policy.get('authority') != 'pfSense'
            or not isinstance(policy.get('server'), str)):
        raise TransactionError('PUBLIC_HOST_TIME_POLICY_DENIED')
    try:
        server = ipaddress.IPv4Address(policy['server'])
    except ipaddress.AddressValueError:
        raise TransactionError('PUBLIC_HOST_TIME_POLICY_DENIED') from None
    private_ranges = ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')
    if (str(server) != policy['server']
            or not any(server in ipaddress.IPv4Network(net) for net in private_ranges)):
        raise TransactionError('PUBLIC_HOST_TIME_POLICY_DENIED')
    return ('[Time]\nNTP=\nNTP=' + str(server)
            + '\nFallbackNTP=\nFallbackNTP=' + str(server) + '\n').encode('ascii')


def read_host_time_observation(policy):
    """Read the existing daemon and one source-bound RFC5905 sample, no settime.

    This is an unauthenticated LAN-source observation, not a new trust anchor,
    authority grant, or a replacement for Kernel request/replay validation.
    """
    host_time_configuration(policy)
    def properties(command):
        try:
            result = subprocess.run(command, capture_output=True, text=True,
                                    check=True, timeout=10, env={**os.environ, 'LC_ALL':'C'})
            values = {}
            for line in result.stdout.splitlines():
                key, separator, value = line.partition('=')
                if not separator or key in values:
                    raise ValueError('properties')
                values[key] = value
            return values
        except (OSError, subprocess.SubprocessError, ValueError):
            raise TransactionError('PUBLIC_HOST_TIME_READ_DENIED') from None
    daemon = properties(['/usr/bin/timedatectl', 'show-timesync', '--all', '--no-pager'])
    clock = properties(['/usr/bin/timedatectl', 'show', '--all', '--no-pager'])
    native = properties(['/usr/bin/dpkg-query', '-W', '-f=NativeVersion=${Version}\n', 'systemd-timesyncd'])
    required = {'LinkNTPServers','RuntimeNTPServers','SystemNTPServers',
                'FallbackNTPServers','ServerName','ServerAddress'}
    if not required <= set(daemon) or 'NTPSynchronized' not in clock:
        raise TransactionError('PUBLIC_HOST_TIME_READ_DENIED')
    if daemon['LinkNTPServers'] or daemon['RuntimeNTPServers']:
        raise TransactionError('PUBLIC_HOST_TIME_ALTERNATE_SOURCE_DENIED')
    epoch = 2208988800
    packet = bytearray(48); packet[0] = 0x23
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as channel:
        channel.settimeout(3)
        operation = 'CONNECT'
        try:
            channel.connect((policy['server'], 123))
            before = time.time(); stamp = before + epoch
            struct.pack_into('!II', packet, 40, int(stamp), int((stamp % 1) * 2**32))
            monotonic_before = time.monotonic()
            operation = 'SEND'
            channel.send(packet)
            operation = 'RECEIVE'
            raw = channel.recv(512)
            monotonic_after = time.monotonic(); after = time.time()
        except OSError as error:
            reason = ('TIMEOUT' if isinstance(error, TimeoutError) else
                      {errno.ECONNREFUSED:'CONNECTION_REFUSED', errno.ECONNRESET:'CONNECTION_RESET',
                       errno.ENETUNREACH:'NETWORK_UNREACHABLE', errno.EHOSTUNREACH:'HOST_UNREACHABLE',
                       errno.EACCES:'PERMISSION', errno.EPERM:'PERMISSION'}.get(error.errno,'OTHER'))
            failure = TransactionError('PUBLIC_HOST_TIME_SOURCE_UNAVAILABLE')
            failure.host_time_source_error = {'operation':operation,'reason':reason}
            raise failure from None
    def deny_sample(predicate):
        failure = TransactionError('PUBLIC_HOST_TIME_SAMPLE_DENIED')
        failure.host_time_sample_predicate = predicate
        raise failure
    if len(raw) < 48: deny_sample('LENGTH')
    if raw[24:32] != packet[40:48]: deny_sample('ORIGIN')
    if raw[0] & 7 != 4: deny_sample('MODE')
    if (raw[0] >> 3) & 7 not in (3,4): deny_sample('VERSION')
    if raw[0] >> 6 == 3: deny_sample('LEAP')
    if not 1 <= raw[1] <= 15: deny_sample('STRATUM')
    def timestamp(at):
        seconds, fraction = struct.unpack_from('!II', raw, at)
        return seconds + fraction / 2**32 - epoch
    received, transmitted = timestamp(32), timestamp(40)
    delay = (after - before) - (transmitted - received)
    offset = ((received - before) + (transmitted - after)) / 2
    elapsed = monotonic_after - monotonic_before
    if received <= 0 or transmitted < received: deny_sample('TIMESTAMP_ORDER')
    if not 0 <= elapsed <= 1: deny_sample('MONOTONIC_RTT')
    if delay < -0.001 or delay > 1: deny_sample('NETWORK_DELAY')
    if abs((after-before)-elapsed) > 0.01: deny_sample('CLOCK_CHANGED_DURING_SAMPLE')
    return {'authority':'pfSense', 'server':policy['server'], 'observed_at':after,
            'offset_seconds':offset, 'round_trip_seconds':elapsed, 'stratum':raw[1],
            'source_authenticated':False, 'native_version':native.get('NativeVersion'),
            'daemon':{key:daemon[key] for key in sorted(required)},
            'synchronized':clock['NTPSynchronized'] == 'yes'}


def validate_host_time_witness(policy, observation):
    host_time_configuration(policy)
    if not isinstance(observation, dict):
        raise TransactionError('PUBLIC_HOST_TIME_WITNESS_DENIED')
    daemon = observation.get('daemon', {})
    if (observation.get('authority') != 'pfSense' or observation.get('server') != policy['server']
            or observation.get('synchronized') is not True
            or not isinstance(daemon, dict)
            or type(observation.get('observed_at')) not in (int,float)
            or not math.isfinite(observation['observed_at']) or observation['observed_at'] <= 0
            or type(observation.get('round_trip_seconds')) not in (int,float)
            or not math.isfinite(observation['round_trip_seconds'])
            or not 0 <= observation['round_trip_seconds'] <= 1
            or type(observation.get('stratum')) is not int or not 1 <= observation['stratum'] <= 15
            or observation.get('source_authenticated') is not False
            or daemon.get('LinkNTPServers') != '' or daemon.get('RuntimeNTPServers') != ''
            or any(daemon.get(key) != policy['server'] for key in
                   ('SystemNTPServers','FallbackNTPServers','ServerName','ServerAddress'))
            or type(observation.get('offset_seconds')) not in (int,float)
            or not math.isfinite(observation['offset_seconds'])
            or abs(observation['offset_seconds']) > 1):
        raise TransactionError('PUBLIC_HOST_TIME_WITNESS_DENIED')
    return dict(observation)


def validate_host_time_correction(policy, observation):
    """Bind native small-delta discipline, not an arbitrary clock-set road."""
    offset = observation.get('offset_seconds')
    if (observation.get('server') != policy['server'] or type(offset) not in (int,float)
            or not math.isfinite(offset) or not -.4 < offset <= 10):
        raise TransactionError('PUBLIC_HOST_TIME_CORRECTION_BOUND_DENIED')
    # Exact public Base systemd 257.13 source: fabs(offset)<0.4 uses STA_PLL /
    # ADJ_OFFSET; larger offsets use ADJ_SETOFFSET. Do not generalize this
    # negative-offset permission to another native package or a backward step.
    negative_slew = offset < 0
    if negative_slew:
        rtt = observation.get('round_trip_seconds')
        if (observation.get('native_version') != '257.13-1~deb13u1'
                or type(rtt) not in (int,float) or not math.isfinite(rtt)
                or not 0 <= rtt <= 1
                or offset-rtt/2 <= -.4 or offset+rtt/2 >= .4):
            raise TransactionError('PUBLIC_HOST_TIME_CORRECTION_BOUND_DENIED')
    return negative_slew


def validate_host_clock_interval(before, after, boot_id, *, negative_slew=False):
    """Bound observed net UTC adjustment, not control the native daemon.

    Monotonic brackets retain measurement uncertainty. They cannot exclude an
    unobserved intermediate step or promise future daemon behavior. No code
    here rewinds time, including after configuration compensation.
    """
    if type(negative_slew) is not bool:
        raise TransactionError('PUBLIC_HOST_CLOCK_OBSERVATION_DENIED')
    for sample in (before, after):
        if (not isinstance(sample, dict) or sample.get('boot_id') != boot_id
                or any(type(sample.get(key)) not in (int,float)
                       or not math.isfinite(sample[key]) for key in
                       ('utc','monotonic_before','monotonic_after'))
                or not 0 <= sample['monotonic_after']-sample['monotonic_before'] <= .01):
            raise TransactionError('PUBLIC_HOST_CLOCK_OBSERVATION_DENIED')
    if after['monotonic_before'] < before['monotonic_after']:
        raise TransactionError('PUBLIC_HOST_CLOCK_OBSERVATION_DENIED')
    delta = after['utc'] - before['utc']
    lower = delta - (after['monotonic_after'] - before['monotonic_before'])
    upper = delta - (after['monotonic_before'] - before['monotonic_after'])
    # A native gradual negative slew reduces UTC-minus-monotonic without
    # rewinding realtime. Contain the entire observed interval strictly in
    # the source-bound small-delta range; do not claim continuous trajectory.
    if ((negative_slew and (lower <= -.4 or upper >= .4))
            or (not negative_slew and (lower < -.001 or upper > 10.001))):
        raise TransactionError('PUBLIC_HOST_CLOCK_EFFECT_DENIED')
    return {'before':dict(before), 'after':dict(after),
            'net_adjustment_lower_seconds':lower,'net_adjustment_upper_seconds':upper,
            'sampling_tolerance_seconds':.001,'continuous_trajectory_proven':False,
            'native_negative_slew_bound':negative_slew}

# Only these observed oneshot/timer phases can change without a configuration
# effect. This classification never admits a sample or relaxes promotion CAS.
HOST_READ_PHASES = {
    'serein-outpost-host-witness.service': {('inactive', 'dead'), ('activating', 'start')},
    'serein-outpost-host-witness.timer': {('active', 'waiting'), ('active', 'running')},
}


class HostPhaseReadChanged(TransactionError):
    """Rejected two-read sample; only pre-placement preflight may reacquire."""
    def __init__(self, before):
        super().__init__('PUBLIC_BOOTSTRAP_CHANGED_DURING_READ')
        self.before = before


def _bootstrap_phase_invariant(sample):
    return {'files': sample.get('files'), 'units': {
        name: {key: value for key, value in unit.items()
               if name not in HOST_READ_PHASES or key not in {'ActiveState', 'SubState'}}
        for name, unit in sample['units'].items()}}


def _only_host_read_phase_changed(before, after):
    if _bootstrap_phase_invariant(before) != _bootstrap_phase_invariant(after):
        return False
    for name, unit in before['units'].items():
        other = after['units'][name]
        if unit != other and (name not in HOST_READ_PHASES
                or (unit['ActiveState'], unit['SubState']) not in HOST_READ_PHASES[name]
                or (other['ActiveState'], other['SubState']) not in HOST_READ_PHASES[name]):
            return False
    return before != after


def _await_promotion_unit_prestate(io, expected, verify_invariants):
    """Reacquire exact signed state after retirement; never accept a phase as CAS.

    The same read-only budget as pre-placement preflight applies. Expiry denies
    promotion; it never terminates a service/installer or releases its custody.
    Only the already-declared Host collector lifecycle may differ while reading.
    """
    if any(row['ActiveState'] not in {'active', 'inactive', 'failed'}
           or row['UnitFileState'] not in {'', 'enabled', 'disabled', 'static'}
           for row in expected.values()):
        raise TransactionError('PUBLIC_PROMOTION_UNIT_PRESTATE_DENIED')
    before = {'units': expected}
    deadline = time.monotonic() + 30
    while True:
        verify_invariants()
        observed = {name: io.unit_state(name) for name in expected}
        if time.monotonic() > deadline:
            raise TransactionError('PUBLIC_PROMOTION_UNIT_PRESTATE_DENIED')
        if observed == expected:
            return
        if (not _only_host_read_phase_changed(before, {'units': observed})
                or time.monotonic() >= deadline):
            raise TransactionError('PUBLIC_PROMOTION_UNIT_PRESTATE_DENIED')
        time.sleep(0.25)


@contextmanager
def public_generation_lock(root, source_plan_sha256, boot_id, *, recovery_plan=None):
    """The donor's exclusive transaction lock, without its recovery effects.

    Ordinary callers retain O_EXCL. A complete successor may handle the exact
    retained prior-boot transaction only through a separately verified current
    source plan. Neither age nor an empty process sample authorizes recovery.
    """
    if (not isinstance(source_plan_sha256, str)
            or not re.fullmatch(r'[0-9a-f]{64}', source_plan_sha256)
            or not isinstance(boot_id, str)
            or not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}', boot_id)):
        raise TransactionError('PUBLIC_LOCK_BINDING_DENIED')
    root = Path(os.path.abspath(root))
    parent = root / 'var/lib/serein/rollback'
    name = '.outpost-public-generation.lock'
    handles, fd, acquired = [], None, None
    payload = canonical({'source_plan_sha256':source_plan_sha256, 'boot_id':boot_id}) + b'\n'
    if recovery_plan is not None:
        with _retained_generation_ownership(root, source_plan_sha256, boot_id,
                                            recovery_plan) as owned:
            yield owned
        return
    try:
        current = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        handles.append((current, None, None))
        for part in parent.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            handles.append((child, current, part)); current = child
        info = os.fstat(current)
        if (info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) not in {0o700,0o755}
                or os.geteuid() != 0 or os.getegid() != 0):
            raise TransactionError('PUBLIC_LOCK_CUSTODY_DENIED')
        try:
            fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=current)
        except FileExistsError:
            raise TransactionError('PUBLIC_TRANSACTION_LOCKED') from None
        acquired = os.fstat(fd)
        os.fchmod(fd, 0o600)
        with os.fdopen(os.dup(fd), 'wb') as stream:
            stream.write(payload); stream.flush(); os.fsync(stream.fileno())
        os.fsync(current)
        for child, owner, part in handles[1:]:
            opened = os.fstat(child); named = os.stat(part, dir_fd=owner, follow_symlinks=False)
            if (opened.st_dev,opened.st_ino) != (named.st_dev,named.st_ino):
                raise TransactionError('PUBLIC_LOCK_DIRECTORY_CHANGED')
        yield {'path':'/var/lib/serein/rollback/' + name, 'source_plan_sha256':source_plan_sha256,
               'boot_id':boot_id, 'lock_sha256':sha(payload)}
    except OSError:
        raise TransactionError('PUBLIC_LOCK_IO_DENIED') from None
    finally:
        try:
            if acquired is not None:
                named = os.stat(name, dir_fd=handles[-1][0], follow_symlinks=False)
                if ((named.st_dev,named.st_ino) != (acquired.st_dev,acquired.st_ino)
                        or not stat.S_ISREG(named.st_mode) or named.st_nlink != 1
                        or named.st_uid != 0 or named.st_gid != 0 or stat.S_IMODE(named.st_mode) != 0o600):
                    raise TransactionError('PUBLIC_LOCK_RELEASE_DENIED')
                os.lseek(fd, 0, os.SEEK_SET)
                if os.read(fd, len(payload)+1) != payload:
                    raise TransactionError('PUBLIC_LOCK_RELEASE_DENIED')
                os.unlink(name, dir_fd=handles[-1][0]); os.fsync(handles[-1][0])
        finally:
            if fd is not None: os.close(fd)
            for descriptor,_,_ in reversed(handles): os.close(descriptor)


def _retained_transaction_binding(fields):
    """Exact signed historical evidence; never a clear-lock switch."""
    packet = fields.get('retained_transaction')
    if (not isinstance(packet, dict)
            or set(packet) != {'prior_boot_id', 'request_sha256', 'retained_lock', 'history'}
            or not isinstance(packet['prior_boot_id'], str)
            or not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}', packet['prior_boot_id'])
            or packet['prior_boot_id'] == fields.get('current_boot_id')
            or not isinstance(packet['request_sha256'], str)
            or not re.fullmatch('[0-9a-f]{64}', packet['request_sha256'])):
        raise TransactionError('PUBLIC_RETAINED_TRANSACTION_BINDING_DENIED')
    lock = packet['retained_lock']; history = packet['history']
    if (not isinstance(lock, dict)
            or set(lock) != {'sha256', 'device', 'inode', 'ctime_ns', 'mtime_ns'}
            or any(type(lock[k]) is not int or lock[k] < 0
                   for k in ('device', 'inode', 'ctime_ns', 'mtime_ns'))
            or lock['sha256'] != sha(canonical({'source_plan_sha256':packet['request_sha256'],
                                              'boot_id':packet['prior_boot_id']}) + b'\n')
            or not isinstance(history, dict) or len(history) != 3):
        raise TransactionError('PUBLIC_RETAINED_TRANSACTION_BINDING_DENIED')
    parents = set()
    for path, digest in history.items():
        if (not isinstance(path, str) or not re.fullmatch(
                r'/var/lib/serein/rollback/kernel-first-install-\d{8}T\d{6}Z-[0-9a-f]{12}/(plan|receipt|phase-journal)\.json', path)
                or not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest)):
            raise TransactionError('PUBLIC_RETAINED_TRANSACTION_BINDING_DENIED')
        parents.add(str(PurePosixPath(path).parent))
    if len(parents) != 1:
        raise TransactionError('PUBLIC_RETAINED_TRANSACTION_BINDING_DENIED')
    return packet


class _OwnedGeneration(dict):
    """Serializable evidence with a process-local continuity check."""
    def __init__(self, evidence, verify):
        super().__init__(evidence)
        self.verify = verify


@contextmanager
def _retained_generation_ownership(root, source_digest, boot, plan):
    """Same installer lock, held throughout a fresh complete transaction.

    The old O_EXCL file continues excluding legacy callers. Native flock on
    that exact inode excludes competing successor installers. Historical
    bytes are never rewritten. Failure keeps the original file and history;
    success requires the new signed COMPLETE journal before exact unlink.
    """
    import fcntl
    if (type(plan) is not VerifiedSourcePlan or not plan.authority_custody_proven
            or sha(plan.encoded) != source_digest
            or plan.as_dict().get('current_boot_id') != boot):
        raise TransactionError('PUBLIC_VERIFIED_PLAN_REQUIRED')
    fields = plan.as_dict(); packet = _retained_transaction_binding(fields)
    if source_digest == packet['request_sha256']:
        raise TransactionError('PUBLIC_STALE_REQUEST_DENIED')
    parent = root/'var/lib/serein/rollback'
    path = parent/'.outpost-public-generation.lock'
    handles, fd = [], None
    body_active = False
    raw = canonical({'source_plan_sha256':packet['request_sha256'],
                     'boot_id':packet['prior_boot_id']}) + b'\n'
    expected = packet['retained_lock']
    def read_bound(absolute, digest, mode=0o600):
        target = root/absolute.lstrip('/')
        chain=[]
        try:
            owner=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            chain.append((owner,None,None))
            for part in target.parent.parts[1:]:
                child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=owner)
                chain.append((child,owner,part));owner=child
            descriptor=os.open(target.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=owner)
            with os.fdopen(descriptor,'rb') as stream:
                before=os.fstat(stream.fileno())
                if (not stat.S_ISREG(before.st_mode) or before.st_nlink!=1
                        or (before.st_uid,before.st_gid,stat.S_IMODE(before.st_mode))!=(0,0,mode)):
                    raise TransactionError('PUBLIC_RECOVERY_EVIDENCE_CUSTODY_DENIED')
                data=stream.read(16*1024*1024+1)
                after=os.fstat(stream.fileno())
                named=os.stat(target.name,dir_fd=owner,follow_symlinks=False)
                fingerprint=lambda item:(item.st_dev,item.st_ino,item.st_size,item.st_mtime_ns,item.st_ctime_ns)
                if (len(data)>16*1024*1024 or (digest is not None and sha(data)!=digest)
                        or fingerprint(before)!=fingerprint(after) or fingerprint(before)!=fingerprint(named)):
                    raise TransactionError('PUBLIC_RECOVERY_EVIDENCE_CHANGED')
                for child,parent_fd,name in chain[1:]:
                    opened=os.fstat(child);named=os.stat(name,dir_fd=parent_fd,follow_symlinks=False)
                    if (opened.st_dev,opened.st_ino)!=(named.st_dev,named.st_ino):
                        raise TransactionError('PUBLIC_RECOVERY_EVIDENCE_DIRECTORY_CHANGED')
                return data
        finally:
            for descriptor,_,_ in reversed(chain):os.close(descriptor)
    def boundary():
        if (root/'proc/sys/kernel/random/boot_id').read_text().strip() != boot:
            raise TransactionError('PUBLIC_BOOT_DRIFT_DENIED')
        for child, owner, name in handles[1:]:
            opened=os.fstat(child); named=os.stat(name,dir_fd=owner,follow_symlinks=False)
            if (opened.st_dev,opened.st_ino)!=(named.st_dev,named.st_ino):
                raise TransactionError('PUBLIC_LOCK_DIRECTORY_CHANGED')
        custody=os.fstat(handles[-1][0])
        if ((custody.st_uid,custody.st_gid)!=(0,0)
                or stat.S_IMODE(custody.st_mode) not in {0o700,0o755}):
            raise TransactionError('PUBLIC_LOCK_CUSTODY_DENIED')
        for item in (os.fstat(fd),os.stat(path.name,dir_fd=handles[-1][0],follow_symlinks=False)):
            if (not stat.S_ISREG(item.st_mode) or item.st_nlink!=1
                    or (item.st_uid,item.st_gid,stat.S_IMODE(item.st_mode))!=(0,0,0o600)
                    or (item.st_dev,item.st_ino,item.st_ctime_ns,item.st_mtime_ns)!=tuple(
                        expected[k] for k in ('device','inode','ctime_ns','mtime_ns'))):
                raise TransactionError('PUBLIC_LOCK_OBSERVATION_CHANGED')
        if os.pread(fd,len(raw)+1,0)!=raw:
            raise TransactionError('PUBLIC_LOCK_OBSERVATION_CHANGED')
        for absolute,digest in packet['history'].items():
            read_bound(absolute,digest)
    try:
        current=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        handles.append((current,None,None))
        for part in parent.parts[1:]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=current)
            handles.append((child,current,part));current=child
        info=os.fstat(current)
        if (os.geteuid()!=0 or os.getegid()!=0 or (info.st_uid,info.st_gid)!=(0,0)
                or stat.S_IMODE(info.st_mode) not in {0o700,0o755}):
            raise TransactionError('PUBLIC_LOCK_CUSTODY_DENIED')
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=current)
        try: fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError: raise TransactionError('PUBLIC_TRANSACTION_LOCKED') from None
        boundary()
        # The authenticated prior boot excludes its original process. The
        # retained name excludes O_EXCL entrants and flock excludes successors.
        # A global /proc sample is not ownership authority; unreadable proc
        # entries must never be converted to an empty/no-owner observation.
        body_active = True
        yield _OwnedGeneration({'path':'/var/lib/serein/rollback/'+path.name,
               'source_plan_sha256':source_digest,'boot_id':boot,
               'lock_sha256':expected['sha256'],'retained_transaction':packet},boundary)
        body_active = False
        boundary()
        _verify_retained_successor_complete(root,plan,read_bound)
        boundary()
        os.unlink(path.name,dir_fd=current);os.fsync(current)
    except OSError:
        if body_active:raise
        raise TransactionError('PUBLIC_LOCK_IO_DENIED') from None
    finally:
        if fd is not None:os.close(fd)
        for descriptor,_,_ in reversed(handles):os.close(descriptor)


def _verify_retained_successor_complete(root, plan, read_bound):
    """Do not release retained exclusion on a callback or test's say-so."""
    fields=plan.as_dict(); selector=fields['rollback_selector']
    if not re.fullmatch(r'/var/lib/serein/rollback/outpost-public-generation-\d{8}T\d{6}Z-[0-9a-f]{12}',selector):
        raise TransactionError('PUBLIC_RECOVERY_COMPLETION_DENIED')
    anchor=read_bound('/usr/share/serein/outpost/cognition-verification.pem',
                      plan.authority_sha256,0o644)
    public=load_pem_public_key(anchor)
    raw=read_bound(selector+'/prestate-receipt.json',None)
    receipt=strict_json(raw)
    body={key:value for key,value in receipt.items() if key not in {'receipt_signature','receipt_digest'}}
    verify_prestate_receipt(raw,body,public)
    if (body.get('source_plan_sha256')!=sha(plan.encoded)
            or body.get('boot_id')!=fields['current_boot_id']
            or body.get('retained_transaction')!=fields['retained_transaction']
            or body.get('kernel_retirement')!=fields.get('kernel_retirement')
            or body.get('generation_target')!='/usr/share/serein/outpost-generations/'+fields['release_digest'].removeprefix('sha256:')):
        raise TransactionError('PUBLIC_RECOVERY_COMPLETION_DENIED')
    journal=strict_json(read_bound(selector+'/forward-state.json',None))
    unsigned={key:value for key,value in journal.items() if key not in {'state_signature','state_digest'}}
    expected={key:value for key,value in body.items() if key!='schema'}
    expected.update(schema='SereinPublicOutpostForwardState/v1',
                    prestate_receipt_digest=receipt['receipt_digest'],phase='COMPLETE',step=0)
    if (unsigned!=expected or journal.get('state_digest')!=sha(canonical(
            {key:value for key,value in journal.items() if key!='state_digest'}))):
        raise TransactionError('PUBLIC_RECOVERY_COMPLETION_DENIED')
    try:
        public.verify(base64.urlsafe_b64decode(journal['state_signature']+'=='),canonical(unsigned))
    except Exception:
        raise TransactionError('PUBLIC_RECOVERY_COMPLETION_SIGNATURE_DENIED') from None
    if 'kernel_retirement' in fields:
        transaction=strict_json(read_bound(selector+'/transaction-receipt.json',None))
        signed={key:value for key,value in transaction.items() if key not in {'state_signature','state_digest'}}
        try:public.verify(base64.urlsafe_b64decode(transaction['state_signature']+'=='),canonical(signed))
        except Exception:raise TransactionError('PUBLIC_RECOVERY_COMPLETION_SIGNATURE_DENIED') from None
        retired=signed.get('kernel_retirement',{})
        if (signed.get('source_plan_sha256')!=sha(plan.encoded)
                or signed.get('boot_id')!=fields['current_boot_id']
                or retired.get('result')!='KERNEL_PROGRAM_RETIRED_PRIVATE_STATE_PRESERVED'
                or retired.get('source_plan_sha256')!=sha(plan.encoded)
                or retired.get('boot_id')!=fields['current_boot_id']):
            raise TransactionError('PUBLIC_KERNEL_RETIREMENT_TERMINAL_DENIED')
        terminal=strict_json(read_bound(selector+'/kernel-retirement-state.json',retired.get('journal_sha256')))
        terminal_body={key:value for key,value in terminal.items() if key not in {'state_signature','state_digest'}}
        try:public.verify(base64.urlsafe_b64decode(terminal['state_signature']+'=='),canonical(terminal_body))
        except Exception:raise TransactionError('PUBLIC_RECOVERY_COMPLETION_SIGNATURE_DENIED') from None
        if (terminal_body.get('phase')!='RETIRED' or terminal_body.get('source_plan_sha256')!=sha(plan.encoded)
                or terminal_body.get('boot_id')!=fields['current_boot_id']
                or terminal_body.get('prestate_sha256')!=retired.get('prestate_sha256')):
            raise TransactionError('PUBLIC_KERNEL_RETIREMENT_TERMINAL_DENIED')
        read_bound(selector+'/kernel-retirement-prestate.json',retired.get('prestate_sha256'))


def _public_lock_process_identity(raw, pid):
    """Read Linux proc stat field 22 without splitting a parenthesized comm."""
    try:
        text = raw.decode('ascii')
        prefix, fields = text.rsplit(') ', 1)
        if int(prefix.split(' (', 1)[0]) != pid:
            raise ValueError
        start = fields.split()[19]  # fields starts at stat field 3 (state).
        if not start.isdigit():
            raise ValueError
        return {'pid': pid, 'start_time': start}
    except (UnicodeError, ValueError, IndexError):
        raise TransactionError('PUBLIC_LOCK_PROCESS_OBSERVATION_DENIED') from None


def _public_lock_fd_owners(device, inode, observer_fd, *, proc=Path('/proc')):
    """Read-only descriptor evidence; absence never grants lock takeover.

    An unreadable or changing process makes this observation incomplete. The
    caller must not interpret a partial scan, dead remembered PID, or age as
    recovery authority. Only this observer's exact descriptor is excluded.
    """
    owners = []
    try:
        processes = sorted((p for p in proc.iterdir() if p.name.isdecimal()),
                           key=lambda p: int(p.name))
        for process in processes:
            pid = int(process.name)
            before = _public_lock_process_identity((process/'stat').read_bytes(), pid)
            # Keep scandir's descriptor alive while examining /proc/self/fd;
            # listing then closing it would manufacture a disappeared entry.
            with os.scandir(process/'fd') as descriptors:
                for descriptor in descriptors:
                    if not descriptor.name.isdecimal():
                        raise TransactionError('PUBLIC_LOCK_PROCESS_OBSERVATION_DENIED')
                    fd = int(descriptor.name)
                    if (pid, fd) == (os.getpid(), observer_fd):
                        continue
                    info = descriptor.stat()
                    if (info.st_dev, info.st_ino) == (device, inode):
                        owners.append({**before, 'fd': fd})
            after = _public_lock_process_identity((process/'stat').read_bytes(), pid)
            if before != after:
                raise TransactionError('PUBLIC_LOCK_PROCESS_OBSERVATION_CHANGED')
    except OSError:
        raise TransactionError('PUBLIC_LOCK_PROCESS_OBSERVATION_DENIED') from None
    return sorted(owners, key=lambda row: (row['pid'], row['fd']))


def observe_interrupted_public_lock(root, source_plan_sha256, boot_id, expected):
    """Bind retained-lock bytes/custody and descriptor observations, no effects.

    This is supporting evidence for the existing failed-construction recovery,
    NOT permission to clear, adopt, rename, resume, or bypass the O_EXCL lock.
    Legacy lock bytes contain no owner incarnation. Even two empty descriptor
    samples cannot establish exclusive recovery ownership or authenticate the
    failed plan/journal. Those remain separate mandatory recovery predicates.
    """
    if (not isinstance(source_plan_sha256, str)
            or not re.fullmatch(r'[0-9a-f]{64}', source_plan_sha256)
            or not isinstance(boot_id, str)
            or not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}', boot_id)
            or not isinstance(expected, dict)
            or set(expected) != {'sha256', 'device', 'inode', 'ctime_ns', 'mtime_ns'}
            or not isinstance(expected['sha256'], str)
            or not re.fullmatch(r'[0-9a-f]{64}', expected['sha256'])
            or any(type(expected[k]) is not int or expected[k] < 0
                   for k in ('device', 'inode', 'ctime_ns', 'mtime_ns'))):
        raise TransactionError('PUBLIC_LOCK_BINDING_DENIED')
    root = Path(os.path.abspath(root))
    parent = root/'var/lib/serein/rollback'
    name = '.outpost-public-generation.lock'
    payload = canonical({'source_plan_sha256': source_plan_sha256, 'boot_id': boot_id}) + b'\n'
    if sha(payload) != expected['sha256']:
        raise TransactionError('PUBLIC_LOCK_BINDING_DENIED')
    handles, fd = [], None
    try:
        current = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        handles.append((current, None, None))
        for part in parent.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            handles.append((child, current, part)); current = child
        info = os.fstat(current)
        if (os.geteuid() != 0 or os.getegid() != 0 or info.st_uid != 0 or info.st_gid != 0
                or stat.S_IMODE(info.st_mode) not in {0o700, 0o755}):
            raise TransactionError('PUBLIC_LOCK_CUSTODY_DENIED')
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=current)

        def boundary():
            for child, owner, part in handles[1:]:
                opened = os.fstat(child); named = os.stat(part, dir_fd=owner, follow_symlinks=False)
                if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
                    raise TransactionError('PUBLIC_LOCK_DIRECTORY_CHANGED')
            parent_info = os.fstat(current)
            if ((parent_info.st_uid, parent_info.st_gid) != (0, 0)
                    or stat.S_IMODE(parent_info.st_mode) not in {0o700, 0o755}):
                raise TransactionError('PUBLIC_LOCK_CUSTODY_DENIED')
            opened = os.fstat(fd); named = os.stat(name, dir_fd=current, follow_symlinks=False)
            for row in (opened, named):
                if (not stat.S_ISREG(row.st_mode) or row.st_nlink != 1
                        or (row.st_uid, row.st_gid, stat.S_IMODE(row.st_mode)) != (0, 0, 0o600)
                        or (row.st_dev, row.st_ino, row.st_ctime_ns, row.st_mtime_ns) != tuple(
                            expected[k] for k in ('device', 'inode', 'ctime_ns', 'mtime_ns'))):
                    raise TransactionError('PUBLIC_LOCK_OBSERVATION_CHANGED')
            if os.pread(fd, len(payload) + 1, 0) != payload:
                raise TransactionError('PUBLIC_LOCK_OBSERVATION_CHANGED')

        boundary()
        first = _public_lock_fd_owners(expected['device'], expected['inode'], fd)
        boundary()
        second = _public_lock_fd_owners(expected['device'], expected['inode'], fd)
        boundary()
        if first != second:
            raise TransactionError('PUBLIC_LOCK_PROCESS_OBSERVATION_CHANGED')
        return {'path': '/var/lib/serein/rollback/' + name, **expected,
                'source_plan_sha256': source_plan_sha256, 'boot_id': boot_id,
                'descriptor_holders': second, 'owner_incarnation': 'NOT_RECORDED',
                'continuous_process_inventory': 'UNPROVEN',
                'exclusive_recovery_ownership': 'UNPROVEN', 'mutation_effect': 'NONE',
                'recovery_admitted': False}
    except OSError:
        raise TransactionError('PUBLIC_LOCK_IO_DENIED') from None
    finally:
        if fd is not None: os.close(fd)
        for descriptor, _, _ in reversed(handles): os.close(descriptor)


@dataclass(frozen=True, init=False)
class FixtureVerifiedSourcePlan:
    """Signed source identity only, not current-boot or installation authority."""
    encoded: bytes
    authority_sha256: str
    authority_custody_proven: bool

    def __init__(self, encoded, authority_sha256, *, _token=None):
        if _token is not _VERIFIED:
            raise TransactionError("PUBLIC_VERIFIED_PLAN_REQUIRED")
        object.__setattr__(self, "encoded", encoded)
        object.__setattr__(self, "authority_sha256", authority_sha256)
        object.__setattr__(self, "authority_custody_proven", False)

    def as_dict(self):
        return strict_json(self.encoded)


@dataclass(frozen=True, init=False)
class VerifiedSourcePlan(FixtureVerifiedSourcePlan):
    def __init__(self, encoded, authority_sha256, *, _token=None):
        super().__init__(encoded, authority_sha256, _token=_token)
        object.__setattr__(self, "authority_custody_proven", True)


def _interrupted_kernel_binding(fields):
    """Closed, signed successor-only binding; never a generic stale-lock flag."""
    packet = fields.get('interrupted_kernel')
    if (not isinstance(packet, dict)
            or set(packet) != {'receipt_path', 'expected', 'retained_lock'}
            or not isinstance(packet['receipt_path'], str)
            or not re.fullmatch(r'/var/lib/serein/rollback/kernel-first-install-\d{8}T\d{6}Z-[0-9a-f]{12}/receipt.json', packet['receipt_path'])):
        raise TransactionError('PUBLIC_INTERRUPTED_KERNEL_BINDING_DENIED')
    expected = packet['expected']; lock = packet['retained_lock']
    hashes = {'plan_sha256', 'receipt_sha256', 'journal_sha256', 'witness_sha256', 'request_sha256'}
    if (not isinstance(expected, dict)
            or set(expected) != hashes | {'current_outpost_generation', 'preserved_runtime'}
            or any(not isinstance(expected[k], str) or not re.fullmatch('[0-9a-f]{64}', expected[k]) for k in hashes)
            or not isinstance(lock, dict)
            or set(lock) != {'sha256', 'device', 'inode', 'ctime_ns', 'mtime_ns'}
            or any(type(lock[k]) is not int or lock[k] < 0 for k in ('device', 'inode', 'ctime_ns', 'mtime_ns'))):
        raise TransactionError('PUBLIC_INTERRUPTED_KERNEL_BINDING_DENIED')
    payload = canonical({'source_plan_sha256': expected['request_sha256'],
                         'boot_id': fields.get('current_boot_id')}) + b'\n'
    current = expected['current_outpost_generation']; runtime = expected['preserved_runtime']
    if (lock['sha256'] != sha(payload) or not isinstance(current, dict)
            or set(current) != {'schema', 'generation', 'release_digest', 'predecessor_receipt_sha256',
                                'inventory_digest', 'selector_digest'}
            or current.get('schema') != 'SereinOutpostGenerationSelector/v1'
            or any(not isinstance(current[k], str) or not re.fullmatch('[0-9a-f]{64}', current[k])
                   for k in ('generation', 'predecessor_receipt_sha256', 'inventory_digest', 'selector_digest'))
            or current['release_digest'] != 'sha256:' + current['generation']
            or current['selector_digest'] != sha(canonical({k:v for k,v in current.items() if k != 'selector_digest'}))
            or current['release_digest'] == fields.get('release_digest')
            or not isinstance(runtime, dict)
            or set(runtime) != {'boot_id', 'pid', 'start_time', 'binary_sha256', 'binary_bytes', 'model_root'}
            or runtime.get('boot_id') != fields.get('current_boot_id')
            or type(runtime.get('pid')) is not int or runtime['pid'] < 1
            or not isinstance(runtime.get('start_time'), str) or not re.fullmatch('[0-9]+', runtime['start_time'])
            or not isinstance(runtime.get('binary_sha256'), str) or not re.fullmatch('[0-9a-f]{64}', runtime['binary_sha256'])
            or type(runtime.get('binary_bytes')) is not int or runtime['binary_bytes'] < 1
            or runtime.get('model_root') != '/var/lib/ollama/models'):
        raise TransactionError('PUBLIC_INTERRUPTED_KERNEL_BINDING_DENIED')
    return packet


def _verify_plan_bytes(plan, authority_bytes, expected_authority_sha256):
    """Pure signed-plan proof; caller supplies an independently pinned anchor.

    A plan's own asserted fingerprint never selects its trust anchor. Test
    anchors do not confer installed authority or prove native file custody.
    """
    required = {"schema", "repository", "repo_url", "ref", "commit", "tree", "archive_url", "archive_sha256", "release_digest", "authority_key_id", "authority_sha256", "signature", "current_boot_id", "immutable_rows", "rollback_selector"}
    if (not isinstance(plan, dict) or not required <= set(plan)
            or set(plan) - required not in (set(), {'recovery'}, {'host_time'}, {'interrupted_kernel'},
                                           {'retained_transaction'}, {'retained_transaction','host_time'},
                                           {'retained_transaction','kernel_retirement'},
                                           {'retained_transaction','kernel_retirement','host_time'})
            or plan.get("schema") != "SereinPublicOutpostGenerationPlan/v1"):
        raise TransactionError("PUBLIC_PLAN_SHAPE_DENIED")
    plan = strict_json(canonical(plan))
    if 'interrupted_kernel' in plan:
        _interrupted_kernel_binding(plan)
    if 'retained_transaction' in plan:
        _retained_transaction_binding(plan)
    if 'kernel_retirement' in plan:
        if (not isinstance(plan['kernel_retirement'],dict)
                or set(plan['kernel_retirement'])!={'boot_id','historical_plan_sha256','public_payload','public_state',
                    'preserved','enablement_links','dependencies','runtime_access'}
                or plan['kernel_retirement']['boot_id']!=plan['current_boot_id']):
            raise TransactionError('PUBLIC_KERNEL_RETIREMENT_BINDING_DENIED')
    if 'host_time' in plan:
        host_time_configuration(plan['host_time'])
    if 'recovery' in plan:
        recovery = plan['recovery']
        names = {'commit','tree','archive_sha256','release_digest','source_plan_sha256',
                 'predecessor_receipt_path','predecessor_receipt_sha256',
                 'candidate_path','candidate_sha256','current_selector_sha256',
                 'lkg_selector_sha256','lkg_generation'}
        if not isinstance(recovery, dict) or set(recovery) != names:
            raise TransactionError('PUBLIC_RECOVERY_PLAN_DENIED')
        for field in names - {'predecessor_receipt_path','candidate_path','release_digest'}:
            length = 40 if field in {'commit','tree'} else 64
            if not isinstance(recovery[field], str) or not re.fullmatch('[0-9a-f]{%d}' % length, recovery[field]):
                raise TransactionError('PUBLIC_RECOVERY_PLAN_DENIED')
        if (not isinstance(recovery['release_digest'], str)
                or not re.fullmatch(r'sha256:[0-9a-f]{64}', recovery['release_digest'])):
            raise TransactionError('PUBLIC_RECOVERY_PLAN_DENIED')
        for field, suffix in (('predecessor_receipt_path','prestate-receipt.json'), ('candidate_path','candidate.json')):
            if (not isinstance(recovery[field], str)
                    or not re.fullmatch(r'/var/lib/serein/rollback/outpost-public-generation-\d{8}T\d{6}Z-[0-9a-f]{12}/' + re.escape(suffix), recovery[field])):
                raise TransactionError('PUBLIC_RECOVERY_PLAN_DENIED')
    if plan["repository"] != "Kaotikking/sfos-public" or plan["repo_url"] != "https://github.com/Kaotikking/sfos-public.git" or plan["ref"] != "refs/heads/main":
        raise TransactionError("PUBLIC_SOURCE_IDENTITY_DENIED")
    for field in ("commit", "tree"):
        if not isinstance(plan[field], str) or not re.fullmatch(r"[0-9a-f]{40}", plan[field]):
            raise TransactionError("PUBLIC_LINEAGE_DENIED")
    if plan["archive_url"] != "https://codeload.github.com/Kaotikking/sfos-public/tar.gz/" + plan["commit"]:
        raise TransactionError("PUBLIC_ARCHIVE_URL_DENIED")
    if (not isinstance(plan["archive_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", plan["archive_sha256"])
            or not isinstance(plan["release_digest"], str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", plan["release_digest"])):
        raise TransactionError("PUBLIC_DIGEST_DENIED")
    if (not isinstance(plan["current_boot_id"], str)
            or not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", plan["current_boot_id"])
            or not isinstance(plan["rollback_selector"], str) or not plan["rollback_selector"]):
        raise TransactionError("PUBLIC_TARGET_BINDING_DENIED")
    rows = plan["immutable_rows"]
    if not isinstance(rows, list) or len(rows) != len(IMMUTABLE_POLICY):
        raise TransactionError("PUBLIC_IMMUTABLE_SCHEMA_DENIED")
    targets = set()
    for row in rows:
        if (not isinstance(row, dict) or set(row) != {"target", "bytes", "sha256", "mode", "uid", "gid"}
                or not isinstance(row["target"], str) or row["target"] not in IMMUTABLE_POLICY or row["target"] in targets
                or row["mode"] != IMMUTABLE_POLICY[row["target"]] or type(row["bytes"]) is not int or row["bytes"] < 1
                or not isinstance(row["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", row["sha256"])
                or type(row["uid"]) is not int or row["uid"] != 0 or type(row["gid"]) is not int or row["gid"] < 0):
            raise TransactionError("PUBLIC_IMMUTABLE_SCHEMA_DENIED")
        targets.add(row["target"])
    if (not isinstance(authority_bytes, bytes) or not isinstance(expected_authority_sha256, str)
            or not re.fullmatch(r"[0-9a-f]{64}", expected_authority_sha256)
            or sha(authority_bytes) != expected_authority_sha256
            or plan["authority_sha256"] != expected_authority_sha256 or plan["authority_key_id"] != "outpost-cognition-v1"):
        raise TransactionError("PUBLIC_AUTHORITY_IDENTITY_DENIED")
    anchor_row = next(row for row in rows if row["target"] == "/usr/share/serein/outpost/cognition-verification.pem")
    if anchor_row["sha256"] != expected_authority_sha256 or anchor_row["bytes"] != len(authority_bytes):
        raise TransactionError("PUBLIC_AUTHORITY_IDENTITY_DENIED")
    try:
        encoded = plan["signature"]
        if not isinstance(encoded, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", encoded):
            raise ValueError("signature encoding")
        signature = base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
        key = load_pem_public_key(authority_bytes)
        if not isinstance(key, Ed25519PublicKey): raise ValueError("key type")
        key.verify(signature, canonical({k:v for k,v in plan.items() if k != "signature"}))
    except Exception:
        raise TransactionError("PUBLIC_PLAN_SIGNATURE_DENIED") from None
    # Preserve the signed historical evidence locator without interpreting it
    # as permission to create rollback state, restore or activate anything.
    return FixtureVerifiedSourcePlan(canonical(plan), expected_authority_sha256, _token=_VERIFIED)


def _verify_plan(plan):
    if not isinstance(CANONICAL_AUTHORITY_SHA256, str) or not re.fullmatch(r"[0-9a-f]{64}", CANONICAL_AUTHORITY_SHA256):
        raise TransactionError("CANONICAL_AUTHORITY_UNKNOWN")
    if (not isinstance(plan, dict) or plan.get("authority_sha256") != CANONICAL_AUTHORITY_SHA256
            or plan.get("authority_key_id") != "outpost-cognition-v1"):
        raise TransactionError("PUBLIC_AUTHORITY_IDENTITY_DENIED")
    path = CANONICAL_AUTHORITY_PATH
    nofollow_ancestors(Path(path.anchor), path, allow_missing=False)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != 0
                or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o644):
            raise TransactionError("PUBLIC_AUTHORITY_CUSTODY_DENIED")
        key = stream.read(65537)
        if len(key) > 65536:
            raise TransactionError("PUBLIC_AUTHORITY_SIZE_DENIED")
    fixture = _verify_plan_bytes(plan, key, CANONICAL_AUTHORITY_SHA256)
    return VerifiedSourcePlan(fixture.encoded, fixture.authority_sha256, _token=_VERIFIED)


def _safe_archive(raw, plan):
    if type(plan) is not VerifiedSourcePlan or not plan.authority_custody_proven:
        raise TransactionError("PUBLIC_VERIFIED_PLAN_REQUIRED")
    return _archive_material(raw, plan.as_dict())


def preflight_target(plan):
    """Read-only current-boot and immutable-file expected-before evidence.

    Combines the attributed donor's Host/immutable checks with exact existing
    current/LKG readback. No selectors, services, permissions or installation
    are changed. This result is not a lock or permission to install; the
    complete transaction must recheck it.
    """
    if type(plan) is not VerifiedSourcePlan or not plan.authority_custody_proven:
        raise TransactionError("PUBLIC_VERIFIED_PLAN_REQUIRED")
    if 'interrupted_kernel' in plan.as_dict():
        _observe_bound_interrupted_kernel(Path('/'), plan)
    before = _target_prestate(Path("/"), plan.as_dict())
    recovery = 'recovery' in plan.as_dict()
    destination = (retained_recovery_prestate(Path('/'),plan.as_dict()) if recovery
                   else prospective_generation_prestate(Path('/'),plan.as_dict()['release_digest']))
    installed = successor_generation_prestate(Path("/"))
    # A timer-driven oneshot can be activating during an otherwise healthy
    # predecessor read. Promotion cannot accept that transient state. Wait
    # read-only BEFORE staging/placement instead of orphaning a generation
    # which was already known to be ineligible for promotion.
    deadline = time.monotonic() + 30
    invariant = None
    previous_sample = None
    while True:
        try:
            bootstrap = (bootstrap_prestate(Path('/'), read_bootstrap_unit, host_time=plan.as_dict()['host_time'])
                         if 'host_time' in plan.as_dict() else bootstrap_prestate(Path('/'), read_bootstrap_unit))
            settled = all(unit['ActiveState'] in {'active', 'inactive', 'failed'}
                          for unit in bootstrap['units'].values())
            sample = bootstrap
        except HostPhaseReadChanged as changed:
            # A rejected read is not expected-before evidence. Retain its
            # static projection only to reject drift across reacquisitions.
            sample, settled = changed.before, False
        current_invariant = _bootstrap_phase_invariant(sample)
        if invariant is not None and current_invariant != invariant:
            raise TransactionError('PUBLIC_BOOTSTRAP_CHANGED_DURING_READ')
        comparable = {'files': sample.get('files'), 'units': sample['units']}
        if (previous_sample is not None and comparable != previous_sample
                and not _only_host_read_phase_changed(previous_sample, comparable)):
            raise TransactionError('PUBLIC_BOOTSTRAP_CHANGED_DURING_READ')
        previous_sample = comparable
        invariant = current_invariant
        if time.monotonic() > deadline:
            raise TransactionError('PUBLIC_TRANSIENT_UNIT_PREFLIGHT_DENIED')
        if settled:
            break
        if time.monotonic() >= deadline:
            raise TransactionError('PUBLIC_TRANSIENT_UNIT_PREFLIGHT_DENIED')
        time.sleep(0.25)
    if any(unit['UnitFileState'] not in {'', 'enabled', 'disabled', 'static'}
           for unit in bootstrap['units'].values()):
        raise TransactionError('PUBLIC_PROMOTION_UNIT_PRESTATE_DENIED')
    if _target_prestate(Path("/"), plan.as_dict()) != before:
        raise TransactionError("PUBLIC_TARGET_CHANGED_DURING_PREFLIGHT")
    final_destination = (retained_recovery_prestate(Path('/'),plan.as_dict()) if recovery
                         else prospective_generation_prestate(Path('/'),plan.as_dict()['release_digest']))
    if final_destination != destination:
        raise TransactionError('PUBLIC_GENERATION_DESTINATION_CHANGED')
    return {**before, "installed_prestate": installed, 'bootstrap_prestate': bootstrap,
            'generation_destination':destination}


def _observe_bound_interrupted_kernel(root, plan, *, promoted=False):
    """Consume the signed preflight through the existing read-only verifier.

    The fixed Kernel inbox and receipt selector remain private on the target.
    This may run from the incoming complete Outpost installer; it does not
    execute the inactive generation as an admitted Outpost/domain authority.
    """
    if type(plan) is not VerifiedSourcePlan or not plan.authority_custody_proven:
        raise TransactionError('PUBLIC_VERIFIED_PLAN_REQUIRED')
    from . import kernel_first_install_runner as runner
    fields = plan.as_dict(); packet = _interrupted_kernel_binding(fields)
    expected = strict_json(canonical(packet['expected']))
    if promoted:
        selected, _ = runner.read_outpost_generation(root)
        if (selected['release_digest'] != fields['release_digest']
                or selected['predecessor_receipt_sha256'] != sha(plan.encoded)):
            raise TransactionError('PUBLIC_INTERRUPTED_KERNEL_SUCCESSOR_DENIED')
        expected['current_outpost_generation'] = selected
    return runner.observe_failed_construction(root,
        Path(root)/'var/lib/serein-outpost/kernel/source/sfos/kernel',
        Path(root)/packet['receipt_path'].lstrip('/'), expected, packet['retained_lock'])


def prospective_generation_prestate(root, release_digest):
    """Read the donor's exact final destination collision predicate.

    Existing content is evidence, never an overwrite/resume/ALREADY_COMMITTED
    shortcut. A private staging directory is not this installed destination.
    """
    if not isinstance(release_digest,str) or not re.fullmatch(r'sha256:[0-9a-f]{64}',release_digest):
        raise TransactionError('PUBLIC_RELEASE_DIGEST_DENIED')
    root=Path(os.path.abspath(root))
    absolute='/usr/share/serein/outpost-generations/'+release_digest.removeprefix('sha256:')
    path=root/absolute.lstrip('/')
    nofollow_ancestors(Path(root.anchor),path.parent,allow_missing=False)
    parent=path.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or (parent.st_uid,parent.st_gid,stat.S_IMODE(parent.st_mode))!=(0,0,0o755):
        raise TransactionError('PUBLIC_GENERATION_PARENT_DENIED')
    if os.path.lexists(path):
        raise TransactionError('PUBLIC_GENERATION_COLLISION_DENIED')
    nofollow_ancestors(Path(root.anchor),path.parent,allow_missing=False)
    after=path.parent.lstat()
    identity=lambda info:(info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode)
    if identity(parent)!=identity(after) or os.path.lexists(path):
        raise TransactionError('PUBLIC_GENERATION_DESTINATION_CHANGED')
    return {'target':absolute,'state':'ABSENT',
            'parent':{'device':parent.st_dev,'inode':parent.st_ino,'uid':0,'gid':0,'mode':'0755'}}


def preflight_placed_target(plan, selector, candidate_record):
    """Verify exactly the inactive placed tree; no selector promotion implied."""
    if type(plan) is not VerifiedSourcePlan or not plan.authority_custody_proven:
        raise TransactionError('PUBLIC_VERIFIED_PLAN_REQUIRED')
    return _placed_target_prestate(Path('/'),plan.as_dict(),selector,candidate_record,
                                   sha(plan.encoded),read_bootstrap_unit)


def _placed_target_prestate(root, fields, selector, candidate_record, source_digest, read_unit):
    from .generation_launcher import read_selector, LaunchDenied
    absolute=fields['rollback_selector']+'/candidate.json'
    candidate=root/absolute.lstrip('/')
    if (candidate_record.get('path')!=absolute
            or selector.get('release_digest')!=fields['release_digest']
            or selector.get('predecessor_receipt_sha256')!=source_digest):
        raise TransactionError('PUBLIC_CANDIDATE_PRESTATE_BINDING_DENIED')
    def observe():
        parent=root/'usr/share/serein/outpost-generations'
        nofollow_ancestors(root,parent,allow_missing=False)
        info=parent.lstat()
        if (info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode))!=(0,0,0o755):
            raise TransactionError('PUBLIC_GENERATION_PARENT_DENIED')
        try: value,selected=read_selector(candidate,parent)
        except (OSError,LaunchDenied):raise TransactionError('PUBLIC_CANDIDATE_CONSUMER_DENIED') from None
        if value!=selector or selected!=parent/selector['generation']:
            raise TransactionError('PUBLIC_CANDIDATE_CONSUMER_DENIED')
        return {'target':'/'+selected.relative_to(root).as_posix(),'state':'PRESENT','selector':value,
                'parent':{'device':info.st_dev,'inode':info.st_ino,'uid':0,'gid':0,'mode':'0755'}}
    before=_target_prestate(root,fields); destination=observe()
    installed=successor_generation_prestate(root)
    bootstrap=(bootstrap_prestate(root,read_unit,host_time=fields['host_time'])
               if 'host_time' in fields else bootstrap_prestate(root,read_unit))
    if _target_prestate(root,fields)!=before or observe()!=destination:
        raise TransactionError('PUBLIC_TARGET_CHANGED_DURING_PREFLIGHT')
    return {**before,'installed_prestate':installed,'bootstrap_prestate':bootstrap,
            'generation_destination':destination}


def _bootstrap_file_state(root, absolute, *, capture=False):
    """Read the donor image prestate, never private keys or arbitrary paths."""
    if absolute not in {item[0] for item in IMAGE_FILES.values()} | {HOST_TIME_CONFIG}:
        raise TransactionError('PUBLIC_IMAGE_PATH_DENIED')
    path = root / absolute.lstrip('/')
    nofollow_ancestors(Path(root.anchor), path)
    if not os.path.lexists(path):
        row = {'target': absolute, 'state': 'ABSENT'}
        return (row, None) if capture else row
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_uid != 0 or before.st_gid != 0
                or stat.S_IMODE(before.st_mode) not in {0o644, 0o755}
                or before.st_size > 1024 * 1024):
            raise TransactionError('PUBLIC_IMAGE_PRESTATE_DENIED')
        data = stream.read(1024 * 1024 + 1)
        after = os.fstat(stream.fileno())
    nofollow_ancestors(Path(root.anchor), path, allow_missing=False)
    named = path.lstat()
    identity = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_uid,
                             item.st_gid, item.st_nlink, item.st_size,
                             item.st_mtime_ns, item.st_ctime_ns)
    if identity(before) != identity(after) or identity(after) != identity(named) or len(data) != before.st_size:
        raise TransactionError('PUBLIC_IMAGE_CHANGED_DURING_READ')
    row = {'target': absolute, 'state': 'PRESENT', 'bytes': len(data), 'sha256': sha(data),
           'mode': f'{stat.S_IMODE(before.st_mode):04o}', 'uid': 0, 'gid': 0}
    return (row, data) if capture else row


def read_bootstrap_unit(name):
    """Native read-only machine interface; no status-text parsing or defaults."""
    if name not in (*IMAGE_UNITS, HOST_TIME_UNIT):
        raise TransactionError('PUBLIC_UNIT_PATH_DENIED')
    try:
        result = subprocess.run(['/usr/bin/systemctl', 'show', '--all', '--no-pager',
                                 '--property=' + ','.join(UNIT_PROPERTIES), name],
                                capture_output=True, text=True, timeout=15, check=True)
    except (OSError, subprocess.SubprocessError):
        raise TransactionError('PUBLIC_UNIT_READ_DENIED') from None
    value = {}
    for line in result.stdout.splitlines():
        key, separator, item = line.partition('=')
        if not separator or key in value:
            raise TransactionError('PUBLIC_UNIT_PRESTATE_DENIED')
        value[key] = item
    return _checked_unit_state(name, value)


def _checked_unit_state(name, value):
    if (not isinstance(value, dict) or set(value) != set(UNIT_PROPERTIES)
            or any(not isinstance(item, str) for item in value.values())
            or value['Id'] != name or value['LoadState'] not in {'loaded', 'not-found'}
            or not value['ActiveState'] or not value['SubState']
            or value['NeedDaemonReload'] != 'no' or value['DropInPaths']):
        raise TransactionError('PUBLIC_UNIT_PRESTATE_DENIED')
    if value['LoadState'] == 'not-found':
        if (value['FragmentPath'] or value['UnitFileState']
                or value['ActiveState'] != 'inactive' or value['SubState'] != 'dead'):
            raise TransactionError('PUBLIC_UNIT_PRESTATE_DENIED')
    elif (value['FragmentPath'] != ('/usr/lib/systemd/system/' if name == HOST_TIME_UNIT else '/etc/systemd/system/') + name
          or not value['UnitFileState']):
        raise TransactionError('PUBLIC_UNIT_PRESTATE_DENIED')
    return dict(value)


def bootstrap_prestate(root, read_unit, *, host_time=None):
    """Exact bootstrap files and native unit state, reread without mutation.

    Adapts donor _file_state/_unit_state to G0. Missing image files remain
    explicit, never manufacture a FIRST_INSTALL classification. This is
    expected-before evidence, not a transaction lock or permission to promote.
    """
    root = Path(os.path.abspath(root))
    if host_time is not None:
        host_time_configuration(host_time)
    def collect():
        files = [_bootstrap_file_state(root, target) for target, _ in IMAGE_FILES.values()]
        units = {name: _checked_unit_state(name, read_unit(name)) for name in IMAGE_UNITS}
        for name, unit in units.items():
            row = next(item for item in files if item['target'] == '/etc/systemd/system/' + name)
            if (row['state'] == 'PRESENT') != (unit['LoadState'] == 'loaded'):
                raise TransactionError('PUBLIC_UNIT_FILE_BINDING_DENIED')
        if host_time is not None:
            host_time_dropin_preflight(root)
            files.append(_bootstrap_file_state(root, HOST_TIME_CONFIG))
            unit = _checked_unit_state(HOST_TIME_UNIT, read_unit(HOST_TIME_UNIT))
            if (unit['LoadState'], unit['ActiveState'], unit['SubState'], unit['UnitFileState']) != ('loaded', 'active', 'running', 'enabled'):
                raise TransactionError('PUBLIC_HOST_TIME_EXISTING_DAEMON_REQUIRED')
            units[HOST_TIME_UNIT] = unit
        return {'files': files, 'units': units}
    try:
        before = collect()
        after = collect()
        if after != before:
            if _only_host_read_phase_changed(before, after):
                raise HostPhaseReadChanged(before)
            raise TransactionError('PUBLIC_BOOTSTRAP_CHANGED_DURING_READ')
    except OSError:
        raise TransactionError('PUBLIC_BOOTSTRAP_READ_DENIED') from None
    return {**before, **({'host_time':dict(host_time)} if host_time is not None else {}),
            'mutation_effect': 'NONE', 'admission': 'UNPROVEN'}


def host_time_dropin_preflight(root):
    """Do not override unknown administrator/runtime/vendor time policy."""
    root = Path(os.path.abspath(root))
    for directory in ('etc', 'run', 'usr/local/lib', 'usr/lib'):
        path = root / directory / 'systemd/timesyncd.conf.d'
        nofollow_ancestors(Path(root.anchor), path)
        if os.path.lexists(path):
            info = path.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                    or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o755
                    or any(path.iterdir())):
                raise TransactionError('PUBLIC_HOST_TIME_DROPIN_CONFLICT')


def capture_bootstrap_predecessor(root, expected, read_unit):
    """Capture exact donor image bytes privately, not just recovery hashes.

    The enclosing transaction must hold its lock and durably retain/sign this
    capture before replacing files. Returned bytes must not enter public
    evidence. This function performs no write, service action or restoration.
    """
    root = Path(os.path.abspath(root))
    policy = expected.get('host_time')
    if bootstrap_prestate(root, read_unit, host_time=policy) != expected:
        raise TransactionError('PUBLIC_BOOTSTRAP_PRESTATE_CHANGED')
    captured = {}
    try:
        for before in expected['files']:
            target = before['target']
            row, data = _bootstrap_file_state(root, target, capture=True)
            if row != before:
                raise TransactionError('PUBLIC_BOOTSTRAP_PRESTATE_CHANGED')
            captured[target] = data
        if bootstrap_prestate(root, read_unit, host_time=policy) != expected:
            raise TransactionError('PUBLIC_BOOTSTRAP_PRESTATE_CHANGED')
    except OSError:
        raise TransactionError('PUBLIC_BOOTSTRAP_READ_DENIED') from None
    return captured


def capture_selector_predecessor(root, expected):
    """Retain both exact selector bytes; never substitute LKG for current.

    Private transaction input only. The surrounding lock and durable record
    are still required before promotion. This cannot repair or admit state.
    """
    from .generation_launcher import _read_regular, LaunchDenied
    root = Path(os.path.abspath(root))
    if successor_generation_prestate(root) != expected:
        raise TransactionError('PUBLIC_SELECTOR_PRESTATE_CHANGED')
    captured = {}
    try:
        for name in ('current', 'lkg'):
            target = '/var/lib/serein-outpost/generation-state/' + name + '.json'
            raw, info = _read_regular(root / target.lstrip('/'), 0o644)
            row = expected['selectors'][name]
            if (row['target'] != target or info.st_nlink != 1
                    or len(raw) != row['bytes'] or sha(raw) != row['sha256']
                    or strict_json(raw) != row['selector']):
                raise TransactionError('PUBLIC_SELECTOR_PRESTATE_CHANGED')
            captured[name] = raw
        if successor_generation_prestate(root) != expected:
            raise TransactionError('PUBLIC_SELECTOR_PRESTATE_CHANGED')
    except (OSError, LaunchDenied):
        raise TransactionError('PUBLIC_SELECTOR_CAPTURE_DENIED') from None
    return captured


def prepared_prestate_receipt(evidence, release, material, capture):
    """Construct the donor's private prestate record from exact captures.

    Pure bytes binding, not authorization. Never log this record: predecessor
    configuration is retained privately even though key paths are excluded.
    """
    target = evidence['target_prestate']
    image = prepared_bootstrap_image(release, material, target)
    digest = evidence.get('source_plan_sha256')
    boot = target.get('current_boot_id')
    if (not isinstance(digest, str) or not re.fullmatch(r'[0-9a-f]{64}', digest)
            or not isinstance(boot, str)
            or not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}', boot)
            or set(capture) != {'image_bytes','selector_bytes'}
            or set(capture['image_bytes']) != {row['target'] for row in image}
            or set(capture['selector_bytes']) != {'current','lkg'}):
        raise TransactionError('PUBLIC_PRESTATE_CAPTURE_BINDING_DENIED')
    def content(row, raw):
        row = dict(row)
        if row.get('state') == 'ABSENT':
            if raw is not None:
                raise TransactionError('PUBLIC_PRESTATE_CAPTURE_BINDING_DENIED')
            return row
        if not isinstance(raw, bytes) or len(raw) != row['bytes'] or sha(raw) != row['sha256']:
            raise TransactionError('PUBLIC_PRESTATE_CAPTURE_BINDING_DENIED')
        return {**row, 'state':'PRESENT', 'content_b64':base64.b64encode(raw).decode('ascii')}
    selectors = {}
    for name in ('current','lkg'):
        row = dict(target['installed_prestate']['selectors'][name])
        value = row.pop('selector')
        raw = capture['selector_bytes'][name]
        if strict_json(raw) != value:
            raise TransactionError('PUBLIC_PRESTATE_CAPTURE_BINDING_DENIED')
        selectors[name] = content(row, raw)
    files = [{'target':row['target'],
              'pre':content(row['pre'],capture['image_bytes'][row['target']]),
              'post':content(row['post'],host_time_configuration(target['bootstrap_prestate']['host_time'])
                             if row['target'] == HOST_TIME_CONFIG else material[row['source']])} for row in image]
    return {'schema':'SereinPublicOutpostPrestateReceipt/v1',
            'source_plan_sha256':digest, 'boot_id':boot,
            'generation_target':'/usr/share/serein/outpost-generations/' + release['self_digest'].removeprefix('sha256:'),
            'selector_pre':selectors, 'image_files':files,
            'unit_prestate':{name:dict(value) for name,value in target['bootstrap_prestate']['units'].items()}}


def seal_prestate_receipt(body, private, public):
    """Donor signing format; caller must separately prove native key custody."""
    value = strict_json(canonical(body))
    value['receipt_signature'] = base64.urlsafe_b64encode(private.sign(canonical(value))).decode('ascii').rstrip('=')
    value['receipt_digest'] = sha(canonical(value))
    raw = canonical(value) + b'\n'
    verify_prestate_receipt(raw, body, public)
    return raw


def load_prestate_signer(plan):
    """Reuse the preserved donor signing identity; no generation or repair.

    Only the native verified plan can reach key reads. The bytes must match
    its immutable rows and the existing canonical public fingerprint. This
    supplies record attribution, never constitutional or install admission.
    """
    if type(plan) is not VerifiedSourcePlan or not plan.authority_custody_proven:
        raise TransactionError('PUBLIC_VERIFIED_PLAN_REQUIRED')
    fields = plan.as_dict()
    rows = {row['target']:row for row in fields['immutable_rows']}
    signing_path = '/etc/serein-outpost/cognition-signing.pem'
    public_path = str(CANONICAL_AUTHORITY_PATH)
    signing = _read_target_fact(Path('/'),signing_path,expected=rows[signing_path],capture=True)
    verification = _read_target_fact(Path('/'),public_path,expected=rows[public_path],capture=True)
    try:
        private = load_pem_private_key(signing,password=None)
        public = load_pem_public_key(verification)
        derived = private.public_key().public_bytes(Encoding.PEM,PublicFormat.SubjectPublicKeyInfo)
        if derived != verification or sha(verification) != CANONICAL_AUTHORITY_SHA256:
            raise ValueError('key identity')
        if not isinstance(public,Ed25519PublicKey):
            raise ValueError('key algorithm')
    except Exception:
        raise TransactionError('PUBLIC_RECEIPT_KEYPAIR_DENIED') from None
    _read_target_fact(Path('/'),signing_path,expected=rows[signing_path])
    _read_target_fact(Path('/'),public_path,expected=rows[public_path])
    return private, public


def verify_prestate_receipt(raw, expected, public):
    """Require exact private prestate and signature, not merely a valid hash."""
    value = strict_json(raw)
    required = {'schema','source_plan_sha256','boot_id','generation_target',
                'selector_pre','image_files','unit_prestate'}
    if 'retained_transaction' in expected:
        required.add('retained_transaction')
        _retained_transaction_binding({'retained_transaction':expected['retained_transaction'],
                                      'current_boot_id':expected.get('boot_id')})
    if 'kernel_retirement' in expected:
        required.add('kernel_retirement')
        if ('retained_transaction' not in expected or not isinstance(expected['kernel_retirement'],dict)
                or expected['kernel_retirement'].get('boot_id')!=expected['boot_id']):
            raise TransactionError('PUBLIC_KERNEL_RETIREMENT_BINDING_DENIED')
    if (set(expected) != required or expected['schema'] != 'SereinPublicOutpostPrestateReceipt/v1'
            or set(value) != required | {'receipt_signature','receipt_digest'}):
        raise TransactionError('PUBLIC_PRESTATE_RECEIPT_DENIED')
    body = {key:value[key] for key in required}
    if body != expected or value['receipt_digest'] != sha(canonical({key:item for key,item in value.items() if key != 'receipt_digest'})):
        raise TransactionError('PUBLIC_PRESTATE_RECEIPT_DENIED')
    try:
        signature = value['receipt_signature']
        if not isinstance(signature,str) or not re.fullmatch(r'[A-Za-z0-9_-]{86}',signature):
            raise ValueError('signature encoding')
        public.verify(base64.urlsafe_b64decode(signature+'=='),canonical(body))
    except Exception:
        raise TransactionError('PUBLIC_PRESTATE_RECEIPT_SIGNATURE_DENIED') from None
    return value


def persist_prestate_receipt(root, selector, raw, expected, public):
    """Create one donor-layout private record with exclusive, durable readback.

    No overwrites, retries into an existing transaction, recovery or selector
    effects. Failed attempts remain evidence. This low-level primitive confers
    no authority: the native transaction must bind its plan, lock and signer.
    """
    verified = verify_prestate_receipt(raw, expected, public)
    if not isinstance(selector,str) or not re.fullmatch(
            r'/var/lib/serein/rollback/outpost-public-generation-\d{8}T\d{6}Z-[0-9a-f]{12}',selector):
        raise TransactionError('PUBLIC_ROLLBACK_SELECTOR_DENIED')
    if not isinstance(raw,bytes) or len(raw) > 16*1024*1024:
        raise TransactionError('PUBLIC_PRESTATE_RECEIPT_SIZE_DENIED')
    root = Path(os.path.abspath(root))
    parent = root/'var/lib/serein/rollback'
    name = PurePosixPath(selector).name
    handles = []
    try:
        fd = os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        handles.append((fd,None,None))
        for part in parent.parts[1:]:
            child = os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            handles.append((child,fd,part)); fd = child
        info = os.fstat(fd)
        if (info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) not in {0o700,0o755}
                or os.geteuid()!=0 or os.getegid()!=0):
            raise TransactionError('PUBLIC_PRESTATE_PARENT_DENIED')
        try: os.mkdir(name,0o700,dir_fd=fd)
        except FileExistsError: raise TransactionError('PUBLIC_ROLLBACK_COLLISION_DENIED') from None
        record = os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
        handles.append((record,fd,name))
        os.fchmod(record,0o700)
        file_fd = os.open('prestate-receipt.json',os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=record)
        with os.fdopen(file_fd,'w+b') as stream:
            os.fchmod(stream.fileno(),0o600)
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
            stream.seek(0)
            if stream.read(len(raw)+1) != raw:
                raise TransactionError('PUBLIC_PRESTATE_READBACK_DENIED')
        read_fd = os.open('prestate-receipt.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=record)
        with os.fdopen(read_fd,'rb') as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink!=1
                    or (info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode))!=(0,0,0o600)
                    or info.st_size!=len(raw) or stream.read(len(raw)+1)!=raw):
                raise TransactionError('PUBLIC_PRESTATE_READBACK_DENIED')
            after = os.fstat(stream.fileno())
            named = os.stat('prestate-receipt.json',dir_fd=record,follow_symlinks=False)
            identity = lambda item:(item.st_dev,item.st_ino,item.st_mode,item.st_uid,
                                    item.st_gid,item.st_nlink,item.st_size,item.st_mtime_ns,item.st_ctime_ns)
            if identity(info)!=identity(after) or identity(after)!=identity(named):
                raise TransactionError('PUBLIC_PRESTATE_READBACK_DENIED')
        os.fsync(record); os.fsync(fd)
        for child,owner,part in handles[1:]:
            opened=os.fstat(child); named=os.stat(part,dir_fd=owner,follow_symlinks=False)
            if (opened.st_dev,opened.st_ino,opened.st_mode,opened.st_uid,opened.st_gid)!=(named.st_dev,named.st_ino,named.st_mode,named.st_uid,named.st_gid):
                raise TransactionError('PUBLIC_PRESTATE_DIRECTORY_CHANGED')
    except OSError:
        raise TransactionError('PUBLIC_PRESTATE_RECORD_IO_DENIED') from None
    finally:
        for fd,_,_ in reversed(handles): os.close(fd)
    return {'path':selector+'/prestate-receipt.json','sha256':sha(raw),
            'receipt_digest':verified['receipt_digest'], 'installed':'UNPROVEN','activation':'NONE'}


def reread_prestate_receipt(root, receipt, expected, public):
    """Recheck durable record after target revalidation, before consumption."""
    if (not isinstance(receipt,dict) or not isinstance(receipt.get('path'),str)
            or not re.fullmatch(r'/var/lib/serein/rollback/outpost-public-generation-\d{8}T\d{6}Z-[0-9a-f]{12}/prestate-receipt.json',receipt['path'])):
        raise TransactionError('PUBLIC_PRESTATE_RECORD_PATH_DENIED')
    root = Path(os.path.abspath(root)); path = root/receipt['path'].lstrip('/')
    try:
        nofollow_ancestors(Path(root.anchor),path,allow_missing=False)
        parent = path.parent.lstat()
        if not stat.S_ISDIR(parent.st_mode) or (parent.st_uid,parent.st_gid,stat.S_IMODE(parent.st_mode))!=(0,0,0o700):
            raise TransactionError('PUBLIC_PRESTATE_RECEIPT_CUSTODY_DENIED')
        fd = os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as stream:
            before = os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink!=1
                    or (before.st_uid,before.st_gid,stat.S_IMODE(before.st_mode))!=(0,0,0o600)
                    or before.st_size>16*1024*1024):
                raise TransactionError('PUBLIC_PRESTATE_RECEIPT_CUSTODY_DENIED')
            raw = stream.read(16*1024*1024+1)
            after = os.fstat(stream.fileno())
        named = path.lstat()
        identity = lambda item:(item.st_dev,item.st_ino,item.st_mode,item.st_uid,item.st_gid,
                                item.st_nlink,item.st_size,item.st_mtime_ns,item.st_ctime_ns)
        nofollow_ancestors(Path(root.anchor),path,allow_missing=False)
        if (identity(before)!=identity(after) or identity(after)!=identity(named)
                or identity(parent)!=identity(path.parent.lstat())
                or len(raw)!=before.st_size or sha(raw)!=receipt.get('sha256')):
            raise TransactionError('PUBLIC_PRESTATE_READBACK_DENIED')
        value = verify_prestate_receipt(raw,expected,public)
        if value['receipt_digest']!=receipt.get('receipt_digest'):
            raise TransactionError('PUBLIC_PRESTATE_READBACK_DENIED')
        return dict(receipt)
    except OSError:
        raise TransactionError('PUBLIC_PRESTATE_RECORD_IO_DENIED') from None


def retained_predecessor(root, receipt, expected, public, candidate_path, expected_generation):
    """Read the exact signed predecessor; never move a live selector.

    This is the existing install transaction's recovery input, not a fallback
    search. The caller must separately bind current state and authorize the
    recovery effect. A historical receipt cannot confer current admission.
    """
    from .generation_launcher import read_selector, LaunchDenied
    root = Path(os.path.abspath(root))
    if (not isinstance(expected_generation, str)
            or not re.fullmatch(r'[0-9a-f]{64}', expected_generation)
            or not isinstance(candidate_path, str)
            or not re.fullmatch(r'/var/lib/serein/rollback/outpost-public-generation-\d{8}T\d{6}Z-[0-9a-f]{12}/candidate.json', candidate_path)):
        raise TransactionError('PUBLIC_RETAINED_TARGET_DENIED')
    # Freeze the caller's structures before any callback or filesystem read.
    receipt = strict_json(canonical(receipt))
    expected = strict_json(canonical(expected))
    reread_prestate_receipt(root, receipt, expected, public)
    row = expected['selector_pre'].get('current')
    required = {'target','bytes','sha256','mode','uid','gid','state','content_b64'}
    if (not isinstance(row, dict) or set(row) != required
            or row['target'] != '/var/lib/serein-outpost/generation-state/current.json'
            or row['state'] != 'PRESENT' or row['mode'] != '0644'
            or type(row['bytes']) is not int or not 0 < row['bytes'] <= 4096
            or (row['uid'], row['gid']) != (0, 0)):
        raise TransactionError('PUBLIC_RETAINED_SELECTOR_DENIED')
    try:
        captured = base64.b64decode(row['content_b64'], validate=True)
        selector = strict_json(captured)
        if (len(captured) != row['bytes'] or sha(captured) != row['sha256']
                or selector.get('generation') != expected_generation):
            raise TransactionError('PUBLIC_RETAINED_SELECTOR_DENIED')
        path = root / candidate_path.lstrip('/')
        nofollow_ancestors(Path(root.anchor), path, allow_missing=False)
        parent = path.parent.lstat()
        if (parent.st_uid, parent.st_gid, stat.S_IMODE(parent.st_mode)) != (0, 0, 0o700):
            raise TransactionError('PUBLIC_RETAINED_CUSTODY_DENIED')
        fingerprint = lambda s: (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,
                                 s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        def bounded_candidate():
            parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                opened_parent = os.fstat(parent_fd)
                if fingerprint(opened_parent) != fingerprint(parent):
                    raise TransactionError('PUBLIC_RETAINED_CHANGED')
                fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
                with os.fdopen(fd, 'rb') as stream:
                    first = os.fstat(stream.fileno())
                    if (not stat.S_ISREG(first.st_mode) or first.st_nlink != 1
                            or first.st_size != row['bytes']
                            or (first.st_uid, first.st_gid, stat.S_IMODE(first.st_mode)) != (0, 0, 0o600)):
                        raise TransactionError('PUBLIC_RETAINED_CUSTODY_DENIED')
                    data = stream.read(row['bytes'] + 1)
                    stream.seek(0)
                    second = stream.read(row['bytes'] + 1)
                    last = os.fstat(stream.fileno())
                named = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
                if (len(data) != row['bytes'] or data != second
                        or fingerprint(first) != fingerprint(last)
                        or fingerprint(last) != fingerprint(named)
                        or fingerprint(opened_parent) != fingerprint(path.parent.lstat())):
                    raise TransactionError('PUBLIC_RETAINED_CHANGED')
                return data, last
            finally:
                os.close(parent_fd)
        before, info = bounded_candidate()
        if strict_json(before) != selector:
            raise TransactionError('PUBLIC_RETAINED_SELECTOR_DENIED')
        selected, generation = read_selector(path, root / 'usr/share/serein/outpost-generations')
        if selected != selector or generation.name != expected_generation:
            raise TransactionError('PUBLIC_RETAINED_SELECTOR_DENIED')
        reread_prestate_receipt(root, receipt, expected, public)
        after, final = bounded_candidate()
        nofollow_ancestors(Path(root.anchor), path, allow_missing=False)
        if (before != after or fingerprint(info) != fingerprint(final)
                or fingerprint(parent) != fingerprint(path.parent.lstat())):
            raise TransactionError('PUBLIC_RETAINED_CHANGED')
        again, same_generation = read_selector(path, root / 'usr/share/serein/outpost-generations')
        if again != selected or same_generation != generation:
            raise TransactionError('PUBLIC_RETAINED_CHANGED')
    except (OSError, ValueError, KeyError, TypeError, LaunchDenied):
        raise TransactionError('PUBLIC_RETAINED_READ_DENIED') from None
    return {'selector': selector, 'captured_current': row,
            'predecessor_receipt': receipt, 'candidate_path': candidate_path,
            'generation': expected_generation, 'mutation_effect': 'NONE',
            'admission': 'UNPROVEN'}


def retained_recovery_prestate(root, fields, *, transitioning=False):
    """Bind the signed recovery selector to an existing canonical generation."""
    from .public_installer_cli import _load_plan
    root = Path(os.path.abspath(root))
    recovery = fields['recovery']
    record_path = root / recovery['predecessor_receipt_path'].lstrip('/')
    record = _load_plan(record_path, recovery['predecessor_receipt_sha256'])
    expected = {k:v for k,v in record.items() if k not in {'receipt_signature','receipt_digest'}}
    receipt = {'path':recovery['predecessor_receipt_path'],
               'sha256':recovery['predecessor_receipt_sha256'],
               'receipt_digest':record['receipt_digest']}
    anchor = next(row for row in fields['immutable_rows'] if row['target'] == str(CANONICAL_AUTHORITY_PATH))
    public = load_pem_public_key(_read_target_fact(root, str(CANONICAL_AUTHORITY_PATH), expected=anchor, capture=True))
    retained = retained_predecessor(root, receipt, expected, public,
        recovery['candidate_path'], recovery['release_digest'].removeprefix('sha256:'))
    candidate = _load_plan(root / recovery['candidate_path'].lstrip('/'), recovery['candidate_sha256'])
    if candidate != retained['selector'] or candidate['predecessor_receipt_sha256'] != recovery['source_plan_sha256']:
        raise TransactionError('PUBLIC_RECOVERY_SOURCE_DENIED')
    current = successor_generation_prestate(root)
    allowed = {recovery['current_selector_sha256']}
    if transitioning:
        allowed.add(retained['captured_current']['sha256'])
    if current['selectors']['current']['sha256'] not in allowed:
        raise TransactionError('PUBLIC_RECOVERY_CURRENT_CHANGED')
    # Preserve the authenticated original selector pair, never an arbitrary
    # currently available fallback. The successor reader validates its entire
    # retained inventory as well as selector custody; compare exact bytes too.
    lkg = expected['selector_pre'].get('lkg')
    required = {'target','bytes','sha256','mode','uid','gid','state','content_b64'}
    if (not isinstance(lkg, dict) or set(lkg) != required
            or lkg['target'] != '/var/lib/serein-outpost/generation-state/lkg.json'
            or lkg['state'] != 'PRESENT' or lkg['mode'] != '0644'
            or (lkg['uid'], lkg['gid']) != (0, 0)
            or type(lkg['bytes']) is not int or not 0 < lkg['bytes'] <= 4096):
        raise TransactionError('PUBLIC_RECOVERY_LKG_DENIED')
    try:
        lkg_bytes = base64.b64decode(lkg['content_b64'], validate=True)
        lkg_selector = strict_json(lkg_bytes)
        live = current['selectors']['lkg']
        facts = {key:value for key,value in lkg.items() if key not in {'state','content_b64'}}
        if (len(lkg_bytes) != lkg['bytes'] or sha(lkg_bytes) != lkg['sha256']
                or lkg['sha256'] != recovery['lkg_selector_sha256']
                or lkg_selector.get('generation') != recovery['lkg_generation']
                or live != dict(facts, selector=lkg_selector)
                or capture_selector_predecessor(root, current)['lkg'] != lkg_bytes):
            raise TransactionError('PUBLIC_RECOVERY_LKG_DENIED')
    except (ValueError, KeyError, TypeError):
        raise TransactionError('PUBLIC_RECOVERY_LKG_DENIED') from None
    generation = root / 'usr/share/serein/outpost-generations' / retained['generation']
    # The existing inventory reader already checks every byte and file policy.
    from .generation_launcher import _read_regular, read_selector
    source_raw, _ = _read_regular(generation / 'public-source.json', 0o644)
    source = strict_json(source_raw)
    if (source.get('schema') != 'SereinOutpostPublicSource/v1'
            or source.get('repository') != fields['repository']
            or any(source.get(key) != recovery[key] for key in
                   ('commit','tree','archive_sha256','release_digest','source_plan_sha256'))):
        raise TransactionError('PUBLIC_RECOVERY_SOURCE_DENIED')
    again, _ = read_selector(root / recovery['candidate_path'].lstrip('/'), generation.parent)
    if again != retained['selector']:
        raise TransactionError('PUBLIC_RETAINED_CHANGED')
    return {'target':'/usr/share/serein/outpost-generations/' + retained['generation'],
            'state':'RETAINED', 'retained':retained, 'source':source,
            'preserved_lkg':live}


def capture_retained_material(root, destination):
    """Read the already-indexed generation; do not stage, replace or delete it."""
    from .generation_launcher import read_selector, _read_regular, _decode_json, LaunchDenied
    root = Path(os.path.abspath(root))
    retained = destination['retained']
    path = root / retained['candidate_path'].lstrip('/')
    generations = root / 'usr/share/serein/outpost-generations'
    try:
        selector, directory = read_selector(path, generations)
        if selector != retained['selector'] or '/'+directory.relative_to(root).as_posix() != destination['target']:
            raise TransactionError('PUBLIC_RETAINED_CHANGED')
        raw, _ = _read_regular(directory/'generation-inventory.json', 0o644)
        inventory = _decode_json(raw)
        if (not isinstance(inventory, list)
                or sha(canonical(inventory)) != selector['inventory_digest']
                or any(not isinstance(row, dict) or row.get('kind') not in {'file','directory'}
                       or not isinstance(row.get('path'), str)
                       or row['path'].startswith('/') or '\\' in row['path']
                       or any(part in {'','.', '..'} for part in row['path'].split('/'))
                       for row in inventory)):
            raise TransactionError('PUBLIC_RETAINED_INVENTORY_DENIED')
        material = {}
        for row in inventory:
            if row['kind'] != 'file':
                continue
            name = row['path']
            value, info = _read_regular(directory/name, int(row['mode'], 8))
            if info.st_nlink != 1 or len(value) != row['bytes'] or sha(value) != row['sha256']:
                raise TransactionError('PUBLIC_RETAINED_CHANGED')
            material[name] = value
        release = strict_json(material['release-manifest.json'])
        material = bind_generation_material(release, material, selector['release_digest'])
        if strict_json(material['public-source.json']) != destination['source']:
            raise TransactionError('PUBLIC_RECOVERY_SOURCE_DENIED')
        again, same = read_selector(path, generations)
        if again != selector or same != directory:
            raise TransactionError('PUBLIC_RETAINED_CHANGED')
        return release, material
    except (OSError, ValueError, KeyError, TypeError, LaunchDenied):
        raise TransactionError('PUBLIC_RETAINED_MATERIAL_DENIED') from None


def seal_prepared_forward_state(prestate_raw, expected, private, public):
    """Initialize the donor journal only; no effect or admission is recorded."""
    prestate = verify_prestate_receipt(prestate_raw, expected, public)
    body = {key:prestate[key] for key in expected if key != 'schema'}
    body.update(schema='SereinPublicOutpostForwardState/v1',
                prestate_receipt_digest=prestate['receipt_digest'], phase='PREPARED', step=0)
    body['state_signature'] = base64.urlsafe_b64encode(private.sign(canonical(body))).decode('ascii').rstrip('=')
    body['state_digest'] = sha(canonical(body))
    raw = canonical(body) + b'\n'
    verify_prepared_forward_state(raw, prestate_raw, expected, public)
    return raw


def verify_prepared_forward_state(raw, prestate_raw, expected, public):
    """Bind the exact prestate, rejecting even signed phase advancement."""
    prestate = verify_prestate_receipt(prestate_raw, expected, public)
    body = {key:prestate[key] for key in expected if key != 'schema'}
    body.update(schema='SereinPublicOutpostForwardState/v1',
                prestate_receipt_digest=prestate['receipt_digest'], phase='PREPARED', step=0)
    value = strict_json(raw)
    if (set(value) != set(body) | {'state_signature','state_digest'}
            or type(value.get('step')) is not int
            or {key:value[key] for key in body} != body
            or value['state_digest'] != sha(canonical({key:item for key,item in value.items() if key!='state_digest'}))):
        raise TransactionError('PUBLIC_FORWARD_PRESTATE_BINDING_DENIED')
    try:
        signature = value['state_signature']
        if not isinstance(signature,str) or not re.fullmatch(r'[A-Za-z0-9_-]{86}',signature):
            raise ValueError('signature encoding')
        public.verify(base64.urlsafe_b64decode(signature+'=='),canonical(body))
    except Exception:
        raise TransactionError('PUBLIC_FORWARD_STATE_SIGNATURE_DENIED') from None
    return value


def prepared_forward_record(root, receipt, prestate_raw, expected, public, *, create_raw=None, journal=None):
    """Create once or independently read the initial private donor journal.

    No resume, phase advancement, recovery, selector or service action. Both
    paths bind the existing receipt and directory; failed writes are retained
    as collision evidence, never silently repaired or overwritten.
    """
    reread_prestate_receipt(root,receipt,expected,public)
    if sha(prestate_raw) != receipt.get('sha256'):
        raise TransactionError('PUBLIC_FORWARD_PRESTATE_BINDING_DENIED')
    verify_prestate_receipt(prestate_raw,expected,public)
    absolute = str(PurePosixPath(receipt['path']).parent/'forward-state.json')
    if create_raw is not None:
        if journal is not None or not isinstance(create_raw,bytes) or len(create_raw)>16*1024*1024:
            raise TransactionError('PUBLIC_FORWARD_STATE_DENIED')
        verified = verify_prepared_forward_state(create_raw,prestate_raw,expected,public)
        journal = {'path':absolute,'sha256':sha(create_raw),'state_digest':verified['state_digest'],
                   'phase':'PREPARED','step':0,'installed':'UNPROVEN','activation':'NONE'}
    if (not isinstance(journal,dict) or journal.get('path')!=absolute
            or journal.get('phase')!='PREPARED' or type(journal.get('step')) is not int or journal['step']!=0):
        raise TransactionError('PUBLIC_FORWARD_STATE_DENIED')
    root = Path(os.path.abspath(root)); parent = root/absolute.lstrip('/')
    handles = []
    try:
        fd = os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        handles.append((fd,None,None))
        for part in parent.parent.parts[1:]:
            child = os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            handles.append((child,fd,part)); fd=child
        info = os.fstat(fd)
        if (info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode))!=(0,0,0o700):
            raise TransactionError('PUBLIC_FORWARD_STATE_CUSTODY_DENIED')
        if create_raw is not None:
            if os.geteuid()!=0 or os.getegid()!=0:
                raise TransactionError('PUBLIC_FORWARD_STATE_CUSTODY_DENIED')
            try:
                opened = os.open('forward-state.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
            except FileExistsError:
                raise TransactionError('PUBLIC_FORWARD_STATE_COLLISION_DENIED') from None
            with os.fdopen(opened,'wb') as stream:
                os.fchmod(stream.fileno(),0o600)
                stream.write(create_raw); stream.flush(); os.fsync(stream.fileno())
            os.fsync(fd)
        opened = os.open('forward-state.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
        with os.fdopen(opened,'rb') as stream:
            before=os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink!=1
                    or (before.st_uid,before.st_gid,stat.S_IMODE(before.st_mode))!=(0,0,0o600)
                    or before.st_size>16*1024*1024):
                raise TransactionError('PUBLIC_FORWARD_STATE_CUSTODY_DENIED')
            raw=stream.read(16*1024*1024+1); after=os.fstat(stream.fileno())
        named=os.stat('forward-state.json',dir_fd=fd,follow_symlinks=False)
        identity=lambda item:(item.st_dev,item.st_ino,item.st_mode,item.st_uid,item.st_gid,
                              item.st_nlink,item.st_size,item.st_mtime_ns,item.st_ctime_ns)
        if (identity(before)!=identity(after) or identity(after)!=identity(named)
                or len(raw)!=before.st_size or sha(raw)!=journal.get('sha256')
                or (create_raw is not None and raw!=create_raw)):
            raise TransactionError('PUBLIC_FORWARD_STATE_READBACK_DENIED')
        value=verify_prepared_forward_state(raw,prestate_raw,expected,public)
        if value['state_digest']!=journal.get('state_digest'):
            raise TransactionError('PUBLIC_FORWARD_STATE_READBACK_DENIED')
        for child,owner,part in handles[1:]:
            opened=os.fstat(child); named=os.stat(part,dir_fd=owner,follow_symlinks=False)
            if (opened.st_dev,opened.st_ino,opened.st_mode,opened.st_uid,opened.st_gid)!=(named.st_dev,named.st_ino,named.st_mode,named.st_uid,named.st_gid):
                raise TransactionError('PUBLIC_FORWARD_DIRECTORY_CHANGED')
        reread_prestate_receipt(root,receipt,expected,public)
    except OSError:
        raise TransactionError('PUBLIC_FORWARD_STATE_IO_DENIED') from None
    finally:
        for fd,_,_ in reversed(handles): os.close(fd)
    return dict(journal)


def prepared_candidate_record(root, receipt, prestate_raw, expected, public,
                              selector, staging_parent, *, create=False, placed=False):
    """Bind private candidate.json to the actual launcher reader, not launch.

    The caller supplies the selector derived from the verified material. This
    checks its exact signed-prestate source/generation and staged inventory;
    it does not select current/LKG or infer permission to promote.
    """
    from .generation_launcher import read_selector, LaunchDenied
    reread_prestate_receipt(root,receipt,expected,public)
    prestate=verify_prestate_receipt(prestate_raw,expected,public)
    if (sha(prestate_raw)!=receipt.get('sha256') or not isinstance(selector,dict)
            or selector.get('predecessor_receipt_sha256')!=prestate['source_plan_sha256']
            or prestate['generation_target']!='/usr/share/serein/outpost-generations/'+str(selector.get('generation'))):
        raise TransactionError('PUBLIC_CANDIDATE_PRESTATE_BINDING_DENIED')
    root=Path(os.path.abspath(root)); parent=(root/receipt['path'].lstrip('/')).parent
    staging_parent=Path(os.path.abspath(staging_parent)); path=parent/'candidate.json'
    if placed and (create or staging_parent!=root/'usr/share/serein/outpost-generations'):
        raise TransactionError('PUBLIC_CANDIDATE_CONSUMER_DENIED')
    nofollow_ancestors(Path(staging_parent.anchor),staging_parent,allow_missing=False)
    info=staging_parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or (info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode))!=(0,0,0o755 if placed else 0o700):
        raise TransactionError('PRIVATE_STAGING_PARENT_REQUIRED')
    raw=canonical(selector)+b'\n'; handles=[]
    try:
        fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);handles.append((fd,None,None))
        for part in parent.parts[1:]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            handles.append((child,fd,part));fd=child
        info=os.fstat(fd)
        if (info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode))!=(0,0,0o700):
            raise TransactionError('PUBLIC_CANDIDATE_CUSTODY_DENIED')
        if create:
            if os.geteuid()!=0 or os.getegid()!=0:
                raise TransactionError('PUBLIC_CANDIDATE_CUSTODY_DENIED')
            try: opened=os.open('candidate.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
            except FileExistsError: raise TransactionError('PUBLIC_CANDIDATE_COLLISION_DENIED') from None
            with os.fdopen(opened,'wb') as stream:
                os.fchmod(stream.fileno(),0o600);stream.write(raw);stream.flush();os.fsync(stream.fileno())
            os.fsync(fd)
        opened=os.open('candidate.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
        with os.fdopen(opened,'rb') as stream:
            before=os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink!=1
                    or (before.st_uid,before.st_gid,stat.S_IMODE(before.st_mode))!=(0,0,0o600)
                    or before.st_size!=len(raw) or stream.read(len(raw)+1)!=raw):
                raise TransactionError('PUBLIC_CANDIDATE_READBACK_DENIED')
            value,selected=read_selector(path,staging_parent)
            if value!=selector or selected!=staging_parent/selector['generation']:
                raise TransactionError('PUBLIC_CANDIDATE_CONSUMER_DENIED')
            after=os.fstat(stream.fileno());named=os.stat('candidate.json',dir_fd=fd,follow_symlinks=False)
            identity=lambda item:(item.st_dev,item.st_ino,item.st_mode,item.st_uid,item.st_gid,
                                  item.st_nlink,item.st_size,item.st_mtime_ns,item.st_ctime_ns)
            if identity(before)!=identity(after) or identity(after)!=identity(named):
                raise TransactionError('PUBLIC_CANDIDATE_READBACK_DENIED')
        for child,owner,part in handles[1:]:
            opened=os.fstat(child);named=os.stat(part,dir_fd=owner,follow_symlinks=False)
            if (opened.st_dev,opened.st_ino,opened.st_mode,opened.st_uid,opened.st_gid)!=(named.st_dev,named.st_ino,named.st_mode,named.st_uid,named.st_gid):
                raise TransactionError('PUBLIC_CANDIDATE_DIRECTORY_CHANGED')
        reread_prestate_receipt(root,receipt,expected,public)
    except (OSError,LaunchDenied):
        raise TransactionError('PUBLIC_CANDIDATE_CONSUMER_DENIED') from None
    finally:
        for fd,_,_ in reversed(handles):os.close(fd)
    return {'path':str(PurePosixPath(receipt['path']).parent/'candidate.json'),
            'sha256':sha(raw),'generation':selector['generation'],'installed':'UNPROVEN','activation':'NONE'}


def read_generation_witness(root, *, expected_generation, boot_id, not_before,
                            service_uid, service_gid, observed_at=None):
    """Independently consume the existing G0 coordinator's bounded witness.

    The caller binds the service account and promotion boundary. This is a
    supporting runtime observation only: no positive G0/Host admission and no
    change to a selector, unit, credential, constitution or recovery state.
    """
    from outpost.service import validate_coordinator_witness, OutpostServiceError
    if (type(not_before) not in (int,float) or not math.isfinite(not_before) or not_before<0
            or (observed_at is not None and (type(observed_at) not in (int,float)
                or not math.isfinite(observed_at) or observed_at<not_before))
            or any(type(item) is not int or item<0 for item in (service_uid,service_gid))
            or not isinstance(expected_generation,dict)):
        raise TransactionError('PUBLIC_WITNESS_EXPECTATION_DENIED')
    root = Path(os.path.abspath(root))
    if _read_target_fact(root,'/proc/sys/kernel/random/boot_id').strip()!=str(boot_id).encode('ascii',errors='replace'):
        raise TransactionError('PUBLIC_BOOT_DRIFT_DENIED')
    before = successor_generation_prestate(root)
    if before['selectors']['current']['selector'] != expected_generation:
        raise TransactionError('PUBLIC_WITNESS_CURRENT_GENERATION_DENIED')
    path = root/'var/lib/serein-outpost/coordinator/current.json'
    try:
        nofollow_ancestors(Path(root.anchor),path,allow_missing=False)
        parent = path.parent.lstat()
        if (not stat.S_ISDIR(parent.st_mode)
                or (parent.st_uid,parent.st_gid,stat.S_IMODE(parent.st_mode))!=(service_uid,service_gid,0o750)):
            raise TransactionError('PUBLIC_WITNESS_CUSTODY_DENIED')
        fd = os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as stream:
            opened=os.fstat(stream.fileno())
            if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink!=1
                    or (opened.st_uid,opened.st_gid,stat.S_IMODE(opened.st_mode))!=(service_uid,service_gid,0o600)
                    or opened.st_size>1024*1024):
                raise TransactionError('PUBLIC_WITNESS_CUSTODY_DENIED')
            raw=stream.read(1024*1024+1); after=os.fstat(stream.fileno())
        named=path.lstat()
        identity=lambda item:(item.st_dev,item.st_ino,item.st_mode,item.st_uid,item.st_gid,
                              item.st_nlink,item.st_size,item.st_mtime_ns,item.st_ctime_ns)
        nofollow_ancestors(Path(root.anchor),path,allow_missing=False)
        if (identity(opened)!=identity(after) or identity(after)!=identity(named)
                or identity(parent)!=identity(path.parent.lstat()) or len(raw)!=opened.st_size):
            raise TransactionError('PUBLIC_WITNESS_CHANGED_DURING_READ')
        # Native time is sampled after capturing bytes: current/LKG hashing
        # may span a coordinator publication. An earlier upper bound would
        # falsely label that valid new witness as future evidence.
        upper_bound=time.time() if observed_at is None else observed_at
        if (type(upper_bound) not in (int,float) or not math.isfinite(upper_bound)
                or upper_bound<not_before):
            raise TransactionError('PUBLIC_WITNESS_EXPECTATION_DENIED')
        value=validate_coordinator_witness(strict_json(raw),boot_id=boot_id,
                                           observed_at=upper_bound,expected_generation=expected_generation)
        if value['observed_at']<not_before:
            raise TransactionError('PUBLIC_WITNESS_PREDATES_PROMOTION')
        if successor_generation_prestate(root)!=before:
            raise TransactionError('PUBLIC_WITNESS_CURRENT_GENERATION_CHANGED')
        if _read_target_fact(root,'/proc/sys/kernel/random/boot_id').strip()!=str(boot_id).encode('ascii',errors='replace'):
            raise TransactionError('PUBLIC_BOOT_DRIFT_DENIED')
    except (OSError,OutpostServiceError):
        raise TransactionError('PUBLIC_CURRENT_BOOT_WITNESS_DENIED') from None
    return {'result':'SUPPORTING_CURRENT_BOOT_WITNESS', 'witness':value,
            'coordinator_sha256':sha(raw),
            'current_selector_sha256':before['selectors']['current']['sha256'],
            'admission':'UNPROVEN','authority_effect':'NONE','mutation_effect':'NONE'}


def read_vitals_witness(*, expected_generation, boot_id, not_before, certificate_row,
                       failed_install_digest=None):
    """Supporting local presentation/TLS proof, never public-edge acceptance.

    Reuse the installed fixed edge and its immutable certificate. No secret
    leaves the guest. JSON and HTML each carry their own validated projection;
    live timestamps mean their projection digests need not be identical.
    """
    import html
    import http.client
    import socket
    import ssl
    from outpost import vitals_edge
    from outpost.http_readonly import html_body
    from outpost.service import validate_coordinator_witness
    from outpost.vitals_aggregation import validate_producer

    if failed_install_digest is not None and (not isinstance(failed_install_digest,str)
            or not re.fullmatch('[0-9a-f]{64}',failed_install_digest)):
        raise TransactionError('PUBLIC_VITALS_FAILURE_BINDING_DENIED')

    def projection(raw):
        value=strict_json(raw)
        if (not vitals_edge._surface_ready(raw) or value['current_boot_id']!=boot_id
                or not not_before<=value['generated_at']<=time.time()):
            raise TransactionError('PUBLIC_VITALS_PROJECTION_DENIED')
        if failed_install_digest is not None:
            rows=[item for item in value['sections']['recovery']['perspectives']
                  if item['producer']=='OUTPOST_INSTALLER']
            if len(rows)!=1:
                raise TransactionError('PUBLIC_VITALS_FAILURE_BINDING_DENIED')
            row=validate_producer({k:v for k,v in rows[0].items() if k!='freshness'})
            observation=row['payload']
            if (row['claim']!='FAILED_INSTALL' or row['boot_id']!=boot_id
                    or observation.get('state')!='FAILED_INSTALL'
                    or observation.get('boot_id')!=boot_id
                    or observation.get('generation')!=expected_generation['generation']
                    or observation.get('observation_digest')!=failed_install_digest
                    or sha(canonical({k:v for k,v in observation.items() if k!='observation_digest'}))!=failed_install_digest):
                raise TransactionError('PUBLIC_VITALS_FAILURE_BINDING_DENIED')
            return value
        rows=[item for item in value['sections']['domains']['perspectives']
              if item['producer']=='OUTPOST_DOMAIN_COORDINATOR']
        if len(rows)!=1 or 'coordinator' not in rows[0]['payload']:
            raise TransactionError('PUBLIC_VITALS_GENERATION_DENIED')
        coordinator=validate_coordinator_witness(rows[0]['payload']['coordinator'],
            boot_id=boot_id,observed_at=time.time(),expected_generation=expected_generation)
        if coordinator['observed_at']<not_before:
            raise TransactionError('PUBLIC_VITALS_GENERATION_DENIED')
        return value

    certificate=_read_target_fact(Path('/'),'/etc/serein/tls/serein-backend-cert.pem',
                                  expected=certificate_row,capture=True)
    context=ssl.create_default_context(cadata=certificate.decode('ascii'))
    context.verify_flags|=ssl.VERIFY_X509_PARTIAL_CHAIN
    expected_der=ssl.PEM_cert_to_DER_cert(certificate.decode('ascii'))
    def fetch(path,accept):
        # Exact already-installed backend route; not a substitute for public
        # HAProxy readback by the independent SFOS verifier.
        with socket.create_connection((vitals_edge.BACKEND_ADDRESS,vitals_edge.BACKEND_PORT),timeout=3) as tcp:
            with context.wrap_socket(tcp,server_hostname='serein.sardonyxsapphire.us') as tls:
                if tls.getpeercert(binary_form=True)!=expected_der:
                    raise TransactionError('PUBLIC_VITALS_TLS_IDENTITY_DENIED')
                request=('GET '+path+' HTTP/1.1\r\nHost: serein.sardonyxsapphire.us\r\nAccept: '+accept+'\r\nConnection: close\r\n\r\n').encode('ascii')
                tls.sendall(request)
                response=http.client.HTTPResponse(tls);response.begin()
                body=response.read(vitals_edge.MAX_RESPONSE_BYTES+1)
                if response.status!=200 or len(body)>vitals_edge.MAX_RESPONSE_BYTES:
                    raise TransactionError('PUBLIC_VITALS_ENDPOINT_DENIED')
                return response.getheader('Content-Type'),body
    try:
        status,kind,_,raw=vitals_edge._presentation('GET',vitals_edge.STATUS_PATH,'application/json')
        if status!=200 or kind!='application/json':
            raise TransactionError('PUBLIC_VITALS_SOCKET_DENIED')
        local=projection(raw)
        kind,raw=fetch(vitals_edge.STATUS_PATH,'application/json')
        if kind!='application/json':raise TransactionError('PUBLIC_VITALS_TYPE_DENIED')
        api=projection(raw)
        kind,raw=fetch(vitals_edge.STATUS_PATH,'text/html')
        if kind!='text/html; charset=utf-8':raise TransactionError('PUBLIC_VITALS_TYPE_DENIED')
        text=raw.decode('utf-8');prefix="<pre id='vitality'>"
        if text.count(prefix)!=1:raise TransactionError('PUBLIC_VITALS_HTML_DENIED')
        embedded=html.unescape(text.split(prefix,1)[1].split('</pre>',1)[0]).encode()
        rendered=projection(embedded)
        if html_body(rendered)!=raw:raise TransactionError('PUBLIC_VITALS_HTML_DENIED')
        kind,ready=fetch(vitals_edge.READY_PATH,'application/json')
        if kind!='application/json' or strict_json(ready)!={'status':'READY'}:
            raise TransactionError('PUBLIC_VITALS_READINESS_DENIED')
        _read_target_fact(Path('/'),'/etc/serein/tls/serein-backend-cert.pem',expected=certificate_row)
    except (OSError,ValueError,KeyError,TypeError,http.client.HTTPException) as error:
        raise TransactionError('PUBLIC_VITALS_ACCEPTANCE_DENIED') from error
    return {'result':('LOCAL_VITALS_FAILURE_JSON_HTML_OBSERVED' if failed_install_digest is not None
                      else 'LOCAL_VITALS_JSON_HTML_OBSERVED'),'boot_id':boot_id,
            'generation':expected_generation['generation'],
            'local_projection':local['projection_digest'],'api_projection':api['projection_digest'],
            'html_projection':rendered['projection_digest'],'certificate_sha256':certificate_row['sha256'],
            'public_edge':'INDEPENDENT_VERIFICATION_REQUIRED','admission_effect':'NONE'}


def successor_generation_prestate(root):
    """Capture the observed existing-generation road without any mutation.

    Adapted from the public donor's selector/prestate checks, not its fallback,
    custody changes or restoration. VM4010 has current/LKG generations: absent
    or invalid state must not silently become FIRST_INSTALL or another current.
    The eventual promotion must compare this exact prestate again under its
    transaction lock; this read alone is neither a lock nor authorization.
    """
    from .generation_launcher import read_selector, _read_regular, LaunchDenied
    root = Path(os.path.abspath(root))
    state = root / 'var/lib/serein-outpost/generation-state'
    generations = root / 'usr/share/serein/outpost-generations'
    nofollow_ancestors(Path(root.anchor), state, allow_missing=False)
    nofollow_ancestors(Path(root.anchor), generations, allow_missing=False)
    def directory_identity(path):
        info=path.lstat()
        if (not stat.S_ISDIR(info.st_mode)
                or (info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode)) != (0,0,0o755)):
            raise TransactionError('PUBLIC_SUCCESSOR_CUSTODY_DENIED')
        return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid)
    try:
        state_identity=directory_identity(state)
        root_identity=directory_identity(generations)
        selectors={}
        captured={}
        for name in ('current','lkg'):
            path=state/(name+'.json')
            raw,info=_read_regular(path,0o644)
            if info.st_nlink!=1 or len(raw)>1024*1024:
                raise TransactionError('PUBLIC_SUCCESSOR_SELECTOR_DENIED')
            value,_=read_selector(path,generations)
            if strict_json(raw)!=value:
                raise TransactionError('PUBLIC_SUCCESSOR_CHANGED_DURING_READ')
            captured[name]=(raw,info.st_dev,info.st_ino)
            selectors[name]={'target':'/var/lib/serein-outpost/generation-state/'+name+'.json',
                             'bytes':len(raw),'sha256':sha(raw),'mode':'0644','uid':0,'gid':0,
                             'selector':value}
        for name,(raw,device,inode) in captured.items():
            after,info=_read_regular(state/(name+'.json'),0o644)
            if (after,info.st_dev,info.st_ino)!=(raw,device,inode) or info.st_nlink!=1:
                raise TransactionError('PUBLIC_SUCCESSOR_CHANGED_DURING_READ')
        if directory_identity(state)!=state_identity or directory_identity(generations)!=root_identity:
            raise TransactionError('PUBLIC_SUCCESSOR_CHANGED_DURING_READ')
    except (OSError,ValueError,TypeError,KeyError,LaunchDenied):
        raise TransactionError('PUBLIC_SUCCESSOR_PRESTATE_DENIED') from None
    return {'classification':'SUCCESSOR_GENERATION_REPLACEMENT','selectors':selectors,
            'state_directory':{'mode':'0755','uid':0,'gid':0},
            'current_admission':'UNPROVEN','authority_effect':'NONE','mutation_effect':'NONE'}


def _fixture_target_prestate(root, plan):
    """Synthetic target proof only; cannot enter the production preflight."""
    if type(plan) is not FixtureVerifiedSourcePlan:
        raise TransactionError("FIXTURE_PLAN_REQUIRED")
    root=Path(os.path.abspath(root))
    if root==Path("/") or root.samefile("/"):
        raise TransactionError("FIXTURE_ROOT_REQUIRED")
    result=_target_prestate(root,plan.as_dict())
    result["result"]="FIXTURE_TARGET_PRESTATE_ONLY"
    return result


def _target_prestate(root, fields):
    from verify_install_preflight import verify_host_identity
    try:
        host_identity=verify_host_identity(root, {
            "os_id":"debian", "os_version_id":"13", "hostname_policy":"PRESERVE_NONEMPTY"})
    except (SystemExit, OSError, UnicodeError, ValueError):
        raise TransactionError("PUBLIC_HOST_IDENTITY_DENIED") from None
    boot_path="/proc/sys/kernel/random/boot_id"
    try:boot=_read_target_fact(root,boot_path).decode("ascii").strip()
    except UnicodeError:raise TransactionError("PUBLIC_BOOT_DRIFT_DENIED") from None
    if boot!=fields["current_boot_id"] or host_identity["boot_id"]!=boot:
        raise TransactionError("PUBLIC_BOOT_DRIFT_DENIED")
    rows=[]
    for row in fields["immutable_rows"]:
        _read_target_fact(root,row["target"],expected=row)
        rows.append(dict(row))
    # Detect a changed boot during the read-only comparison as well as before
    # it. This is a point-in-time prestate, never a claim of target locking.
    if _read_target_fact(root,boot_path).strip()!=boot.encode("ascii"):
        raise TransactionError("PUBLIC_BOOT_DRIFT_DENIED")
    return {"result":"SUPPORTING_TARGET_PRESTATE_ONLY","current_boot_id":boot,
            "host_identity":host_identity,
            "immutable_rows":rows,"installed":"UNPROVEN",
            "authority_effect":"NONE","mutation_effect":"NONE"}


def _read_target_fact(root, absolute, *, expected=None, capture=False):
    """Descriptor-bound comparison; optional private signer capture only.

    Capture is internal transaction material, never public evidence. Ordinary
    immutable checks continue returning no file contents.
    """
    if capture and (expected is None or absolute not in {
            '/etc/serein-outpost/cognition-signing.pem',str(CANONICAL_AUTHORITY_PATH),
            '/etc/serein/tls/serein-backend-cert.pem'}):
        raise TransactionError('PUBLIC_KEY_CAPTURE_PATH_DENIED')
    root=Path(os.path.abspath(root))
    if absolute not in IMMUTABLE_POLICY and absolute!="/proc/sys/kernel/random/boot_id":
        raise TransactionError("PUBLIC_TARGET_PATH_DENIED")
    target=root/absolute.lstrip("/")
    descriptors=[]
    try:
        parent=os.open("/",os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        descriptors.append((parent,None,None))
        for part in target.parts[1:-1]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
            descriptors.append((child,parent,part));parent=child
        descriptor=os.open(target.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        with os.fdopen(descriptor,"rb") as stream:
            before=os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1:
                raise TransactionError("PUBLIC_TARGET_CUSTODY_DENIED")
            if expected is not None:
                if (before.st_size!=expected["bytes"] or stat.S_IMODE(before.st_mode)!=int(expected["mode"],8)
                        or before.st_uid!=expected["uid"] or before.st_gid!=expected["gid"]):
                    raise TransactionError("PUBLIC_IMMUTABLE_PRESTATE_DENIED")
                if before.st_size>MAX_ARCHIVE_BYTES:
                    raise TransactionError("PUBLIC_TARGET_SIZE_DENIED")
                if capture and before.st_size>65536:
                    raise TransactionError('PUBLIC_KEY_SIZE_DENIED')
                digest=hashlib.sha256();size=0;captured=[]
                while True:
                    block=stream.read(min(1024*1024,expected["bytes"]+1-size))
                    if not block:break
                    size+=len(block);digest.update(block)
                    if capture: captured.append(block)
                    if size>expected["bytes"]:raise TransactionError("PUBLIC_IMMUTABLE_PRESTATE_DENIED")
                if size!=expected["bytes"] or digest.hexdigest()!=expected["sha256"]:
                    raise TransactionError("PUBLIC_IMMUTABLE_PRESTATE_DENIED")
                result=b''.join(captured) if capture else None
            else:
                result=stream.read(38)
                if len(result)>37:raise TransactionError("PUBLIC_BOOT_DRIFT_DENIED")
            after=os.fstat(stream.fileno())
            fingerprint=lambda item:(item.st_dev,item.st_ino,item.st_mode,item.st_uid,item.st_gid,item.st_nlink,item.st_size,item.st_mtime_ns,item.st_ctime_ns)
            named=os.stat(target.name,dir_fd=parent,follow_symlinks=False)
            if fingerprint(before)!=fingerprint(after) or fingerprint(after)!=fingerprint(named):
                raise TransactionError("PUBLIC_TARGET_CHANGED_DURING_READ")
            for fd,parent_fd,name in descriptors[1:]:
                opened=os.fstat(fd);named_directory=os.stat(name,dir_fd=parent_fd,follow_symlinks=False)
                if (opened.st_dev,opened.st_ino,opened.st_mode)!=(named_directory.st_dev,named_directory.st_ino,named_directory.st_mode):
                    raise TransactionError("PUBLIC_TARGET_CHANGED_DURING_READ")
            return result
    except (OSError,UnicodeError):
        raise TransactionError("PUBLIC_TARGET_READ_DENIED") from None
    finally:
        for descriptor,_,_ in reversed(descriptors):os.close(descriptor)


def _fixture_archive_material(raw, plan):
    """Test-authority parser proof only; excluded from production fetch."""
    if type(plan) is not FixtureVerifiedSourcePlan:
        raise TransactionError("FIXTURE_PLAN_REQUIRED")
    return _archive_material(raw, plan.as_dict())


def generation_inventory(material):
    """Derive the donor generation inventory without creating any files.

    This is the deterministic inventory slice of install_public_generation,
    not its selectors, permission changes, installation or recovery behavior.
    The generated inventory itself is deliberately outside its own digest.
    """
    from verify_install_preflight import _path
    if not isinstance(material, dict) or not material:
        raise TransactionError("PUBLIC_GENERATION_MATERIAL_DENIED")
    directories = set()
    for name, data in material.items():
        try:
            # The admitted release manifest joins payload only after its
            # digest/schema checks; payload path validation reserves its name.
            valid = name if name == "release-manifest.json" else _path(name)
        except (SystemExit, TypeError):
            raise TransactionError("PUBLIC_PAYLOAD_PATH_DENIED") from None
        if valid != name or not isinstance(data, bytes):
            raise TransactionError("PUBLIC_GENERATION_MATERIAL_DENIED")
        parents = {parent.as_posix() for parent in PurePosixPath(name).parents
                   if parent.as_posix() != "."}
        if name == "generation-inventory.json" or "generation-inventory.json" in parents:
            raise TransactionError("PUBLIC_GENERATION_INVENTORY_COLLISION_DENIED")
        directories.update(parents)
    if directories.intersection(material):
        raise TransactionError("PUBLIC_GENERATION_PATH_CONFLICT_DENIED")
    inventory = [{"kind":"directory", "path":name, "mode":"0755", "uid":0, "gid":0}
                 for name in sorted(directories, key=lambda value:(value.count("/"), value))]
    inventory.extend({"kind":"file", "path":name, "bytes":len(data), "sha256":sha(data),
                      "mode":"0644", "uid":0, "gid":0}
                     for name, data in sorted(material.items()))
    return inventory


def bind_generation_material(release, material, release_digest):
    """Freeze and recheck prepared bytes before inactive filesystem staging.

    Reuses the archive's exact release/payload contract. This pure comparison
    does not verify signing custody or grant installation authority by itself.
    """
    if not isinstance(release, dict) or not isinstance(material, dict):
        raise TransactionError("PREPARED_MATERIAL_DENIED")
    release = strict_json(canonical(release))
    material = dict(material)
    if (release.get("schema") != "SereinOutpostSourceRelease/v2"
            or release.get("classification") != "PUBLIC_HOST_GATE_SAFE_UNCOMMISSIONED"
            or release.get("self_digest") != release_digest
            or release_digest != "sha256:" + sha(canonical({k:v for k,v in release.items() if k != "self_digest"}))):
        raise TransactionError("PREPARED_RELEASE_IDENTITY_DENIED")
    manifest = material.get("release-manifest.json")
    if (not isinstance(manifest, bytes) or len(manifest) > 1024 * 1024
            or strict_json(manifest) != release):
        raise TransactionError("PREPARED_MANIFEST_BINDING_DENIED")
    payload = release.get("payload")
    if not isinstance(payload, list) or not payload:
        raise TransactionError("PREPARED_PAYLOAD_DENIED")
    expected = {}
    for row in payload:
        if (not isinstance(row, dict) or set(row) != {"path", "bytes", "sha256"}
                or not isinstance(row["path"], str) or row["path"] in expected
                or row["path"] == "release-manifest.json"
                or type(row["bytes"]) is not int or row["bytes"] < 0):
            raise TransactionError("PREPARED_PAYLOAD_DENIED")
        expected[row["path"]] = row
    generated=set()
    if "public-source.json" in material:
        binding=strict_json(material["public-source.json"])
        if (not isinstance(binding,dict) or set(binding)!={"schema","repository","commit","tree","archive_sha256","release_digest","source_plan_sha256"}
                or binding.get("schema")!="SereinOutpostPublicSource/v1"
                or binding.get("repository")!="Kaotikking/sfos-public"
                or binding.get("release_digest")!=release_digest
                or any(not re.fullmatch(r'[0-9a-f]{40}',str(binding.get(k))) for k in ('commit','tree'))
                or any(not re.fullmatch(r'[0-9a-f]{64}',str(binding.get(k))) for k in ('archive_sha256','source_plan_sha256'))
                or "public-source.json" in expected):
            raise TransactionError("PREPARED_PUBLIC_SOURCE_DENIED")
        generated.add("public-source.json")
    if set(material) != set(expected) | {"release-manifest.json"} | generated:
        raise TransactionError("PREPARED_MATERIAL_DENOMINATOR_DENIED")
    if any(not isinstance(data, bytes) for data in material.values()) or sum(map(len, material.values())) > MAX_ARCHIVE_BYTES:
        raise TransactionError("PREPARED_MATERIAL_DENIED")
    for name, row in expected.items():
        data = material[name]
        if len(data) != row["bytes"] or sha(data) != row["sha256"]:
            raise TransactionError("PREPARED_PAYLOAD_HASH_DENIED")
    generation_inventory(material)
    return material


def bootstrap_candidate_precheck(release, material, source_plan_sha256, *, retained_selector=None):
    """Independent Outpost source predicate, not installed Vitals acceptance.

    Native target/transaction checks still run separately under the lock.
    Host compatibility is not SFOS admission; source consistency is not
    permission, constitutional admission or an installed current-boot result.
    """
    from outpost.constitutional_registry import bootstrap_constitution_binding, ConstitutionalRegistryError
    material=bind_generation_material(release,material,release.get('self_digest'))
    path='outpost/bootstrap-constitution.json'
    rows=[row for row in release['payload'] if row['path']==path]
    if len(rows)!=1 or path not in material:
        raise TransactionError('BOOTSTRAP_CONSTITUTION_REQUIRED')
    try: constitution=bootstrap_constitution_binding(material[path],rows[0]['sha256'])
    except ConstitutionalRegistryError as error:
        raise TransactionError(str(error)) from None
    selector=prepared_generation_selector(release,material,source_plan_sha256)
    # Recovery is bound by its caller to an already captured, signed-plan
    # selected predecessor. Never impose a successor-only capability on that
    # generation, or let a mismatched selector relax the candidate check.
    if retained_selector is not None and retained_selector != selector:
        raise TransactionError('PUBLIC_RETAINED_SOURCE_DENIED')
    runtime = {'outpost/service.py','outpost/host_witness_runner.py',
               'outpost/watchdog.py','outpost/reboot_vitality.py',
               'outpost/constitutional_registry.py','outpost/host_vitality.py',
               'outpost/vitals_aggregation.py','outpost/debian_host_collector.py',
               'outpost/presentation_service.py','outpost/vitals_edge.py',
               'outpost/http_readonly.py','outpost/vitals_runtime.py',
               'outpost/public_tree_host.py','install/install-outpost.sh',
               'install/public_installer_cli.py','install/public_generation_transaction.py',
               'install/transaction.py','install/kernel_first_install_runner.py',
               'verify_install_preflight.py'}
    if retained_selector is None:
        runtime.add('outpost/kernel_direct_witness.py')
    image_sources = set(IMAGE_FILES)
    if retained_selector is not None:
        # A signed, exactly bound historical generation predates recurring
        # collection. Its history stays valid; this never exempts a candidate.
        image_sources.discard('systemd/serein-outpost-host-witness.timer')
    if any(source not in material for source in image_sources|runtime):
        raise TransactionError('PUBLIC_IMAGE_PAYLOAD_MISSING')
    return {'result':'G0_SOURCE_PREDICATES_PASS','release_digest':release['self_digest'],
            'source_plan_sha256':source_plan_sha256,'selector':selector,'constitution':constitution,
            'installed':'UNPROVEN','sfos_admission':'UNPROVEN','outpost_admission':'UNPROVEN',
            'authority_effect':'NONE','admission_effect':'NONE','downstream_activation':'NONE'}


def prepared_generation_selector(release, material, source_plan_sha256):
    """Build the existing selector grammar without promoting any generation.

    This constructs the existing canonical selector grammar.
    The predecessor receipt field binds its canonical signed source-plan bytes,
    not file formatting, a claimed constitution, or inferred install authority.
    """
    if (not isinstance(source_plan_sha256,str)
            or not re.fullmatch(r'[0-9a-f]{64}',source_plan_sha256)):
        raise TransactionError('PREPARED_SOURCE_PLAN_BINDING_DENIED')
    release_digest=release.get('self_digest') if isinstance(release,dict) else None
    material=bind_generation_material(release,material,release_digest)
    if ('public-source.json' in material
            and strict_json(material['public-source.json'])['source_plan_sha256']!=source_plan_sha256):
        raise TransactionError('PREPARED_SOURCE_PLAN_BINDING_DENIED')
    selector={'schema':'SereinOutpostGenerationSelector/v1',
              'generation':release_digest.removeprefix('sha256:'),
              'release_digest':release_digest,
              'predecessor_receipt_sha256':source_plan_sha256,
              'inventory_digest':sha(canonical(generation_inventory(material)))}
    selector['selector_digest']=sha(canonical(selector))
    return selector


def prepared_bootstrap_image(release, material, target_prestate):
    """Bind the donor image pre/post rows without writing an installed image.

    Expected-before comes only from the existing preparation result. The
    enclosing transaction must recheck that entire result under its lock;
    this pure plan is not authority, a receipt, or executable recovery.
    """
    digest = release.get('self_digest') if isinstance(release, dict) else None
    material = bind_generation_material(release, material, digest)
    if not isinstance(target_prestate, dict):
        raise TransactionError('PREPARED_BOOTSTRAP_PRESTATE_REQUIRED')
    installed = target_prestate.get('installed_prestate')
    bootstrap = target_prestate.get('bootstrap_prestate')
    policy = bootstrap.get('host_time') if isinstance(bootstrap, dict) else None
    time_bytes = host_time_configuration(policy) if policy is not None else None
    expected_units = set(IMAGE_UNITS) | ({HOST_TIME_UNIT} if policy is not None else set())
    expected_paths = [item[0] for item in IMAGE_FILES.values()] + ([HOST_TIME_CONFIG] if policy is not None else [])
    if (not isinstance(installed, dict)
            or installed.get('classification') != 'SUCCESSOR_GENERATION_REPLACEMENT'
            or not isinstance(installed.get('selectors'), dict)
            or set(installed['selectors']) != {'current', 'lkg'}
            or not isinstance(bootstrap, dict)
            or bootstrap.get('mutation_effect') != 'NONE'
            or not isinstance(bootstrap.get('files'), list)
            or not isinstance(bootstrap.get('units'), dict)
            or set(bootstrap['units']) != expected_units):
        raise TransactionError('PREPARED_BOOTSTRAP_PRESTATE_REQUIRED')
    rows = bootstrap['files']
    if (len(rows) != len(expected_paths)
            or any(not isinstance(row, dict) for row in rows)
            or [row.get('target') for row in rows] != expected_paths):
        raise TransactionError('PREPARED_BOOTSTRAP_DENOMINATOR_DENIED')
    image = []
    sources = list(IMAGE_FILES.items()) + ([('@signed-host-time', (HOST_TIME_CONFIG, '0644'))] if policy is not None else [])
    for (source, (target, mode)), before in zip(sources, rows):
        if source != '@signed-host-time' and source not in material:
            raise TransactionError('PREPARED_BOOTSTRAP_PAYLOAD_MISSING')
        if before.get('state') == 'ABSENT':
            if set(before) != {'target', 'state'}:
                raise TransactionError('PREPARED_BOOTSTRAP_PRESTATE_DENIED')
        elif (before.get('state') != 'PRESENT'
                or set(before) != {'target','state','bytes','sha256','mode','uid','gid'}
                or type(before['bytes']) is not int or before['bytes'] < 0
                or before['mode'] not in {'0644','0755'}
                or type(before['uid']) is not int or before['uid'] != 0
                or type(before['gid']) is not int or before['gid'] != 0
                or not isinstance(before['sha256'], str)
                or not re.fullmatch(r'[0-9a-f]{64}', before['sha256'])):
            raise TransactionError('PREPARED_BOOTSTRAP_PRESTATE_DENIED')
        name = PurePosixPath(target).name
        if name in IMAGE_UNITS:
            unit = _checked_unit_state(name, bootstrap['units'][name])
            if (before['state'] == 'PRESENT') != (unit['LoadState'] == 'loaded'):
                raise TransactionError('PREPARED_BOOTSTRAP_UNIT_BINDING_DENIED')
        data = time_bytes if source == '@signed-host-time' else material[source]
        image.append({'source':source, 'target':target, 'pre':dict(before),
                      'post':{'target':target, 'state':'PRESENT', 'bytes':len(data),
                              'sha256':sha(data), 'mode':mode, 'uid':0, 'gid':0}})
    return image


def _archive_material(raw, plan):
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_ARCHIVE_BYTES:
        raise TransactionError("PUBLIC_ARCHIVE_SIZE_DENIED")
    if sha(raw) != plan.get("archive_sha256"):
        raise TransactionError("PUBLIC_ARCHIVE_HASH_DENIED")
    files, directories, root, expanded = {}, set(), None, 0
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as compressed:
            decoded = compressed.read(MAX_ARCHIVE_BYTES + 1)
        if len(decoded) > MAX_ARCHIVE_BYTES:
            raise TransactionError("PUBLIC_ARCHIVE_EXPANSION_DENIED")
        with tarfile.open(fileobj=io.BytesIO(decoded), mode="r:") as archive:
            for member in archive:
                name = member.name.rstrip("/") if member.isdir() else member.name
                path = PurePosixPath(name)
                if (path.is_absolute() or ".." in path.parts or not path.parts
                        or path.as_posix() != name or "\\" in name or ":" in name or "\x00" in name):
                    raise TransactionError("PUBLIC_ARCHIVE_PATH_DENIED")
                if root is None:
                    root = path.parts[0]
                if path.parts[0] != root:
                    raise TransactionError("PUBLIC_ARCHIVE_ROOT_DENIED")
                if len(path.parts) == 1:
                    if not member.isdir():
                        raise TransactionError("PUBLIC_ARCHIVE_ROOT_DENIED")
                    continue
                relative = PurePosixPath(*path.parts[1:]).as_posix()
                if relative in files or relative in directories:
                    raise TransactionError("PUBLIC_ARCHIVE_DUPLICATE_DENIED")
                # Bound expanded content, including header overhead. Hash
                # agreement alone cannot make an archive safe to process.
                expanded += 512 + member.size
                if expanded > MAX_ARCHIVE_BYTES:
                    raise TransactionError("PUBLIC_ARCHIVE_EXPANSION_DENIED")
                if member.isdir():
                    directories.add(relative)
                    continue
                if not member.isreg() or member.issym() or member.islnk():
                    raise TransactionError("PUBLIC_ARCHIVE_MEMBER_TYPE_DENIED")
                stream = archive.extractfile(member)
                if stream is None:
                    raise TransactionError("PUBLIC_ARCHIVE_MEMBER_DENIED")
                data = stream.read(member.size + 1)
                if len(data) != member.size:
                    raise TransactionError("PUBLIC_ARCHIVE_TRUNCATED")
                files[relative] = data
    except (tarfile.TarError, OSError, EOFError):
        raise TransactionError("PUBLIC_ARCHIVE_DENIED") from None
    prefix = "sfos/outpost/"
    manifest_path = prefix + "release-manifest.json"
    if manifest_path not in files:
        raise TransactionError("PUBLIC_RELEASE_MISSING")
    try:
        release = strict_json(files[manifest_path])
    except (ValueError, UnicodeError):
        raise TransactionError("PUBLIC_RELEASE_SHAPE_DENIED") from None
    if not isinstance(release, dict):
        raise TransactionError("PUBLIC_RELEASE_SHAPE_DENIED")
    stated = release.get("self_digest")
    unsigned = {key:value for key,value in release.items() if key != "self_digest"}
    if stated != "sha256:" + sha(canonical(unsigned)) or stated != plan.get("release_digest"):
        raise TransactionError("PUBLIC_RELEASE_DIGEST_DENIED")
    if release.get("schema") != "SereinOutpostSourceRelease/v2" or release.get("classification") != "PUBLIC_HOST_GATE_SAFE_UNCOMMISSIONED":
        raise TransactionError("PUBLIC_RELEASE_CLASSIFICATION_DENIED")
    payload, source_only = release.get("payload"), release.get("source_only_files", [])
    if not isinstance(payload, list) or not payload or not isinstance(source_only, list):
        raise TransactionError("PUBLIC_PAYLOAD_DENIED")
    expected = {}
    from verify_install_preflight import _path
    for row in payload + source_only:
        if not isinstance(row, dict) or set(row) != {"path", "bytes", "sha256"}:
            raise TransactionError("PUBLIC_PAYLOAD_DENIED")
        try:
            name = _path(row["path"])
        except SystemExit:
            raise TransactionError("PUBLIC_PAYLOAD_PATH_DENIED") from None
        if name in expected or type(row["bytes"]) is not int or row["bytes"] < 0:
            raise TransactionError("PUBLIC_PAYLOAD_DENIED")
        expected[name] = row
    archive_files = {name[len(prefix):]:data for name,data in files.items() if name.startswith(prefix) and name != manifest_path}
    if set(archive_files) != set(expected):
        raise TransactionError("PUBLIC_ARCHIVE_DENOMINATOR_DENIED")
    for name, data in archive_files.items():
        row = expected[name]
        if row["bytes"] != len(data) or row["sha256"] != sha(data):
            raise TransactionError("PUBLIC_PAYLOAD_HASH_DENIED")
    # No IMAGE_FILES, service allowlist or generated selectors are inferred.
    # This return value is an inactive byte set, not an admitted installation.
    material = {row["path"]:archive_files[row["path"]] for row in payload}
    material["release-manifest.json"] = files[manifest_path]
    generation_inventory(material)
    return release, material


class _GenerationFileIO:
    """Bounded file CAS for the donor image, selectors and private journal.

    Production constructs this only inside the verified-plan transaction.
    A non-root fixture directory is used by Linux tests, never by the CLI.
    Existing parent permissions are preserved; no privilege repair is hidden
    here. All replacements use same-directory rename and durable readback.
    """
    def __init__(self, root, receipt_directory, *, host_time=None):
        self.root = Path(os.path.abspath(root))
        if not re.fullmatch(r'/var/lib/serein/rollback/outpost-public-generation-\d{8}T\d{6}Z-[0-9a-f]{12}', receipt_directory):
            raise TransactionError('PUBLIC_TRANSACTION_DIRECTORY_DENIED')
        self.receipt_directory = receipt_directory
        if host_time is not None:
            host_time_configuration(host_time)
        self.host_time = dict(host_time) if host_time is not None else None
        self.last_time_checks = {}
        self.first_time_failure = None
        self.allowed = {item[0] for item in IMAGE_FILES.values()} | {
            INSTALL_OBSERVATION,
            '/var/lib/serein-outpost/generation-state/current.json',
            '/var/lib/serein-outpost/generation-state/lkg.json',
            receipt_directory+'/forward-state.json',
            receipt_directory+'/transaction-receipt.json',
            receipt_directory+'/failure-receipt.json'}
        if self.host_time is not None:
            self.allowed.add(HOST_TIME_CONFIG)

    @contextmanager
    def parent(self, absolute):
        if absolute not in self.allowed:
            raise TransactionError('PUBLIC_EFFECT_PATH_DENIED')
        path = self.root/absolute.lstrip('/')
        handles=[]
        try:
            fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            handles.append((fd,None,None))
            for name in path.parent.parts[1:]:
                child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                handles.append((child,fd,name));fd=child
            info=os.fstat(fd)
            if (info.st_uid,info.st_gid)!=(0,0) or stat.S_IMODE(info.st_mode) not in {0o700,0o755}:
                raise TransactionError('PUBLIC_EFFECT_PARENT_CUSTODY_DENIED')
            def recheck():
                for child,owner,name in handles[1:]:
                    opened=os.fstat(child);named=os.stat(name,dir_fd=owner,follow_symlinks=False)
                    if (opened.st_dev,opened.st_ino)!=(named.st_dev,named.st_ino):
                        raise TransactionError('PUBLIC_EFFECT_PARENT_CHANGED')
            recheck()
            yield fd,path.name,recheck
            recheck()
        finally:
            for fd,_,_ in reversed(handles):os.close(fd)

    @staticmethod
    def _read(fd,name,absolute):
        try: child=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
        except FileNotFoundError:return {'target':absolute,'state':'ABSENT'}
        with os.fdopen(child,'rb') as stream:
            before=os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink!=1
                    or (before.st_uid,before.st_gid)!=(0,0)
                    or stat.S_IMODE(before.st_mode) not in {0o600,0o644,0o755}
                    or before.st_size>16*1024*1024):
                raise TransactionError('PUBLIC_EFFECT_FILE_CUSTODY_DENIED')
            raw=stream.read(16*1024*1024+1);after=os.fstat(stream.fileno())
        named=os.stat(name,dir_fd=fd,follow_symlinks=False)
        identity=lambda i:(i.st_dev,i.st_ino,i.st_mode,i.st_uid,i.st_gid,i.st_nlink,i.st_size,i.st_mtime_ns,i.st_ctime_ns)
        if identity(before)!=identity(after) or identity(after)!=identity(named) or len(raw)!=before.st_size:
            raise TransactionError('PUBLIC_EFFECT_FILE_CHANGED')
        return {'target':absolute,'state':'PRESENT','bytes':len(raw),'sha256':sha(raw),
                'mode':f'{stat.S_IMODE(before.st_mode):04o}','uid':0,'gid':0,
                'content_b64':base64.b64encode(raw).decode('ascii')}

    def read(self,absolute):
        with self.parent(absolute) as (fd,name,_):return self._read(fd,name,absolute)

    def selected_generation(self):
        from .generation_launcher import read_selector, LaunchDenied
        try:
            return read_selector(self.root/'var/lib/serein-outpost/generation-state/current.json',
                                 self.root/'usr/share/serein/outpost-generations')[0]
        except LaunchDenied:
            raise TransactionError('PUBLIC_SELECTOR_READBACK_DENIED') from None

    def replace(self,absolute,before,after):
        if before.get('target')!=absolute or after.get('target')!=absolute:
            raise TransactionError('PUBLIC_EFFECT_BINDING_DENIED')
        if after.get('state')=='PRESENT':
            raw=base64.b64decode(after['content_b64'],validate=True)
            if (len(raw)!=after['bytes'] or sha(raw)!=after['sha256'] or after['mode'] not in {'0600','0644','0755'}
                    or (after.get('uid'),after.get('gid'))!=(0,0)):
                raise TransactionError('PUBLIC_EFFECT_BYTES_DENIED')
        elif after!={'target':absolute,'state':'ABSENT'}:
            raise TransactionError('PUBLIC_EFFECT_BINDING_DENIED')
        with self.parent(absolute) as (fd,name,recheck):
            if self._read(fd,name,absolute)!=before:raise TransactionError('PUBLIC_EFFECT_CAS_DENIED')
            if after['state']=='ABSENT':
                if before['state']!='ABSENT':os.unlink(name,dir_fd=fd)
            else:
                # No wildcard cleanup or reuse of an interrupted temporary file.
                temporary='.'+name+'.'+after['sha256'][:16]+'.new'
                child=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,int(after['mode'],8),dir_fd=fd)
                owned=os.fstat(child)
                try:
                    os.fchmod(child,int(after['mode'],8))
                    with os.fdopen(child,'wb') as stream:
                        stream.write(raw);stream.flush();os.fsync(stream.fileno())
                    recheck()
                    if self._read(fd,name,absolute)!=before:raise TransactionError('PUBLIC_EFFECT_CAS_DENIED')
                    os.replace(temporary,name,src_dir_fd=fd,dst_dir_fd=fd)
                finally:
                    try:
                        named=os.stat(temporary,dir_fd=fd,follow_symlinks=False)
                        if (named.st_dev,named.st_ino)==(owned.st_dev,owned.st_ino):os.unlink(temporary,dir_fd=fd)
                    except FileNotFoundError:pass
            os.fsync(fd);recheck()
            if self._read(fd,name,absolute)!=after:raise TransactionError('PUBLIC_EFFECT_READBACK_DENIED')

    def unit(self,action,name=None):
        if action=='daemon-reload' and name is None:args=[action]
        elif action in {'stop','start'} and name in (*IMAGE_UNITS, *((HOST_TIME_UNIT,) if self.host_time is not None else ())):args=[action,name]
        else:raise TransactionError('PUBLIC_SERVICE_EFFECT_DENIED')
        try:subprocess.run(['/usr/bin/systemctl',*args],check=True,capture_output=True,timeout=90)
        except (OSError,subprocess.SubprocessError):raise TransactionError('PUBLIC_SERVICE_EFFECT_FAILED') from None

    def unit_state(self,name):return read_bootstrap_unit(name)

    def time_observation(self):
        if self.host_time is None:
            raise TransactionError('PUBLIC_HOST_TIME_POLICY_DENIED')
        self.last_time_checks = {'observation_read':False}
        host_time_dropin_preflight(self.root)
        observation = read_host_time_observation(self.host_time)
        daemon = observation['daemon']
        self.last_time_checks = {
            'observation_read':True,
            'synchronized':observation['synchronized'] is True,
            'offset_in_bounds':abs(observation['offset_seconds']) <= 1,
            **{key:daemon[key] == ('' if key in ('LinkNTPServers','RuntimeNTPServers')
                                  else self.host_time['server']) for key in
               ('LinkNTPServers','RuntimeNTPServers','SystemNTPServers',
                'FallbackNTPServers','ServerName','ServerAddress')}}
        return observation

    def clock_observation(self):
        boot = _read_target_fact(self.root,'/proc/sys/kernel/random/boot_id').strip().decode('ascii')
        before = time.monotonic(); utc = time.time(); after = time.monotonic()
        if _read_target_fact(self.root,'/proc/sys/kernel/random/boot_id').strip().decode('ascii') != boot:
            raise TransactionError('PUBLIC_HOST_CLOCK_OBSERVATION_DENIED')
        return {'boot_id':boot,'utc':utc,'monotonic_before':before,'monotonic_after':after}

    def time_witness(self):
        deadline = time.monotonic() + 30
        while True:
            try:
                return validate_host_time_witness(self.host_time, self.time_observation())
            except TransactionError as error:
                if self.first_time_failure is None:
                    self.first_time_failure = _host_time_failure_record(error, self.last_time_checks)
                if time.monotonic() >= deadline:
                    raise
                time.sleep(1)


def _host_time_failure_record(error, checks):
    """Fixed, bounded diagnostic values only; never exception text or inputs."""
    code = (error.args[0] if isinstance(error, TransactionError) and len(error.args)==1
            and isinstance(error.args[0],str) else None)
    row = {'code':code if code in {
        'PUBLIC_HOST_TIME_READ_DENIED','PUBLIC_HOST_TIME_ALTERNATE_SOURCE_DENIED',
        'PUBLIC_HOST_TIME_SOURCE_UNAVAILABLE','PUBLIC_HOST_TIME_SAMPLE_DENIED',
        'PUBLIC_HOST_TIME_WITNESS_DENIED','PUBLIC_HOST_TIME_DROPIN_CONFLICT',
        'PUBLIC_HOST_TIME_CORRECTION_BOUND_DENIED'
    } else 'UNCLASSIFIED_HOST_TIME_FAILURE'}
    row['checks'] = {key:value for key,value in checks.items()
        if key in {'observation_read','synchronized','offset_in_bounds','LinkNTPServers',
                   'RuntimeNTPServers','SystemNTPServers','FallbackNTPServers','ServerName','ServerAddress'}
        and type(value) is bool}
    source = getattr(error, 'host_time_source_error', None)
    if (isinstance(source,dict) and set(source)=={'operation','reason'}
            and source['operation'] in ('CONNECT','SEND','RECEIVE')
            and source['reason'] in ('TIMEOUT','CONNECTION_REFUSED','CONNECTION_RESET',
                'NETWORK_UNREACHABLE','HOST_UNREACHABLE','PERMISSION','OTHER')):
        row['source_error'] = dict(source)
    predicate = getattr(error, 'host_time_sample_predicate', None)
    if (row['code'] == 'PUBLIC_HOST_TIME_SAMPLE_DENIED' and isinstance(predicate,str)
            and predicate in ('LENGTH','ORIGIN','MODE','VERSION','LEAP','STRATUM',
                'TIMESTAMP_ORDER','MONOTONIC_RTT','NETWORK_DELAY','CLOCK_CHANGED_DURING_SAMPLE')):
        row['sample_predicate'] = predicate
    return row


def _effect_row(absolute,raw,mode='0600'):
    return {'target':absolute,'state':'PRESENT','bytes':len(raw),'sha256':sha(raw),
            'mode':mode,'uid':0,'gid':0,'content_b64':base64.b64encode(raw).decode('ascii')}


def _signed_transition_record(body,private,public):
    value=strict_json(canonical(body))
    signature=private.sign(canonical(value));public.verify(signature,canonical(value))
    value['state_signature']=base64.urlsafe_b64encode(signature).decode('ascii').rstrip('=')
    value['state_digest']=sha(canonical(value))
    return canonical(value)+b'\n'


def _complete_bootstrap_promotion(io,prepared,body,prestate_raw,private,public,
                                  precheck,verify_invariants,accept,*,retained=None):
    """Complete the existing donor transaction, not a second installer.

    Called under the same verified-plan lock after exact inactive placement.
    Candidate checks never grant admission. Failure preserves the captured
    prestate and failed generation as evidence; it never selects or starts a
    predecessor. A subsequent attempt needs a new complete generation and
    fresh authority, not replay of this journal. Lock ownership is unchanged.
    """
    verify_prestate_receipt(prestate_raw,body,public)
    policy = io.host_time
    unit_names = (*IMAGE_UNITS, *((HOST_TIME_UNIT,) if policy is not None else ()))
    if set(body['unit_prestate']) != set(unit_names):
        raise TransactionError('PUBLIC_HOST_TIME_BINDING_DENIED')
    time_rows = [row for row in body['image_files'] if row['target'] == HOST_TIME_CONFIG]
    time_before = None
    clock_before = None
    negative_slew = False
    if policy is not None:
        if (retained is not None or len(time_rows) != 1
                or time_rows[0]['post'] != _effect_row(HOST_TIME_CONFIG, host_time_configuration(policy), '0644')):
            raise TransactionError('PUBLIC_HOST_TIME_BINDING_DENIED')
        time_before = io.time_observation()
        negative_slew = validate_host_time_correction(policy, time_before)
        clock_before = io.clock_observation()
    elif time_rows:
        raise TransactionError('PUBLIC_HOST_TIME_BINDING_DENIED')
    selector=prepared['candidate_selector']
    source_digest = body['source_plan_sha256']
    if retained is not None:
        if (retained.get('selector') != selector or retained.get('mutation_effect') != 'NONE'
                or retained.get('generation') != selector.get('generation')):
            raise TransactionError('PUBLIC_RETAINED_SELECTOR_DENIED')
        source_digest = selector['predecessor_receipt_sha256']
    if (precheck.get('result')!='G0_SOURCE_PREDICATES_PASS' or precheck.get('selector')!=selector
            or precheck.get('source_plan_sha256')!=source_digest
            or body['generation_target']!='/usr/share/serein/outpost-generations/'+selector['generation']):
        raise TransactionError('PUBLIC_PROMOTION_PRECHECK_DENIED')
    journal_path=io.receipt_directory+'/forward-state.json'
    journal=io.read(journal_path)
    verify_prepared_forward_state(base64.b64decode(journal['content_b64']),prestate_raw,body,public)
    # Retirement can outlast a Host collection cycle. Reacquire the exact
    # signed settled state; transient phases never become accepted prestate.
    _await_promotion_unit_prestate(io, body['unit_prestate'], verify_invariants)
    # This path replaces VM4010's already-enabled Outpost, not first-boot
    # enablement. Preserve the complete existing wants-link footprint. A
    # disabled/missing/static target needs its own captured link transaction;
    # never silently run systemctl enable outside the signed prestate.
    if body['unit_prestate']['serein-outpost.target']['UnitFileState']!='enabled':
        raise TransactionError('PUBLIC_ENABLED_SUCCESSOR_TARGET_REQUIRED')
    for row in body['image_files']:
        if io.read(row['target'])!=row['pre']:raise TransactionError('PUBLIC_EFFECT_CAS_DENIED')
    for row in body['selector_pre'].values():
        if io.read(row['target'])!=row:raise TransactionError('PUBLIC_EFFECT_CAS_DENIED')
    verify_invariants()
    initial=strict_json(base64.b64decode(journal['content_b64']))
    unsigned={key:value for key,value in initial.items() if key not in {'state_signature','state_digest'}}
    failure_record = None
    last_phase, last_step = initial['phase'], initial['step']
    def advance(phase,step=0):
        nonlocal journal, last_phase, last_step
        verify_invariants()
        raw=_signed_transition_record({**unsigned,'phase':phase,'step':step,
                                      **({'failure':failure_record} if failure_record is not None else {})},private,public)
        after=_effect_row(journal_path,raw)
        io.replace(journal_path,journal,after);journal=after
        last_phase, last_step = phase, step
    current=body['selector_pre']['current'];lkg=body['selector_pre']['lkg']
    selected=_effect_row(current['target'],canonical(selector)+b'\n','0644')
    if retained is not None:
        selected = strict_json(canonical(retained['captured_current']))
        if (selected.get('target') != current['target']
                or strict_json(base64.b64decode(selected['content_b64'], validate=True)) != selector):
            raise TransactionError('PUBLIC_RETAINED_SELECTOR_DENIED')
    startup_unchanged = all(row['pre']==row['post'] for row in body['image_files']
                            if row['target'] in {target for target,_ in IMAGE_FILES.values()})
    vitals_cutover_complete = not startup_unchanged
    try:
        for index,name in enumerate(reversed(unit_names),1):
            verify_invariants()
            if (body['unit_prestate'][name]['ActiveState']=='active'
                    and not (startup_unchanged and name in VITALS_UNITS)):
                io.unit('stop',name)
            advance('PREPARED',index)
        for index,row in enumerate(body['image_files'],1):
            verify_invariants()
            if io.read(row['target'])!=row['pre']:raise TransactionError('PUBLIC_EFFECT_CAS_DENIED')
            if row['pre']!=row['post']:io.replace(row['target'],row['pre'],row['post'])
            advance('IMAGE',index)
        io.unit('daemon-reload');advance('DAEMON_RELOAD')
        time_witness = None
        if policy is not None:
            io.unit('start', HOST_TIME_UNIT)
            time_witness = validate_host_time_witness(policy, io.time_witness())
            advance('HOST_TIME_VERIFIED')
        # Preserve the last known-good selector: the captured current may be
        # unadmitted. Only current moves, atomically, after all image writes.
        if io.read(lkg['target'])!=lkg:raise TransactionError('PUBLIC_LKG_SELECTOR_CAS_DENIED')
        verify_invariants();io.replace(current['target'],current,selected);advance('SELECTORS')
        if startup_unchanged:
            for name in reversed(VITALS_UNITS):
                verify_invariants();io.unit('stop',name)
                if io.unit_state(name)['ActiveState'] not in {'inactive','failed'}:
                    raise TransactionError('PUBLIC_VITALS_READINESS_DENIED')
            vitals_cutover_complete = True
        not_before=time.time()
        # Existing enablement is retained exactly; no wants link is changed.
        advance('TARGET_ENABLED')
        io.unit('start','serein-outpost.target');advance('TARGET_STARTED')
        units={name:io.unit_state(name) for name in IMAGE_UNITS}
        if (units['serein-outpost.target']['ActiveState']!='active'
                or units['serein-outpost.target']['UnitFileState']!='enabled'
                or any(units[name]['ActiveState']!='active' for name in (
                    'serein-outpost.service','serein-outpost-presentation.service',
                    'serein-https-gateway-adapter.service','serein-outpost-host-witness.timer'))):
            raise TransactionError('PUBLIC_TARGET_ACTIVATION_DENIED')
        witness=accept(selector,not_before)
        if (witness.get('result')!='SUPPORTING_CURRENT_BOOT_WITNESS'
                or witness.get('witness',{}).get('boot_id')!=body['boot_id']
                or witness.get('witness',{}).get('generation_identity')!=selector
                or witness.get('vitals',{}).get('result')!='LOCAL_VITALS_JSON_HTML_OBSERVED'
                or witness['vitals'].get('boot_id')!=body['boot_id']
                or witness['vitals'].get('generation')!=selector['generation']):
            raise TransactionError('PUBLIC_POSTPROMOTION_WITNESS_DENIED')
        for row in body['image_files']:
            if io.read(row['target'])!=row['post']:raise TransactionError('PUBLIC_IMAGE_READBACK_DENIED')
        if io.read(current['target'])!=selected or io.read(lkg['target'])!=lkg:
            raise TransactionError('PUBLIC_SELECTOR_READBACK_DENIED')
        if policy is not None:
            # Acceptance can take time. Never reuse the pre-promotion time
            # sample as terminal proof of source, daemon or clock state.
            if io.unit_state(HOST_TIME_UNIT) != body['unit_prestate'][HOST_TIME_UNIT]:
                raise TransactionError('PUBLIC_HOST_TIME_TERMINAL_UNIT_DENIED')
            time_witness = validate_host_time_witness(policy, io.time_observation())
            if negative_slew and time_witness.get('native_version') != time_before['native_version']:
                raise TransactionError('PUBLIC_HOST_TIME_CORRECTION_BOUND_DENIED')
            clock_effect = validate_host_clock_interval(clock_before,io.clock_observation(),body['boot_id'],
                                                       negative_slew=negative_slew)
        verify_invariants();advance('TERMINAL_ACCEPTED')
        result={'schema':'SereinOutpostBootstrapInstallReceipt/v1','result':('RESTORED_CURRENT_BOOT_OBSERVED' if retained is not None else 'INSTALLED_CURRENT_BOOT_OBSERVED'),
                'source_plan_sha256':body['source_plan_sha256'],'boot_id':body['boot_id'],
                'generation_identity':selector,'constitution':precheck['constitution'],
                'prestate_receipt_digest':strict_json(prestate_raw)['receipt_digest'],
                'current_boot_witness':witness,'outpost_admission':'UNPROVEN',
                'sfos_admission':'UNPROVEN','stage1':'UNPROVEN','downstream_activation':'NONE'}
        if 'kernel_retirement' in body:
            retirement=prepared.get('kernel_retirement')
            if (not isinstance(retirement,dict)
                    or retirement.get('result')!='KERNEL_PROGRAM_RETIRED_PRIVATE_STATE_PRESERVED'
                    or retirement.get('source_plan_sha256')!=body['source_plan_sha256']
                    or retirement.get('boot_id')!=body['boot_id']):
                raise TransactionError('PUBLIC_KERNEL_RETIREMENT_TERMINAL_DENIED')
            result['kernel_retirement']=retirement
        if policy is not None:
            result['host_time'] = {'before':time_before, 'after':time_witness,
                                  'clock_effect':clock_effect,
                                  'history_rewritten':False, 'clock_rewind_permitted':False}
        if retained is not None:
            result['preserved_lkg_selector'] = strict_json(base64.b64decode(lkg['content_b64']))
            result['preserved_lkg_sha256'] = lkg['sha256']
        path=io.receipt_directory+'/transaction-receipt.json'
        # This write precedes the terminal journal commit. It cannot itself
        # claim that commit succeeded, including after a crash or fsync error.
        supporting = {**result, 'result':'INSTALLATION_WITNESS_RECORDED',
                      'terminal_journal_required':'forward-state.json:COMPLETE'}
        io.replace(path,{'target':path,'state':'ABSENT'},_effect_row(path,_signed_transition_record(supporting,private,public)))
        advance('COMPLETE')
        return result
    except BaseException as failure:
        # Retain fixed predicates in the existing signed journal. Never persist
        # arbitrary exception text, traceback, private inputs or source packets.
        allowed_codes = {
            'PUBLIC_HOST_TIME_READ_DENIED','PUBLIC_HOST_TIME_ALTERNATE_SOURCE_DENIED',
            'PUBLIC_HOST_TIME_SOURCE_UNAVAILABLE','PUBLIC_HOST_TIME_SAMPLE_DENIED',
            'PUBLIC_HOST_TIME_WITNESS_DENIED','PUBLIC_HOST_TIME_DROPIN_CONFLICT',
            'PUBLIC_HOST_TIME_TERMINAL_UNIT_DENIED','PUBLIC_HOST_CLOCK_OBSERVATION_DENIED',
            'PUBLIC_HOST_TIME_CORRECTION_BOUND_DENIED',
            'PUBLIC_HOST_CLOCK_EFFECT_DENIED','PUBLIC_LKG_SELECTOR_CAS_DENIED',
            'PUBLIC_TARGET_ACTIVATION_DENIED','PUBLIC_POSTPROMOTION_WITNESS_DENIED',
            'PUBLIC_IMAGE_READBACK_DENIED','PUBLIC_SELECTOR_READBACK_DENIED',
            'PUBLIC_EFFECT_CAS_DENIED','PUBLIC_VITALS_PROJECTION_DENIED',
            'PUBLIC_VITALS_GENERATION_DENIED','PUBLIC_VITALS_TLS_IDENTITY_DENIED',
            'PUBLIC_VITALS_ENDPOINT_DENIED','PUBLIC_VITALS_SOCKET_DENIED',
            'PUBLIC_VITALS_TYPE_DENIED','PUBLIC_VITALS_HTML_DENIED',
            'PUBLIC_VITALS_READINESS_DENIED','PUBLIC_VITALS_ACCEPTANCE_DENIED'}
        code = (failure.args[0] if isinstance(failure,TransactionError)
                and len(failure.args)==1 and isinstance(failure.args[0],str) else None)
        failure_record = {'code':code if code in allowed_codes else 'UNCLASSIFIED_INSTALL_FAILURE',
                          'last_completed_phase':last_phase,'last_completed_step':last_step}
        if policy is not None:
            failure_record['host_time_failure'] = _host_time_failure_record(failure, io.last_time_checks)
            if io.first_time_failure is not None:
                failure_record['host_time_first_failure'] = dict(io.first_time_failure)
            failure_record['host_time_checks'] = {
                key:value for key,value in io.last_time_checks.items()
                if key in {'observation_read','synchronized','offset_in_bounds',
                           'LinkNTPServers','RuntimeNTPServers','SystemNTPServers',
                           'FallbackNTPServers','ServerName','ServerAddress'} and type(value) is bool}
        # A failed successor is not permission to reactivate its predecessor.
        # Keep image/selector bytes and the signed prestate as evidence. Stop
        # only this transaction's Outpost units; never repair the retained lock,
        # rewrite history, rewind Host time, or claim failed bytes are accepted.
        try:
            verify_invariants()
            if io.read(lkg['target'])!=lkg:raise TransactionError('PUBLIC_RECOVERY_LKG_CHANGED')
            # Only the fully placed, hash-verified CURRENT successor may keep
            # or start its independent read-only observer after a failure.
            # Never select/start predecessor material or a partially placed image.
            observer_safe = False
            retained_observer = False
            try:
                observer_safe = (io.read(current['target'])==selected
                    and all(io.read(row['target'])==row['post'] for row in body['image_files'])
                    and io.selected_generation()==selector)
                retained_observer = (startup_unchanged and io.read(current['target'])==current
                    and io.selected_generation()==strict_json(base64.b64decode(current['content_b64'])))
            except (OSError, ValueError, TransactionError):
                pass
            observation = {'schema':'SereinOutpostInstallObservation/v1',
                'boot_id':body['boot_id'],'generation':selector['generation'],
                'observed_at':time.time(),'state':'FAILED_INSTALL',
                'failure_code':failure_record['code'],'last_completed_phase':last_phase,
                'last_completed_step':last_step,'authority_effect':'NONE','admission_effect':'NONE'}
            observation['observation_digest']=sha(canonical(observation))
            observation_written = False
            try:
                before_observation=io.read(INSTALL_OBSERVATION)
                io.replace(INSTALL_OBSERVATION,before_observation,
                           _effect_row(INSTALL_OBSERVATION,canonical(observation)+b'\n','0644'))
                observation_written = True
            except (OSError, ValueError, TransactionError):
                pass  # Recording failure must not skip independently safe stops.
            observer_safe = observer_safe and observation_written
            contained = True
            unit_outcomes = []
            for name in reversed(IMAGE_UNITS):
                if name in VITALS_UNITS and (observer_safe or (retained_observer
                        and body['unit_prestate'][name]['ActiveState']=='active')):
                    continue
                verify_invariants()
                outcome = {'unit':name,'stop_returned':False,'active_state':'UNKNOWN'}
                try:
                    io.unit('stop',name)
                    outcome['stop_returned'] = True
                except BaseException:
                    contained = False
                unit_outcomes.append(outcome)
            for outcome in unit_outcomes:
                try:
                    state = io.unit_state(outcome['unit'])['ActiveState']
                    outcome['active_state'] = state if state in {
                        'active','inactive','failed','activating','deactivating','reloading'} else 'UNKNOWN'
                    if outcome['active_state'] not in {'inactive','failed'}:
                        contained = False
                except BaseException:
                    contained = False
            verify_invariants()
            if io.read(lkg['target'])!=lkg:raise TransactionError('PUBLIC_RECOVERY_LKG_CHANGED')
            failure_record['mutating_units_contained'] = contained
            failure_record['unit_outcomes'] = unit_outcomes
            failure_record['vitals_successor_selected'] = observer_safe
            failure_record['vitals_existing_observer_preservation_attempted'] = retained_observer
            if retained_observer:
                failure_record['vitals_existing_observer_generation'] = strict_json(
                    base64.b64decode(current['content_b64']))['generation']
            failure_record['install_observation_written'] = observation_written
            failure_record['vitals_endpoint_verification'] = 'INDEPENDENT_READBACK_REQUIRED'
            failure_record['vitals_units_active'] = False
            if observer_safe:
                # Same selected complete generation, never the target (which
                # would pull in the failed coordinator) or another domain.
                cutover_safe = vitals_cutover_complete
                if not cutover_safe:
                    cutover_safe = True
                    # A partial cutover cannot start either successor process
                    # until BOTH old observer processes have stopped.
                    for name in reversed(VITALS_UNITS):
                        verify_invariants()
                        try:
                            io.unit('stop',name)
                            if io.unit_state(name)['ActiveState'] not in {'inactive','failed'}:
                                cutover_safe = False
                        except (OSError, TransactionError):
                            cutover_safe = False
                if cutover_safe:
                    for name in VITALS_UNITS:
                        verify_invariants()
                        if io.selected_generation()!=selector:
                            raise TransactionError('PUBLIC_SELECTOR_READBACK_DENIED')
                        try:
                            if io.unit_state(name)['ActiveState']!='active':
                                io.unit('start',name)
                            if io.unit_state(name)['ActiveState']!='active':
                                break
                        except (OSError, TransactionError):
                            break  # Do not start edge without its presentation.
                try:
                    failure_record['vitals_units_active'] = cutover_safe and all(
                        io.unit_state(name)['ActiveState']=='active' for name in VITALS_UNITS)
                except (OSError, TransactionError):
                    pass
            advance('FAILED_INSTALL_RETAINED' if contained else 'FAILED_INSTALL_CONTAINMENT_UNPROVEN')
        except BaseException:
            raise TransactionError('PUBLIC_INSTALL_FAILED_EVIDENCE_UNPROVEN') from failure
        raise TransactionError('PUBLIC_INSTALL_FAILED_GENERATION_RETAINED' if contained
                               else 'PUBLIC_INSTALL_FAILED_CONTAINMENT_UNPROVEN') from failure
