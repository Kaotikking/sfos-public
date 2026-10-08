"""Kernel Interface's existing HAOS HTTP contract, never Outpost Vitals.

ADAPT project-serein ed86a93a986eb9945d0afa9d7161fa4276d96f2a,
sfos/stage1/https_adapter/serein_https_gateway_adapter.py,
blob 4d51212957697bfe4971c63b71212fd224872fb6. Keep its authenticated
voice endpoint and HAOS response; omit Stage2/Android/unsigned inference roads.

The owning TLS service supplies the exact bind, credentials, clock and gateway_call.
gateway_call takes exact normalized bytes and returns the bounded bytes from
the peer/custody-verified private Kernel exchange. There is deliberately no
fallback transport, credential discovery or automatic startup here.
This is part of ONE complete Kernel installation, not a separate domain.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import ssl
import stat
import time
from uuid import UUID

from .authority_contract import canonical
from .conversation_runtime import (_decode, MAX_TEXT_CHARS, MAX_ANSWER_CHARS,
                                   MAX_AGE_SECONDS, MAX_FUTURE_SKEW_SECONDS)
from .kernel import (classify_request, prepare_haos_tool_round, map_haos_tool_round,
                     exchange_private_service)

CONVERSATION_PATH = '/v1/voice/conversation'
MAX_CONVERSATION_REQUEST_BYTES = 128 * 1024
MAX_GATEWAY_RESPONSE_BYTES = 64 * 1024
REQUEST_TIMEOUT_SECONDS = 2.0


def gateway_request(payload, *, root=Path('/')):
    """One bounded call to the source-defined HAOS private Gateway, no retry.

    The TLS owner supplies this callable, not a caller-controlled URL/socket.
    Transport retains custody/peer/frame/deadline checks from the existing
    private exchange. Actual listener/startup/Authority ownership is separate.
    """
    return exchange_private_service('HAOS_GATEWAY', payload, timeout_seconds=30, root=root)


def build_tls_context(credentials_directory):
    """Reuse the donor's existing systemd-delivered certificate pair, read-only.

    This loads no HAOS token, generates/rotates no key, binds no address, and
    changes no unit or directory custody. The owning service supplies the
    exact credentials directory; requests can never select these paths.
    """
    # Reuse the private-API reader's descriptor-anchored Linux path pattern.
    # Never check a pathname and then let OpenSSL reopen that unbound name.
    # The caller still owns proof of systemd delivery; this is not a source
    # of credential authority, nor a substitute for the owning unit contract.
    directory = Path(credentials_directory)
    if not directory.is_absolute() or '..' in directory.parts:
        raise RuntimeError('backend_credentials_directory_invalid')
    handles = []
    parents = []
    files = []

    def identity(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid,
                info.st_gid, info.st_nlink)

    def file_identity(info):
        return (*identity(info), info.st_size, info.st_mtime_ns, info.st_ctime_ns)

    try:
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        handles.append(fd)
        parents.append((None, '/', fd, identity(os.fstat(fd))))
        for part in directory.parts[1:]:
            parent_fd = fd
            fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                         | os.O_CLOEXEC, dir_fd=parent_fd)
            handles.append(fd)
            parents.append((parent_fd, part, fd, identity(os.fstat(fd))))
        for name, private in (('serein-backend-cert.pem', False),
                              ('serein-backend-key.pem', True)):
            opened = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
                             | os.O_NONBLOCK, dir_fd=fd)
            handles.append(opened)
            info = os.fstat(opened)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or not 0 < info.st_size <= 1024 * 1024
                    or info.st_uid not in (0, os.geteuid())
                    or stat.S_IMODE(info.st_mode) & (0o077 if private else 0o022)):
                raise RuntimeError('backend_credential_custody_invalid')
            files.append((name, opened, file_identity(info)))

        def stable():
            for parent_fd, name, opened, before in parents:
                if (identity(os.fstat(opened)) != before or
                        identity(os.stat(name, dir_fd=parent_fd,
                                         follow_symlinks=False)) != before):
                    raise RuntimeError('backend_credentials_directory_changed')
            for name, opened, before in files:
                if (file_identity(os.fstat(opened)) != before or
                        file_identity(os.stat(name, dir_fd=fd,
                                              follow_symlinks=False)) != before):
                    raise RuntimeError('backend_credential_changed')

        stable()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(*(f'/proc/self/fd/{opened}' for _, opened, _ in files),
                                password=lambda: b'')  # No interactive key prompt.
        stable()
        return context
    except OSError as error:
        raise RuntimeError('backend_credentials_unavailable') from error
    finally:
        for opened in reversed(handles):
            os.close(opened)


def load_companion_token(credentials_directory):
    """Read the donor's named systemd credential without changing custody.

    ADAPT project-serein 6f95a0d, adapter blob314059cc. Retain its exact
    32..4096-byte/no-newline contract, using this module's descriptor-bound
    credential road instead of reopening a pathname. No discovery, fallback,
    key creation, runtime grant, listener or service activation occurs here.
    The owning service must independently bind systemd credential delivery.
    """
    directory=Path(credentials_directory)
    if not directory.is_absolute() or '..' in directory.parts:
        raise RuntimeError('companion_credentials_directory_invalid')
    handles=[];parents=[]
    def identity(info):
        return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink)
    def file_identity(info):
        return (*identity(info),info.st_size,info.st_mtime_ns,info.st_ctime_ns)
    try:
        fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        handles.append(fd);parents.append((None,'/',fd,identity(os.fstat(fd))))
        for part in directory.parts[1:]:
            parent=fd
            fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
            handles.append(fd);parents.append((parent,part,fd,identity(os.fstat(fd))))
        name='haos-companion-token'
        opened=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=fd)
        handles.append(opened);info=os.fstat(opened);before=file_identity(info)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink!=1
                or not 32<=info.st_size<=4096 or info.st_uid not in (0,os.geteuid())
                or stat.S_IMODE(info.st_mode)&0o077):
            raise RuntimeError('companion_credential_custody_invalid')
        key=bytearray()
        while len(key)<=4096:
            chunk=os.read(opened,4097-len(key))
            if not chunk:break
            key.extend(chunk)
        if len(key)!=info.st_size or not 32<=len(key)<=4096 or b'\n' in key or b'\r' in key:
            raise RuntimeError('companion_credential_invalid')
        if (file_identity(os.fstat(opened))!=before
                or file_identity(os.stat(name,dir_fd=fd,follow_symlinks=False))!=before):
            raise RuntimeError('companion_credential_changed')
        for parent,name,opened,before in parents:
            if (identity(os.fstat(opened))!=before
                    or identity(os.stat(name,dir_fd=parent,follow_symlinks=False))!=before):
                raise RuntimeError('companion_credentials_directory_changed')
        return bytes(key)
    except OSError:
        raise RuntimeError('companion_credential_unavailable') from None
    finally:
        for opened in reversed(handles):os.close(opened)


def _authenticate(supplied_token, token):
    if (not isinstance(token, bytes) or not 32 <= len(token) <= 4096
            or b'\n' in token or b'\r' in token
            or not isinstance(supplied_token, str)):
        raise ValueError('conversation_token_invalid')
    try:
        supplied = supplied_token.encode('utf-8')
    except UnicodeError as error:
        raise ValueError('conversation_token_invalid') from error
    if len(supplied) > 4096 or not hmac.compare_digest(supplied, token):
        raise ValueError('conversation_token_invalid')


def validate_conversation_request(payload, supplied_token, *, token, now):
    """Keep the donor authentication ahead of parsing or private dispatch."""
    _authenticate(supplied_token, token)
    request = _decode(payload, MAX_CONVERSATION_REQUEST_BYTES)
    if not isinstance(request, dict):
        raise ValueError('conversation_envelope_invalid')
    if request.get('requested_operation') == 'conversation_tools':
        internal = prepare_haos_tool_round(request, now=now)
    else:
        fields = {'request_id', 'conversation_id', 'machine_identity',
                  'requested_operation', 'utterance', 'observed_at'}
        if set(request) != fields or request['requested_operation'] != 'conversation_only':
            raise ValueError('conversation_envelope_invalid')
        UUID(request['request_id'])
        machine = request['machine_identity']
        if not isinstance(machine, str) or not (machine.upper() == 'HAOS'
                or machine.upper().startswith('HAOS_')):
            raise ValueError('conversation_identity_invalid')
        internal = {'schema': 'SereinStage1Request/v1', 'request_id': request['request_id'],
                    'authority': 'local-operator', 'action': 'companion',
                    'conversation': {k: v for k, v in request.items() if k != 'request_id'}}
        if not classify_request(internal, now=now)[0]:
            raise ValueError('conversation_envelope_invalid')
    return request, internal


def _conversation_answer_envelope(request, internal, response, *, now):
    # Reuse the private runtime's exact completion window; transport success
    # does not make malformed or stale evidence a valid public answer.
    if (not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None
            or not isinstance(response, dict) or not isinstance(response.get('timestamp'), str)
            or not isinstance(response.get('reason'), str) or not response['reason']
            or len(response['reason']) > MAX_TEXT_CHARS or '\x00' in response['reason']):
        raise ValueError('conversation_response_metadata_invalid')
    completed = datetime.fromisoformat(response['timestamp'].replace('Z', '+00:00'))
    observed = datetime.fromisoformat(request['observed_at'].replace('Z', '+00:00'))
    if (completed.tzinfo is None or completed.utcoffset() is None
            or (completed-now).total_seconds() > MAX_FUTURE_SKEW_SECONDS
            or (observed-completed).total_seconds() > MAX_FUTURE_SKEW_SECONDS
            or (now-completed).total_seconds() > MAX_AGE_SECONDS):
        raise ValueError('conversation_response_time_invalid')
    if request['requested_operation'] == 'conversation_tools':
        return map_haos_tool_round(request, internal, response, now=now)
    if (not isinstance(response, dict)
            or set(response) != {'schema', 'request_id', 'status', 'reason', 'timestamp', 'result'}
            or response['schema'] != 'SereinStage1Response/v1'
            or response['request_id'] != internal['request_id']
            or response['status'] != 'ANSWERED'):
        raise ValueError('conversation_response_invalid')
    result = response['result']
    if (not isinstance(result, dict)
            or set(result) != {'state', 'response', 'scope', 'conversation_id', 'authority_effect', 'effects'}
            or result['state'] != 'READY' or result['scope'] != 'stage1-bounded-companion'
            or result['conversation_id'] != request['conversation_id']
            or result['authority_effect'] != 'NONE' or result['effects'] != []
            or not isinstance(result['response'], str) or not result['response']
            or result['response'] != ' '.join(result['response'].split())
            or len(result['response']) > MAX_ANSWER_CHARS or '\x00' in result['response']):
        raise ValueError('conversation_response_invalid')
    return {'status': 'ANSWERED', 'request_id': request['request_id'],
            'conversation_id': request['conversation_id'],
            'message': {'role': 'assistant', 'content': result['response']},
            'continue_conversation': False, 'authority_effect': 'NONE', 'effects': []}


class GatewayHealthHandler(BaseHTTPRequestHandler):
    """Retain the donor handler identity; no health/admission route is exposed."""
    server_version = 'SereinGateway/1'
    sys_version = ''
    # One request per connection: extra/pipelined input cannot cause a second effect.
    protocol_version = 'HTTP/1.0'
    # StreamRequestHandler applies this before reading headers/TLS handshake.
    timeout = REQUEST_TIMEOUT_SECONDS

    def _write_json(self, status, value):
        encoded = canonical(value)
        self.close_connection = True
        self.send_response(status)
        for key, value in [('Content-Type', 'application/json'),
                           ('Content-Length', str(len(encoded))),
                           ('Cache-Control', 'no-store'), ('Pragma', 'no-cache'),
                           ('X-Content-Type-Options', 'nosniff'), ('Connection', 'close')]:
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(encoded)

    def do_POST(self):
        if self.path != CONVERSATION_PATH:
            self._write_json(405, {'status': 'DENIED', 'reason': 'method_not_admitted'})
            return
        try:
            tokens = self.headers.get_all('X-Serein-Client-Token', [])
            if len(tokens) != 1:
                raise ValueError('token')
            _authenticate(tokens[0], getattr(self.server, 'companion_key', None))
        except (TypeError, ValueError):
            self._write_json(403, {'status': 'DENIED', 'reason': 'conversation_token_invalid'})
            return
        if (len(self.headers.get_all('Content-Type', [])) != 1
                or self.headers.get_content_type() != 'application/json'):
            self._write_json(415, {'status': 'DENIED', 'reason': 'conversation_content_type_invalid'})
            return
        try:
            lengths = self.headers.get_all('Content-Length', [])
            if (len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdigit()
                    or len(lengths[0]) > 6 or self.headers.get_all('Transfer-Encoding')
                    or self.headers.get_all('Content-Encoding') or self.headers.get_all('Expect')):
                raise ValueError('framing')
            length = int(lengths[0])
            if not 0 < length <= MAX_CONVERSATION_REQUEST_BYTES:
                raise ValueError('size')
            deadline = time.monotonic() + REQUEST_TIMEOUT_SECONDS
            payload = bytearray()
            while len(payload) < length:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ValueError('deadline')
                self.connection.settimeout(remaining)
                part = self.rfile.read1(min(16384, length - len(payload)))
                if not part:
                    raise ValueError('incomplete')
                payload.extend(part)
            current = self.server.clock()
            if not isinstance(current, datetime) or current.tzinfo is None:
                raise ValueError('clock')
            request, internal = validate_conversation_request(bytes(payload), tokens[0],
                token=self.server.companion_key, now=current)
        except (OSError, ValueError, TypeError, AttributeError, RecursionError):
            self._write_json(400, {'status': 'DENIED', 'reason': 'conversation_request_invalid'})
            return
        try:
            # The token is transport authentication, never an Authority grant.
            # The private Kernel still performs signed policy/replay/audit checks.
            response = _decode(self.server.gateway_call(canonical(internal)),
                               MAX_GATEWAY_RESPONSE_BYTES)
            completed = self.server.clock()
            if (not isinstance(completed, datetime) or completed.tzinfo is None
                    or completed.utcoffset() is None or completed < current):
                raise ValueError('conversation_clock_invalid')
            answer = _conversation_answer_envelope(request, internal, response, now=completed)
        except Exception:
            self._write_json(503, {'status': 'UNAVAILABLE', 'reason': 'gateway_unavailable'})
            return
        self._write_json(200, answer)

    def do_GET(self):
        self._write_json(405, {'status': 'DENIED', 'reason': 'method_not_admitted'})

    do_OPTIONS = do_GET
    do_PUT = do_GET
    do_DELETE = do_GET
    do_PATCH = do_GET
    do_HEAD = do_GET

    def log_message(self, format, *args):
        # No request/token/body or private failure detail is logged by this edge.
        return


def serve_private_http(connection, *, credentials_directory, gateway_call, clock):
    """Reuse the admitted HTTP contract in the existing private Kernel owner.

    The owner verifies AF_UNIX peer/custody before calling. No TLS listener,
    route discovery, new wire schema or import into the Outpost edge. Missing
    credentials deny this request; they cannot affect Vitals availability.
    """
    from types import SimpleNamespace
    import io
    if not callable(gateway_call) or not callable(clock):
        raise ValueError('gateway_owner_callbacks_invalid')
    try:
        token = load_companion_token(credentials_directory)
    except (OSError, ValueError, TypeError, RuntimeError):
        token = None
    owner = SimpleNamespace(companion_key=token, gateway_call=gateway_call, clock=clock)
    deadline = time.monotonic() + REQUEST_TIMEOUT_SECONDS
    class DeadlineReader(io.RawIOBase):
        def readable(self):
            return True
        def readinto(self, buffer):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('gateway_request_deadline')
            connection.settimeout(remaining)
            return connection.recv_into(buffer)
    class BoundedConnection:
        def __getattr__(self, name):
            return getattr(connection, name)
        def makefile(self, mode, buffering=-1):
            if mode != 'rb':
                raise ValueError('gateway_stream_mode_denied')
            return io.BufferedReader(DeadlineReader())
    try:
        GatewayHealthHandler(BoundedConnection(), ('private-haos', 0), owner)
    except OSError:
        # Disconnected/expired request is never a retry or a service restart.
        pass


class GatewayHttpsServer(ThreadingHTTPServer):
    """ADAPT the donor's owning HTTP server, within the same Kernel domain.

    No default address or credential discovery. gateway_https_owner composes
    the TLS lifecycle from explicit inputs supplied by the installed owner.
    This class does not claim that that service composition is commissioned.
    """
    gateway_call = staticmethod(gateway_request)
    clock = staticmethod(lambda: datetime.now(timezone.utc))
    # Owner teardown includes accepted requests, not just the listener. The
    # existing request and private-exchange timeouts bound their normal work.
    daemon_threads = False
    block_on_close = True

    def __init__(self, *args, companion_key=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.companion_key = companion_key


@contextmanager
def gateway_https_owner(*, server_address, credentials_directory, gateway_call, clock):
    """Compose the donor TLS owner with explicit, independently admitted inputs.

    ADAPT the historical adapter's serve lifecycle (6f95a0d / blob314059cc).
    No historical port, environment lookup, missing-token fallback, privilege
    change or automatic launch. The caller owns bind/credential/runtime-grant
    authority. This composition neither chooses nor commissions those inputs.
    """
    if not callable(gateway_call) or not callable(clock):
        raise ValueError('gateway_owner_callbacks_invalid')
    # Resolve both credentials before creating any socket. Failed setup cannot
    # leave a plaintext listener or partially configured request owner behind.
    token = load_companion_token(credentials_directory)
    context = build_tls_context(credentials_directory)
    server = GatewayHttpsServer(server_address, GatewayHealthHandler,
                                companion_key=token, bind_and_activate=False)
    try:
        server.gateway_call = gateway_call
        server.clock = clock
        # Defer per-client handshakes into the request thread; an incomplete
        # client handshake must never block the accepting thread or shutdown.
        server.socket = context.wrap_socket(server.socket, server_side=True,
                                          do_handshake_on_connect=False)
        server.server_bind()
        server.server_activate()
        yield server
    finally:
        server.server_close()


def serve(*, server_address, credentials_directory, gateway_call, clock):
    """Run only the explicitly supplied Kernel HTTPS owner; no default bind."""
    with gateway_https_owner(server_address=server_address,
                             credentials_directory=credentials_directory,
                             gateway_call=gateway_call, clock=clock) as server:
        server.serve_forever()
