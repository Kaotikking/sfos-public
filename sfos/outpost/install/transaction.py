"""Attributed verification and offline first-boot enablement primitives.

No complete installer, rollback, selector permission change or live activation.
"""
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
from pathlib import Path


class TransactionError(RuntimeError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def strict_json(raw):
    def pairs(rows):
        value = {}
        for key, item in rows:
            if key in value:
                raise TransactionError("JSON_DUPLICATE_KEY_DENIED")
            value[key] = item
        return value
    def invalid_constant(_):
        raise TransactionError("JSON_NONFINITE_DENIED")
    def unicode_check(value):
        if isinstance(value, str): value.encode("utf-8", errors="strict")
        elif isinstance(value, dict):
            for key, item in value.items(): unicode_check(key); unicode_check(item)
        elif isinstance(value, list):
            for item in value: unicode_check(item)
    try:
        text = raw.decode("utf-8", errors="strict") if isinstance(raw, bytes) else raw
        value = json.loads(text, object_pairs_hook=pairs, parse_constant=invalid_constant)
        unicode_check(value)
    except (ValueError, UnicodeError, TypeError, RecursionError):
        raise TransactionError("JSON_INVALID_DENIED") from None
    if not isinstance(value, dict):
        raise TransactionError("JSON_OBJECT_REQUIRED")
    return value


def nofollow_ancestors(root, path, allow_missing=True):
    current = root
    if current.is_symlink():
        raise TransactionError("ROOT_SYMLINK_DENIED")
    try:
        parts = path.relative_to(root).parts
    except ValueError as error:
        raise TransactionError("TARGET_PATH_DENIED") from error
    if ".." in parts:
        raise TransactionError("TARGET_PATH_DENIED")
    for part in parts:
        current = current / part
        if current.is_symlink():
            raise TransactionError("PATH_SYMLINK_DENIED")
        if not os.path.lexists(current) and not allow_missing:
            raise TransactionError("PATH_MISSING")


def stage_inactive_generation(staging_parent, generation_id, material):
    """Materialize a new inactive package; never select or install it.

    Adapted from the donor's generation-directory/inventory construction only.
    Existing destinations deny. On failure retain the incomplete attempt as
    evidence; do not repair, resume, remove it or reactivate any predecessor.
    A private native staging parent is required, not an installed selector tree.
    """
    return _write_inactive_generation(staging_parent,generation_id,material,parent_mode=0o700)


def place_inactive_generation(root, release, material, expected_destination):
    """Construct the exact donor destination without selecting or starting it.

    A transaction caller still owns authorization and the lock. This primitive
    never overwrites/resumes an attempt or changes current/LKG or any service.
    """
    from .public_generation_transaction import bind_generation_material, prospective_generation_prestate
    digest=release.get('self_digest')
    material=bind_generation_material(release,material,digest)
    observed=prospective_generation_prestate(root,digest)
    if observed!=expected_destination:
        raise TransactionError('PUBLIC_GENERATION_DESTINATION_CHANGED')
    parent=Path(os.path.abspath(root))/'usr/share/serein/outpost-generations'
    result=_write_inactive_generation(parent,digest.removeprefix('sha256:'),material,
        parent_mode=0o755,expected_parent=(observed['parent']['device'],observed['parent']['inode']))
    return {**result,'result':'PLACED_INACTIVE_BYTES_ONLY','target':observed['target']}


def _write_inactive_generation(staging_parent, generation_id, material, *, parent_mode, expected_parent=None):
    """Shared exact-byte construction; callers fix private/canonical custody."""
    from .public_generation_transaction import generation_inventory
    if not isinstance(generation_id, str) or not re.fullmatch(r"[0-9a-f]{64}", generation_id):
        raise TransactionError("STAGING_GENERATION_ID_DENIED")
    material = dict(material)
    inventory = generation_inventory(material)
    inventory_bytes = canonical(inventory) + b"\n"
    material["generation-inventory.json"] = inventory_bytes
    parent = Path(os.path.abspath(staging_parent))
    if parent == Path("/"):
        raise TransactionError("PRIVATE_STAGING_PARENT_REQUIRED")
    handles, directories = [], {}
    try:
        descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        handles.append((descriptor, None, None))
        for part in parent.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            handles.append((child, descriptor, part))
            descriptor = child
        parent_fd = descriptor
        info = os.fstat(parent_fd)
        if (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (0, 0, parent_mode):
            raise TransactionError("PRIVATE_STAGING_PARENT_REQUIRED")
        if expected_parent is not None and (info.st_dev,info.st_ino)!=expected_parent:
            raise TransactionError('PUBLIC_GENERATION_DESTINATION_CHANGED')
        try:
            os.mkdir(generation_id, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            raise TransactionError("STAGING_COLLISION_NEW_INSTALL_REQUIRED") from None
        root_fd = os.open(generation_id, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        handles.append((root_fd, parent_fd, generation_id))
        os.fchmod(root_fd, 0o700)
        directories["."] = root_fd
        for row in inventory:
            if row["kind"] != "directory":
                continue
            path = Path(row["path"])
            fd = directories[path.parent.as_posix()]
            os.mkdir(path.name, 0o755, dir_fd=fd)
            child = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            directories[row["path"]] = child
            handles.append((child, fd, path.name))
            # Exact package modes apply only to these newly created inactive
            # objects, never the staging parent or installed selectors.
            os.fchmod(child, 0o755)
        for name, data in sorted(material.items()):
            path = Path(name)
            descriptor = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o644, dir_fd=directories[path.parent.as_posix()])
            with os.fdopen(descriptor, "wb") as stream:
                os.fchmod(stream.fileno(), 0o644)
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        for relative, fd in directories.items():
            info = os.fstat(fd)
            expected_mode = 0o700 if relative == "." else 0o755
            if (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (0, 0, expected_mode):
                raise TransactionError("STAGING_CUSTODY_DENIED")
            expected = {Path(name).name for name in material if Path(name).parent.as_posix() == relative}
            expected.update(Path(name).name for name in directories
                            if name != "." and Path(name).parent.as_posix() == relative)
            if set(os.listdir(fd)) != expected:
                raise TransactionError("STAGING_INVENTORY_DENIED")
        for name, data in sorted(material.items()):
            path = Path(name)
            fd = directories[path.parent.as_posix()]
            descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            with os.fdopen(descriptor, "rb") as stream:
                before = os.fstat(stream.fileno())
                if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                        or (before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode)) != (0, 0, 0o644)
                        or before.st_size != len(data) or stream.read(len(data) + 1) != data):
                    raise TransactionError("STAGING_READBACK_DENIED")
                after = os.fstat(stream.fileno())
                named = os.stat(path.name, dir_fd=fd, follow_symlinks=False)
                identity = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_uid,
                                          value.st_gid, value.st_nlink, value.st_size,
                                          value.st_mtime_ns, value.st_ctime_ns)
                if identity(before) != identity(after) or identity(after) != identity(named):
                    raise TransactionError("STAGING_READBACK_DENIED")
        for fd in reversed(list(directories.values())):
            os.fsync(fd)
        # The package's final directory mode must match the actual launcher
        # contract. Its containing staging directory remains private 0700.
        # This is a newly created inactive object, never an installed repair.
        os.fchmod(root_fd,0o755)
        os.fsync(root_fd)
        os.fsync(parent_fd)
        for fd, ancestor_fd, name in handles[1:]:
            opened = os.fstat(fd)
            named = os.stat(name, dir_fd=ancestor_fd, follow_symlinks=False)
            if (opened.st_dev, opened.st_ino, opened.st_mode) != (named.st_dev, named.st_ino, named.st_mode):
                raise TransactionError("STAGING_DIRECTORY_CHANGED")
    except OSError as error:
        raise TransactionError("STAGING_FAILED_NEW_INSTALL_REQUIRED:" + type(error).__name__) from None
    finally:
        for fd, _, _ in reversed(handles):
            os.close(fd)
    return {"result":"STAGED_INACTIVE_BYTES_ONLY", "generation":generation_id,
            "inventory_sha256":sha(inventory_bytes), "inventory_digest":sha(canonical(inventory)),
            "installed":"UNPROVEN", "admission":"NONE", "activation":"NONE"}


def enable_first_host_boot(target_root, expected_unit_sha256, *, staging_parent):
    """Enable only Outpost in an offline root; never start the installer host.

    Adapted from install_sfos_stage1.py::enable_units and the historical Base
    late-install.sh enable-only contract. The complete package entry must call
    this only after its installation checks. This primitive proves file-state
    enablement, not installation, service health, Host verification or admission.
    """
    root = Path(os.path.abspath(target_root))
    if root == Path("/") or not root.is_dir() or root.samefile("/"):
        raise TransactionError("OFFLINE_TARGET_ROOT_REQUIRED")
    nofollow_ancestors(Path(root.anchor), root, allow_missing=False)
    staging_parent = Path(os.path.abspath(staging_parent))
    nofollow_ancestors(Path(staging_parent.anchor), staging_parent, allow_missing=False)
    if (not staging_parent.is_dir() or staging_parent == root
            or root in staging_parent.parents or staging_parent == Path("/")):
        raise TransactionError("OFFLINE_STAGING_PARENT_DENIED")
    if not isinstance(expected_unit_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_unit_sha256):
        raise TransactionError("OFFLINE_UNIT_HASH_REQUIRED")
    units = root / "etc/systemd/system"
    unit = units / "serein-outpost.target"
    nofollow_ancestors(root, unit, allow_missing=False)
    descriptor = os.open(unit, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 65536:
            raise TransactionError("OFFLINE_UNIT_CUSTODY_DENIED")
        data = stream.read(65537)
    if sha(data) != expected_unit_sha256:
        raise TransactionError("OFFLINE_UNIT_HASH_DENIED")
    # Reject expanded enablement (Also/Alias/extra targets). Runtime dependencies
    # are verified by the package, not executed by systemctl --root enable.
    try:
        sections = data.decode("utf-8").split("[Install]")
    except UnicodeError:
        raise TransactionError("OFFLINE_UNIT_INSTALL_POLICY_DENIED") from None
    if len(sections) != 2 or sections[1].strip() != "WantedBy=multi-user.target":
        raise TransactionError("OFFLINE_UNIT_INSTALL_POLICY_DENIED")
    wants = units / "multi-user.target.wants"
    # The complete package prepares this standard target directory beforehand;
    # the final commit here is exactly one no-replace symlink, not mkdir+link.
    nofollow_ancestors(root, wants, allow_missing=False)
    if not wants.is_dir():
        raise TransactionError("OFFLINE_ENABLEMENT_PARENT_REQUIRED")
    link = wants / unit.name
    expected_link = "/etc/systemd/system/serein-outpost.target"
    if os.path.lexists(link):
        raise TransactionError("OFFLINE_ENABLEMENT_COLLISION_NEW_INSTALL_REQUIRED")
    # Use this toolchain's compiled-in paths, not a guessed subset. This read-only
    # verb does not use --root or contact a manager; map each result under root.
    environment = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
    discovery = subprocess.run(["systemd-analyze", "unit-paths"],
                               check=True, capture_output=True, text=True, env=environment)
    paths = discovery.stdout.splitlines()
    if (not paths or len(paths) > 64 or len(paths) != len(set(paths))
            or any(not value.startswith("/") or ".." in Path(value).parts
                   or str(Path(value)) != value for value in paths)
            or "/etc/systemd/system" not in paths):
        raise TransactionError("OFFLINE_UNIT_PATHS_DENIED")
    search = [root / value.lstrip("/") for value in paths]
    for directory in search:
        nofollow_ancestors(root, directory)
        for name in ("serein-outpost.target.d", "serein-.target.d", "target.d"):
            if os.path.lexists(directory / name):
                raise TransactionError("OFFLINE_UNIT_DROPIN_DENIED")
        shadow = directory / unit.name
        if shadow != unit and os.path.lexists(shadow):
            raise TransactionError("OFFLINE_UNIT_SHADOW_DENIED")
        if directory.exists():
            for path in directory.iterdir():
                if path.is_symlink() and Path(os.readlink(path)).name == unit.name:
                    raise TransactionError("OFFLINE_UNIT_ALIAS_DENIED")
    before = _offline_unit_inventory(search, root)
    # Reuse the donor's disposable installer staging pattern. systemctl never
    # receives the real target. Effective overrides were denied above; enable
    # reads only this exact primary unit, not its runtime dependencies.
    with tempfile.TemporaryDirectory(prefix="outpost-enable-", dir=staging_parent) as temporary:
        stage = Path(temporary)
        staged_unit = stage / unit.relative_to(root)
        staged_unit.parent.mkdir(parents=True)
        with staged_unit.open("xb") as stream:
            stream.write(data)
        staged_paths = [stage / value.lstrip("/") for value in paths]
        expected_stage = _offline_unit_inventory(staged_paths, stage)
        expected_stage[str(wants.relative_to(root))] = ("directory",)
        expected_stage[str(link.relative_to(root))] = ("symlink", expected_link)
        result = subprocess.run(["systemctl", "--root", str(stage), "enable", unit.name],
                                check=False, capture_output=True, text=True, env=environment)
        staged_after = _offline_unit_inventory(staged_paths, stage)
        if result.returncode != 0 or staged_after != expected_stage:
            error = TransactionError("OFFLINE_ENABLEMENT_FAILED_NEW_ATOMIC_INSTALL_REQUIRED")
            # The canonical caller must persist this evidence in its failure
            # receipt. Temporary candidate disposal is not target rollback.
            error.evidence = {"unit_sha256": expected_unit_sha256,
                              "returncode": result.returncode,
                              "expected_inventory_sha256": sha(canonical(expected_stage)),
                              "observed_inventory_sha256": sha(canonical(staged_after)),
                              "target_effect": "NONE"}
            raise error
    if _offline_unit_inventory(search, root) != before:
        raise TransactionError("OFFLINE_TARGET_CHANGED_BEFORE_COMMIT")
    # Retain no-follow descriptors for every ancestor; commit relative to the
    # exact opened directory, never to a re-resolved path after a custody check.
    descriptors = []
    try:
        parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append((parent, None, None))
        for part in wants.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            descriptors.append((child, parent, part))
            parent = child
        wants_fd = descriptors[-1][0]
        units_fd = descriptors[-2][0]
        for descriptor, _, _ in descriptors[-4:]:
            info = os.fstat(descriptor)
            if info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
                raise TransactionError("OFFLINE_TARGET_CUSTODY_DENIED")
        def bound_directories():
            for descriptor, parent_fd, name in descriptors[1:]:
                opened = os.fstat(descriptor)
                named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                if (opened.st_dev, opened.st_ino, opened.st_mode) != (named.st_dev, named.st_ino, named.st_mode):
                    raise TransactionError("OFFLINE_TARGET_DIRECTORY_CHANGED")
        bound_directories()
        if _read_offline_unit(units_fd, unit.name) != data:
            raise TransactionError("OFFLINE_UNIT_CHANGED_BEFORE_COMMIT")
        # Atomic no-replace insertion. EEXIST denies; nothing is removed.
        try:
            os.symlink(expected_link, unit.name, dir_fd=wants_fd)
        except FileExistsError:
            raise TransactionError("OFFLINE_ENABLEMENT_COLLISION_NEW_INSTALL_REQUIRED") from None
        info = os.stat(unit.name, dir_fd=wants_fd, follow_symlinks=False)
        if not stat.S_ISLNK(info.st_mode) or os.readlink(unit.name, dir_fd=wants_fd) != expected_link:
            raise TransactionError("OFFLINE_ENABLEMENT_READBACK_DENIED")
        os.fsync(wants_fd)
        bound_directories()
        if _read_offline_unit(units_fd, unit.name) != data:
            raise TransactionError("OFFLINE_ENABLEMENT_READBACK_DENIED")
        expected = dict(before)
        expected[str(link.relative_to(root))] = ("symlink", expected_link)
        if _offline_unit_inventory(search, root) != expected:
            raise TransactionError("OFFLINE_ENABLEMENT_READBACK_DENIED")
    except OSError as error:
        raise TransactionError("OFFLINE_TARGET_COMMIT_DENIED:" + type(error).__name__) from None
    finally:
        for descriptor, _, _ in reversed(descriptors):
            os.close(descriptor)
    return {"state": "OUTPOST_ENABLED_FOR_FIRST_HOST_BOOT", "target_root": str(root),
            "unit": unit.name, "unit_sha256": expected_unit_sha256,
            "enabled_link": str(link.relative_to(root)), "started": False,
            "installed": "UNPROVEN", "host_gate": "UNPROVEN"}


def _read_offline_unit(directory_fd, name):
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != 0
                or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o644 or info.st_size > 65536):
            raise TransactionError("OFFLINE_UNIT_CUSTODY_DENIED")
        return stream.read(65537)


def _offline_unit_inventory(search_paths, root):
    """Bounded enablement-directory evidence; never follow symlinks."""
    rows = {}
    for directory in search_paths:
        if not directory.exists():
            continue
        if not directory.is_dir():
            raise TransactionError("OFFLINE_UNIT_DIRECTORY_DENIED")
        for path in directory.rglob("*"):
            if len(rows) >= 10000:
                raise TransactionError("OFFLINE_UNIT_INVENTORY_LIMIT")
            relative = str(path.relative_to(root))
            if path.is_symlink():
                rows[relative] = ("symlink", os.readlink(path))
            elif path.is_dir():
                rows[relative] = ("directory",)
            else:
                nofollow_ancestors(root, path, allow_missing=False)
                descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(descriptor, "rb") as stream:
                    info = os.fstat(stream.fileno())
                    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 1024 * 1024:
                        raise TransactionError("OFFLINE_UNIT_INVENTORY_CUSTODY_DENIED")
                    data = stream.read(1024 * 1024 + 1)
                    if len(data) != info.st_size:
                        raise TransactionError("OFFLINE_UNIT_INVENTORY_CHANGED")
                rows[relative] = ("file", sha(data))
    return rows
