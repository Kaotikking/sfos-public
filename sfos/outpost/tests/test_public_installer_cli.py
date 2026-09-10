import io
import json
import socket
import urllib.error

import pytest

from install.public_installer_cli import MAX_ARCHIVE_BYTES, TransactionError, fetch_exact


class Response:
    def __init__(self,data,url="https://github.com/Kaotikking/sfos-public/archive/"+("a"*40)+".tar.gz",length=None):
        self.data=data; self.url=url; self.headers={"Content-Length":str(len(data) if length is None else length)}
    def __enter__(self): return self
    def __exit__(self,*args): return False
    def geturl(self): return self.url
    def read(self,size): return self.data[:size]


def install_opener(monkeypatch,value):
    class Opener:
        def open(self,*args,**kwargs):
            if isinstance(value,Exception): raise value
            return value
    monkeypatch.setattr("urllib.request.build_opener",lambda *args:Opener())


def test_fetch_exact_binds_length_and_final_url(monkeypatch):
    response=Response(b"archive"); install_opener(monkeypatch,response)
    assert fetch_exact(response.url)==(b"archive",response.url)


@pytest.mark.parametrize("response,code",[
    (Response(b"short",length=10),"PUBLIC_ARCHIVE_TRUNCATED"),
    (Response(b"x",length=MAX_ARCHIVE_BYTES+1),"PUBLIC_ARCHIVE_SIZE_DENIED"),
])
def test_fetch_exact_denies_truncation_and_oversize(monkeypatch,response,code):
    install_opener(monkeypatch,response)
    with pytest.raises(TransactionError,match=code): fetch_exact(response.url)


@pytest.mark.parametrize("failure",[urllib.error.URLError("secret host detail"),socket.timeout("secret timeout detail")])
def test_fetch_errors_are_sanitized(monkeypatch,failure):
    install_opener(monkeypatch,failure)
    with pytest.raises(TransactionError) as caught: fetch_exact("https://github.com/Kaotikking/sfos-public/archive/"+("a"*40)+".tar.gz")
    assert "secret" not in str(caught.value)


def test_cli_source_contains_no_credential_output():
    from pathlib import Path
    source=(Path(__file__).parents[1]/"install/public_installer_cli.py").read_text()
    assert "Authorization" not in source and "print(plan" not in source and "print(authority" not in source


def test_public_shell_entrypoints_use_only_the_cli():
    from pathlib import Path
    root=Path(__file__).parents[1]/"install"
    update=(root/"public-update.sh").read_text(); rollback=(root/"public-rollback.sh").read_text()
    assert "public_installer_cli.py install-update" in update
    assert '"$#" -eq 1' in update
    assert "--authority" not in update and "--launcher" not in update
    assert "public_installer_cli.py rollback" in rollback
    assert "bootstrap" not in update+rollback


def test_cli_pins_existing_authority_and_launcher_without_override_flags():
    from pathlib import Path
    source=(Path(__file__).parents[1]/"install/public_installer_cli.py").read_text()
    assert 'CANONICAL_AUTHORITY=Path("/usr/share/serein/outpost/cognition-verification.pem")' in source
    assert 'add_argument("--authority"' not in source
    assert 'add_argument("--launcher"' not in source


def test_public_generation_cannot_ship_key_generation_or_broaden_release_contract():
    from pathlib import Path
    root=Path(__file__).parents[1]/"install"
    upgrade=(root/"upgrade_transaction.py").read_text()
    public=(root/"public_generation_transaction.py").read_text()
    assert "Ed25519PrivateKey.generate()" not in upgrade
    assert "UPGRADE_IMMUTABLE_KEY_GENERATION_DENIED" in upgrade
    assert "PUBLIC_RELEASE_UNIT_DENOMINATOR_DENIED" in public
    assert "PUBLIC_RELEASE_GENERATED_DENOMINATOR_DENIED" in public
    assert "PUBLIC_RELEASE_IMMUTABLE_DENOMINATOR_DENIED" in public
