"""Azure Blob connector tests.

* Fake-based tests (always run): a faithful in-memory stand-in for ``ContainerClient`` covering the
  surface the connector uses (``list_blobs(name_starts_with, include)``, ``download_blob(name).readall()``),
  including content_md5 and versioning shapes that Azurite does not reliably emulate.
* Azurite tests (real Blob REST API in docker): run when Azurite listens on 127.0.0.1:10000. The fixture
  tries to start ``mcr.microsoft.com/azure-storage/azurite`` itself when docker is available; otherwise
  they are skipped.
"""

import hashlib
import json
import shutil
import socket
import subprocess
import time
import uuid
from types import SimpleNamespace

import pytest
from ales_connectors import AzureBlobConnector
from connectors_fixtures import reasons, revocations

# Public, documented Azurite development-storage credentials (not a secret).
AZURITE_CONN = (
    "DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;"
    "AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;"
    "BlobEndpoint=http://127.0.0.1:10000/devstoreaccount1;"
)


class FakeContainer:
    def __init__(self):
        self.blobs: dict[str, dict] = {}  # name -> {data, md5, version}
        self.history: list[dict] = []
        self._n = 0

    def upload(self, name, data: bytes, md5=True, version=None):
        self._n += 1
        rec = {
            "data": data,
            "etag": f'"0x{self._n:016X}"',
            "md5": hashlib.md5(data).digest() if md5 else None,
        }
        rec["version"] = f"2024-01-01T00:00:{self._n:02d}.0000000Z" if version else None
        if name in self.blobs and version:
            self.history.append({"name": name, **self.blobs[name]})
        self.blobs[name] = rec

    def delete(self, name):
        del self.blobs[name]

    @staticmethod
    def _props(name, r, current):
        return SimpleNamespace(
            name=name,
            etag=r["etag"],
            size=len(r["data"]),
            version_id=r["version"],
            is_current_version=current if r["version"] else None,
            content_settings=SimpleNamespace(content_md5=bytearray(r["md5"]) if r["md5"] else None),
        )

    def list_blobs(self, name_starts_with=None, include=None):
        out = [
            self._props(n, r, True)
            for n, r in sorted(self.blobs.items())
            if n.startswith(name_starts_with or "")
        ]
        if include and "versions" in include:
            out += [
                self._props(h["name"], h, False)
                for h in self.history
                if h["name"].startswith(name_starts_with or "")
            ]
        return iter(out)

    def download_blob(self, name):
        return SimpleNamespace(readall=lambda: self.blobs[name]["data"])


def _acl(cc, name, **acl):
    cc.upload(name + ".acl.json", json.dumps(acl).encode())


def _conn(client, cc, **kw):
    return AzureBlobConnector(client, "t1", "ctr", container_client=cc, **kw)


def test_fake_scan_acl_prefix_md5_and_etag_modes(client, server):
    cc = FakeContainer()
    cc.upload("docs/a.txt", b"alpha", md5=True)
    cc.upload("docs/b.txt", b"beta", md5=False)
    _acl(cc, "docs/b.txt", classification="confidential", principal_scope=["alice"])
    cc.upload("other/c.txt", b"nope")
    c = _conn(client, cc, prefix="docs/")
    by = {e["object_id"]: e for e in c.scan()}
    assert set(by) == {"docs/a.txt", "docs/b.txt"}
    assert by["docs/b.txt"]["classification"] == "confidential" and by["docs/b.txt"]["principal_scope"] == [
        "alice"
    ]
    assert c.state["docs/a.txt"]["digest_mode"] == "md5" and c.state["docs/b.txt"]["digest_mode"] == "etag"
    assert by["docs/a.txt"]["source_system"] == "azure_blob"
    assert c.scan() == [] and c.watch_once() == []


def test_fake_overwrite_delete_acl(client, server):
    cc = FakeContainer()
    cc.upload("a", b"v1")
    _acl(cc, "a", classification="internal")
    c = _conn(client, cc)
    c.scan()
    cc.upload("a", b"v2")
    assert reasons(c.watch_once()) == ["version_superseded"]
    _acl(cc, "a", classification="restricted")
    assert reasons(c.watch_once()) == ["acl_changed"]
    _acl(cc, "a", classification="internal")
    assert c.watch_once() == []  # widening is silent
    cc.delete("a")
    assert reasons(c.watch_once()) == ["deleted"]
    assert len(revocations(server)) == 3


def test_fake_versioned_listing_ignores_noncurrent_versions(client, server):
    cc = FakeContainer()
    cc.upload("a", b"v1", version=True)
    c = _conn(client, cc, versioned=True)
    c.scan()
    assert "|" in c.state["a"]["hint"]
    cc.upload("a", b"v2", version=True)  # old version now in history (non-current)
    assert reasons(c.watch_once()) == ["version_superseded"]
    assert c.watch_once() == []  # non-current entries never confuse the diff


def test_credentials_never_leak(client):
    conn = AzureBlobConnector(
        client, "t1", "ctr", container_client=FakeContainer(), connection_string="AccountKey=SECRET123"
    )
    assert "SECRET123" not in repr(conn) and "SECRET123" not in json.dumps(conn.health().as_dict())
    with pytest.raises(ValueError):
        AzureBlobConnector(client, "t1", "ctr")


def test_real_sdk_constructors_build_clients(client):
    c = AzureBlobConnector(client, "t1", "ctr", connection_string=AZURITE_CONN)
    assert "AccountKey" not in repr(c)
    c2 = AzureBlobConnector(
        client, "t1", "ctr", account_url="https://x.blob.core.windows.net", credential="k"
    )
    assert c2.container == "ctr"


def _up(port=10000):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            return True
    except OSError:
        return False


@pytest.fixture(scope="module")
def azurite():
    if not _up():
        if not shutil.which("docker"):
            pytest.skip("no docker and no azurite on 127.0.0.1:10000")
        r = subprocess.run(
            [
                "docker",
                "run",
                "-d",
                "--rm",
                "--name",
                "ales-test-azurite-auto",
                "-p",
                "10000:10000",
                "mcr.microsoft.com/azure-storage/azurite",
                "azurite-blob",
                "--blobHost",
                "0.0.0.0",
                "--skipApiVersionCheck",
            ],
            capture_output=True,
            check=False,
        )
        if r.returncode != 0:
            pytest.skip("could not start azurite container")
        for _ in range(30):
            if _up():
                time.sleep(1)
                break
            time.sleep(1)
        else:
            pytest.skip("azurite did not start")
    return True


def test_azurite_end_to_end(client, server, azurite):
    from azure.storage.blob import BlobServiceClient

    svc = BlobServiceClient.from_connection_string(AZURITE_CONN)
    name = "ales" + uuid.uuid4().hex[:10]
    cc = svc.create_container(name)
    try:
        cc.upload_blob("docs/a.txt", b"alpha")
        cc.upload_blob("docs/b.txt", b"beta")
        cc.upload_blob(
            "docs/b.txt.acl.json",
            json.dumps({"classification": "confidential", "principal_scope": ["alice"]}),
        )
        c = AzureBlobConnector(client, "t1", name, connection_string=AZURITE_CONN, prefix="docs/")
        by = {e["object_id"]: e for e in c.scan()}
        assert set(by) == {"docs/a.txt", "docs/b.txt"}
        assert by["docs/b.txt"]["classification"] == "confidential"
        assert c.watch_once() == []
        cc.upload_blob("docs/a.txt", b"alpha-v2", overwrite=True)
        assert reasons(c.watch_once()) == ["version_superseded"]
        cc.upload_blob("docs/b.txt.acl.json", json.dumps({"classification": "restricted"}), overwrite=True)
        assert reasons(c.watch_once()) == ["acl_changed"]
        cc.delete_blob("docs/a.txt")
        assert reasons(c.watch_once()) == ["deleted"]
        assert c.watch_once() == []
    finally:
        svc.delete_container(name)
