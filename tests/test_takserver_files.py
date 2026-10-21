# SPDX-License-Identifier: Apache-2.0
import io
import re
import xml.etree.ElementTree as ET
import zipfile

import pytest

from takconsole.modules import takserver_files as tf

from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"

NS = {"c": "http://bbn.com/marti/xml/config"}


def sample():
    return (FIXTURES / "CoreConfig.sample.xml").read_text()


def test_cert_metadata_sets_all_vars():
    text = (FIXTURES / "cert-metadata.sample.sh").read_text()
    out = tf.patch_cert_metadata(text, {
        "COUNTRY": "CL", "STATE": "Valparaiso", "CITY": "Vina del Mar", "ORGANIZATION": "Org",
        "ORGANIZATIONAL_UNIT": "Com", "CAPASS": "clave.123", "PASS": "clave.123"})
    assert 'COUNTRY="CL"' in out
    assert 'CITY="Vina del Mar"' in out
    assert 'PASS="clave.123"' in out
    assert "${PASS:-$CAPASS}" not in out
    assert "DIR=files" in out


@pytest.mark.parametrize("bad", ['a"b', "a$b", "a`b", "a\\b", "a;b"])
def test_cert_metadata_rejects_shell_chars(bad):
    text = (FIXTURES / "cert-metadata.sample.sh").read_text()
    with pytest.raises(ValueError):
        tf.patch_cert_metadata(text, {"STATE": bad})


def test_coreconfig_security_and_federation():
    out = tf.patch_coreconfig(sample(), cert_pass="s3creta", truststore="certs/files/truststore-INT.jks")
    root = ET.fromstring(out.encode())
    tls = root.find("c:security/c:tls", NS)
    assert tls.get("truststoreFile") == "certs/files/truststore-INT.jks"
    assert tls.get("keystorePass") == "s3creta" and tls.get("truststorePass") == "s3creta"
    fed = root.find("c:federation/c:federation-server/c:tls", NS)
    assert fed.get("keystorePass") == "s3creta"
    assert fed.get("truststoreFile") == "certs/files/fed-truststore.jks"


def test_coreconfig_leaves_comments_untouched():
    out = tf.patch_coreconfig(sample(), cert_pass="s3creta", truststore="certs/files/truststore-INT.jks")
    assert 'keystoreFile="certs/OLD.jks" keystorePass="atakatak"' in out
    comments = re.findall(r"<!--.*?-->", out, re.S)
    assert comments == re.findall(r"<!--.*?-->", sample(), re.S)


def test_coreconfig_enrollment_insert_and_remove():
    enr = {"keystore": "certs/files/INT-signing.jks", "org": "Org", "ou": "Com", "days": 90}
    out = tf.patch_coreconfig(sample(), cert_pass="p4ss.x", truststore="t.jks", enrollment=enr)
    root = ET.fromstring(out.encode())
    cs = root.find("c:certificateSigning", NS)
    assert cs is not None and cs.get("CA") == "TAKServer"
    ca = cs.find("c:TAKServerCAConfig", NS)
    assert ca.get("keystoreFile") == "certs/files/INT-signing.jks"
    assert ca.get("validityDays") == "90"
    names = {e.get("name"): e.get("value") for e in cs.iter("{%s}nameEntry" % NS["c"])}
    assert names == {"O": "Org", "OU": "Com"}
    # idempotente: aplicar dos veces deja un solo bloque
    again = tf.patch_coreconfig(out, cert_pass="p4ss.x", truststore="t.jks", enrollment=enr)
    assert len(ET.fromstring(again.encode()).findall("c:certificateSigning", NS)) == 1
    # quitar
    removed = tf.patch_coreconfig(again, cert_pass="p4ss.x", truststore="t.jks", enrollment=False)
    assert ET.fromstring(removed.encode()).find("c:certificateSigning", NS) is None
    # el bloque de ejemplo comentado sigue ahí
    assert 'keystoreFile="certs/files/x.jks"' in removed


def test_coreconfig_escapes_values():
    out = tf.patch_coreconfig(sample(), cert_pass='a&b"c', truststore="t.jks")
    root = ET.fromstring(out.encode())
    assert root.find("c:security/c:tls", NS).get("keystorePass") == 'a&b"c'


def test_coreconfig_summary():
    s = tf.coreconfig_summary(sample())
    assert [i["port"] for i in s["inputs"]] == ["8089"]
    assert [c["port"] for c in s["connectors"]] == ["8443", "8446"]
    assert s["enrollment"] is False


def test_data_package_atak_and_itak():
    common = dict(user="alfa-01", host="10.147.17.5", port=8089, description="Org",
                  truststore_name="truststore-INT.p12", truststore_bytes=b"T",
                  user_p12_bytes=b"U", cert_pass="p&ss")
    z = zipfile.ZipFile(io.BytesIO(tf.data_package(**common)))
    names = set(z.namelist())
    assert names == {"MANIFEST/manifest.xml", "certs/server.pref",
                     "certs/truststore-INT.p12", "certs/alfa-01.p12"}
    man = ET.fromstring(z.read("MANIFEST/manifest.xml"))
    entries = {c.get("zipEntry") for c in man.iter("Content")}
    assert entries == names - {"MANIFEST/manifest.xml"}
    pref = ET.fromstring(z.read("certs/server.pref"))
    vals = {e.get("key"): e.text for e in pref.iter("entry")}
    assert vals["connectString0"] == "10.147.17.5:8089:ssl"
    assert vals["caLocation0"] == "cert/truststore-INT.p12"
    assert vals["certificateLocation"] == "cert/alfa-01.p12"
    assert vals["clientPassword"] == "p&ss"

    zi = zipfile.ZipFile(io.BytesIO(tf.data_package(kind="itak", **common)))
    assert set(zi.namelist()) == {"config.pref", "truststore-INT.p12", "alfa-01.p12"}
    ipref = {e.get("key"): e.text for e in ET.fromstring(zi.read("config.pref")).iter("entry")}
    assert "caLocation0" not in ipref and ipref["caLocation"] == "cert/truststore-INT.p12"
