# SPDX-License-Identifier: Apache-2.0
import re

import pytest

from takconsole.core import validate


def test_tak_password_rules():
    assert validate.tak_password_problems("Corta1!") != []
    assert validate.tak_password_problems("sinmayusculas123!x") == ["una mayúscula"]
    assert validate.tak_password_problems("Valida-Clave-2026") == []
    assert "sin espacios ni caracteres no ASCII" in validate.tak_password_problems("Con Espacio-2026x")


def test_random_tak_password_meets_rules():
    for _ in range(50):
        assert validate.tak_password_problems(validate.random_tak_password()) == []


@pytest.mark.parametrize("value,ok", [
    ("ORG-ROOT-CA", True), ("ORG_ROOT", False), ("abc", False), ("ORG ROOT", False),
])
def test_ca_name(value, ok):
    assert bool(re.fullmatch(validate.CA_NAME, value)) is ok


@pytest.mark.parametrize("value,ok", [
    ("Vina del Mar", True), ("Viña del Mar", False), ("Region/V", False), ("A=B", False),
])
def test_cert_field_is_printable_ascii(value, ok):
    assert bool(re.fullmatch(validate.CERT_FIELD, value)) is ok


@pytest.mark.parametrize("value,ok", [
    ("atakatak", True), ("abc", False), ("con espacio", False), ("a$b123", False),
    ("a'b123", False), ("p@ss:w0rd-1", True),
])
def test_cert_pass(value, ok):
    assert bool(re.fullmatch(validate.CERT_PASS, value)) is ok


def test_form_collects_errors():
    f = validate.Form({"n": "x", "num": "9999", "flag": "on"})
    f.text("n", r"[a-z]{3,}", "mal")
    f.integer("num", 1, 10, 5)
    assert f.boolean("flag") is True
    assert set(f.errors) == {"n", "num"}
