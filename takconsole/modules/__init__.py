# SPDX-License-Identifier: Apache-2.0
"""Registro de módulos."""
from .mediamtx import MediaMTX
from .mumble import Mumble
from .takserver import TakServer
from .zerotier import ZeroTier

_ALL = [ZeroTier(), TakServer(), MediaMTX(), Mumble()]
MODULES = {m.key: m for m in sorted(_ALL, key=lambda m: m.order)}


def get(key):
    return MODULES.get(key)
