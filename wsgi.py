# SPDX-License-Identifier: Apache-2.0
from takconsole import create_app

from takconsole.core import updates

app = create_app()
updates.start_scheduler()   # comprobación diaria de actualizaciones (solo busca)
