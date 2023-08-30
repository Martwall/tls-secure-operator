# Copyright 2023 Martwall
# See LICENSE file for licensing details.

from subprocess import PIPE, check_output
from typing import Any

import yaml


def show_unit(unit_name: str, model_full_name: str) -> Any:
    """Copyright 2023 Canonical Ltd. Apache 2.0 License."""
    result = check_output(
        f"JUJU_MODEL={model_full_name} juju show-unit {unit_name}",
        stderr=PIPE,
        shell=True,
        universal_newlines=True,
    )

    return yaml.safe_load(result)
