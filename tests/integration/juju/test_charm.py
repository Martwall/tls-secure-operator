#!/usr/bin/env python3
# Copyright 2023 Martwall
# See LICENSE file for licensing details.

import asyncio
import logging
from pathlib import Path

import pytest
import yaml
from pytest_operator.plugin import OpsTest
from juju.application import Application
from juju.unit import Unit

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./metadata.yaml").read_text())
APP_NAME = METADATA["name"]
PEBBLE_DEV_SERVER_URL = "https://pebble-dev.lxd:14000/dir"


@pytest.mark.abort_on_fail
async def test_smoke(ops_test: OpsTest):
    """Build the charm-under-test and deploy it together with related charms.

    Assert on the unit status before any relations/configurations take place.
    """
    # Build and deploy dev requirer charm
    requirer_charm = await ops_test.build_charm("./tests/integration/juju/dev_requirer_charm")
    requirer_app: Application = await ops_test.model.deploy(requirer_charm, num_units=1)
    await ops_test.model.block_until(lambda: requirer_app.status in ("active", "error"), timeout=180)
    if requirer_app.status == "error":
        logger.error("Received error status sleeping 300 seconds")
        await asyncio.sleep(300)
    assert requirer_app.status == "active"

    # Build and deploy charm from local source folder
    charm = await ops_test.build_charm(".")
    app: Application = await ops_test.model.deploy(charm, num_units=1)
    
    # Deploy the charm and wait for active/idle status
    await ops_test.model.block_until(lambda: app.status in ("active", "error"), timeout=360)
    # Allow for manual inspection if error
    if app.status == "error":
        logger.error("Received error status sleeping 300 seconds")
        await asyncio.sleep(300)
    assert app.status == "active"
    # Make sure there is at least one unit:
    await ops_test.model.block_until(lambda: len(app.units) > 0, timeout=60)
    unit: Unit = app.units[0]
    
    # Check the config. Since no email is configured even though use-email is true. It should be in a blocked status
    await ops_test.model.block_until(lambda: unit.workload_status in ("blocked"), timeout=60)
    # Update the config

