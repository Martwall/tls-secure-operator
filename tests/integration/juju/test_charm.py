#!/usr/bin/env python3
# Copyright 2023 Martwall
# See LICENSE file for licensing details.

import asyncio
import logging
from pathlib import Path

import pytest
import yaml
from juju.application import Application
from juju.machine import Machine
from juju.relation import Relation, Endpoint
from pylxd import Client
from pytest_operator.plugin import OpsTest

from charms.harness_extensions.v0.relation_data_wrapper import get_relation_data_from_juju


logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./metadata.yaml").read_text())
ACMESH_APP_NAME = METADATA["name"]
REQUIRER_METADATA = yaml.safe_load(
    Path("./tests/integration/juju/dev_requirer_charm/metadata.yaml").read_text()
)
REQUIRER_APP_NAME = REQUIRER_METADATA["name"]
PEBBLE_LXD_INSTANCE_NAME = "pebble-dev"
PEBBLE_DEV_SERVER_URL = f"https://{PEBBLE_LXD_INSTANCE_NAME}.lxd:14000/dir"


def lxd_tasks(other_instance: str):
    """Add pebble ca certificate to the machine via lxd."""
    lxd_client = Client()
    lxd_machine0 = lxd_client.instances.get(other_instance)
    lxd_pebble = lxd_client.instances.get(PEBBLE_LXD_INSTANCE_NAME)
    # Transfer certificate
    ca_certificate_file: bytes = lxd_pebble.files.get("/root/pebble/test/certs/pebble.minica.pem")
    lxd_machine0.files.put("/usr/share/ca-certificates/pebble.minica.pem.crt", ca_certificate_file)
    # Add to trusted
    minica_cert_name = "pebble.minica.pem.crt"
    ca_certificates_conf: bytes = lxd_machine0.files.get("/etc/ca-certificates.conf")
    if minica_cert_name not in ca_certificates_conf.decode():
        ca_certificates_conf_new = ca_certificates_conf.decode() + minica_cert_name + "\n"
        lxd_machine0.files.put(
            "/etc/ca-certificates.conf", ca_certificates_conf_new.encode("utf-8")
        )
    lxd_machine0.execute(["update-ca-certificates"])


@pytest.mark.abort_on_fail
async def test_smoke(ops_test: OpsTest):
    """Build the charm-under-test and deploy it together with related charms.

    Assert on the unit status before any relations/configurations take place.
    """
    # Add a machine before so that certificates can be transfered to it
    await ops_test.model.add_machine()
    await ops_test.model.block_until(lambda: len(ops_test.model.machines) > 0, timeout=60)
    machine_list: list(str) = await ops_test.model.get_machines()
    logger.info(machine_list)
    machine0_id: str = machine_list[0]
    machine0: Machine = ops_test.model.machines[machine0_id]

    logger.info(machine0.agent_status)  # This is State in juju status
    logger.info(
        machine0.status
    )  # This is the Message but as short eg status_message = Running -> status = running
    logger.info(machine0.safe_data)  # all machine data
    await ops_test.model.block_until(lambda: machine0.hostname is not None, timeout=160)
    lxd_instance_name = machine0.hostname
    logger.info(lxd_instance_name)
    lxd_tasks(lxd_instance_name)

    #### Build and deploy dev requirer charm ####
    requirer_charm = await ops_test.build_charm("./tests/integration/juju/dev_requirer_charm")
    requirer_app: Application = await ops_test.model.deploy(
        requirer_charm, num_units=1, application_name=REQUIRER_APP_NAME, to=str(machine0_id)
    )
    await ops_test.model.block_until(
        lambda: requirer_app.status in ("active", "error"), timeout=180
    )
    # Allow for manual inspection if error
    if requirer_app.status == "error":
        logger.error("Received error status sleeping 300 seconds")
        await asyncio.sleep(300)
    assert requirer_app.status == "active"

    #### Build and deploy subordinate acmesh-operator from local source folder ####
    charm = await ops_test.build_charm(".")
    acmesh_config = {"email": "tester@testingtests.com", "server": PEBBLE_DEV_SERVER_URL}
    app: Application = await ops_test.model.deploy(
        charm, num_units=0, application_name=ACMESH_APP_NAME, config=acmesh_config
    )
    # Relate the two applications
    await ops_test.model.add_relation(ACMESH_APP_NAME, REQUIRER_APP_NAME)
    await ops_test.model.wait_for_idle(apps=[ACMESH_APP_NAME, REQUIRER_APP_NAME])
    # Allow for manual inspection if errors
    if app.status == "error" or requirer_app.status == "error":
        logger.error("Received error status sleeping 300 seconds")
        await asyncio.sleep(300)
    logger.info(app.safe_data)
    logger.info(app.data)
    logger.info(ops_test.model.relations)
    logger.info(app.units)
    logger.info(ops_test.model.units)
    relations: list[Relation] = ops_test.model.relations
    relation = relations[0]
    logger.info(relation.data)
    logger.info(relation.safe_data)
    logger.info(relation.endpoints)
    endpoints: list[Endpoint] = relation.endpoints
    for endpoint in endpoints:
        logger.info(endpoint.name)
        logger.info(endpoint.application_name)
        logger.info(endpoint.data)

    relation_data = get_relation_data_from_juju(
        provider_endpoint="acmesh-operator:signedcertificates",
        requirer_endpoint="dev-requirer:signedcertificates",
        include_default_juju_keys=False
        )
    logger.info(relation_data)
    assert app.status == "active"
    assert requirer_app.status == "active"
