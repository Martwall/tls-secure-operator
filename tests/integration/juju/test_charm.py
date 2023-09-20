#!/usr/bin/env python3
# Copyright 2023 Martwall
# See LICENSE file for licensing details.

import logging
from pathlib import Path

import pytest
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from juju.action import Action
from juju.application import Application
from juju.machine import Machine
from juju.unit import Unit
from pylxd import Client
from pytest_operator.plugin import OpsTest

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


def create_csr(common_name: str):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(
        x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            ]
        )
    )

    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )
    builder = builder.add_extension(
        x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False
    )
    request = builder.sign(private_key, hashes.SHA256())
    return request.public_bytes(serialization.Encoding.PEM)


@pytest.mark.abort_on_fail
async def test_smoke(ops_test: OpsTest):
    """Build the charm-under-test and deploy it together with related charms.

    Assert on the unit status before any relations/configurations take place.
    """
    # Add a machine before so that certificates can be transferred to it
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

    assert requirer_app.status == "active"

    #### Build and deploy subordinate acmesh-operator from local source folder ####
    charm = await ops_test.build_charm(".")
    acmesh_config = {"email": "tester@testingtests.com", "server": PEBBLE_DEV_SERVER_URL}
    app: Application = await ops_test.model.deploy(
        charm, num_units=0, application_name=ACMESH_APP_NAME, config=acmesh_config
    )
    # Relate the two applications
    # The requirer app will ask for a certificate
    await ops_test.model.add_relation(ACMESH_APP_NAME, REQUIRER_APP_NAME)
    await ops_test.model.wait_for_idle(apps=[ACMESH_APP_NAME, REQUIRER_APP_NAME])

    # TODO: Checkout the relation data

    # Test running the certificate actions
    fqdn = (
        lxd_instance_name + ".lxd"
    )  # Should be the address to the machine where acmesh-operator is running
    csr = create_csr(fqdn).decode().strip()
    u: Unit = app.units[0]
    for action_name in ["create-certificate", "renew-certificate"]:
        action: Action = await u.run_action(action_name, csr=csr)
        await action.wait()
        assert "certificate" in action.results
        assert action.results["certificate"] != ""

    action: Action = await u.run_action("revoke-certificate", domain=fqdn)
    await action.wait()
    assert "result" in action.results
    assert action.results["result"] != ""

    assert app.status == "active"
    assert requirer_app.status == "active"
