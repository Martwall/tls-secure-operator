#!/usr/bin/env python3
# Copyright 2023 Martwall
# See LICENSE file for licensing details.

import asyncio
import datetime
import logging
import os
from pathlib import Path

import pytest
import pytest_asyncio
import yaml
import ops
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from juju.action import Action
from juju.application import Application
from juju.machine import Machine
from juju.model import Model
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


@pytest_asyncio.fixture(scope="module")
async def build_charms(ops_test: OpsTest):
    requirer_charm = await build_the_dev_requirer(ops_test)
    acmesh_charm = await ops_test.build_charm(".")

    return {
        "acmesh_charm": acmesh_charm,
        "requirer_charm": requirer_charm,
    }


async def build_the_dev_requirer(ops_test: OpsTest) -> None:
    """Build the dev requirer charm if it does not already exist.

    This means that if changes are made to the dev requirer the charm executable should be removed.
    """
    if os.path.exists("./dev-requirer_ubuntu-22.04-amd64.charm"):
        logger.info(
            "Skipping building of dev-requirer charm because of existing charm in workspace folder. Delete to have it rebuilt."
        )
        return "./dev-requirer_ubuntu-22.04-amd64.charm"
    return await ops_test.build_charm("./tests/integration/juju/dev_requirer_charm")


async def deploy_dev_requirer(charm: Path, model: Model) -> Application:
    """Deploy the dev requirer and wait until it is active."""
    requirer_app: Application = await model.deploy(
        charm, num_units=1, application_name=REQUIRER_APP_NAME
    )
    await model.block_until(lambda: requirer_app.status in ("active", "error"), timeout=180)

    assert requirer_app.status == "active"
    return requirer_app

async def add_machine_for_tls_secure(model: Model) -> Machine:
    """This is needed for the acme.sh curl invocation to trust the self-signed certificates
    of the pebble dev server"""
    # Add a machine before so that certificates can be transferred to it
    machine: Machine = await model.add_machine()
    await model.block_until(lambda: machine.hostname is not None, timeout=160)
    lxd_instance_name = machine.hostname
    logger.info(lxd_instance_name)
    lxd_tasks(lxd_instance_name)

    return machine

async def deploy_tls_secure(model: Model, charm_path: Path) -> dict:
    """Deploy the tls secure application."""
    machine = await add_machine_for_tls_secure(model)
    _config = {"email": "tester@testingtests.com", "server": PEBBLE_DEV_SERVER_URL, "debug": True}
    app: Application = await model.deploy(
        charm_path,
        num_units=1,
        application_name=ACMESH_APP_NAME,
        config=_config,
        to=machine.entity_id,
    )
    return {
        "app": app,
        "machine": machine
        }


async def transfer_haproxy_fqdn_to_dev_requirer(model: Model) -> None:
    """Transfer the haproxy charm fqdn to the dev requirer so that the fqdn is used as the domain name in csr generation.

    This has to be done before the dev_requirer joins the signed-certificates relation as it will otherwise
    use it own fqdn in the csr and the pebble-dev server will send the acme challenge there instead.
    """
    application_keys = model.applications.keys()
    if "haproxy" in application_keys and "dev-requirer" in application_keys:
        haproxy_app: Application = model.applications["haproxy"]
        requirer_app: Application = model.applications["dev-requirer"]
        haproxy_unit_machine_id: str = haproxy_app.units[0].machine_id
        requirer_unit_machine_id: str = requirer_app.units[0].machine_id
        haproxy_machine: Machine = model.machines[haproxy_unit_machine_id]
        requirer_machine: Machine = model.machines[requirer_unit_machine_id]
        lxd_client = Client()
        haproxy_fqdn = haproxy_machine.hostname + ".lxd"
        requirer_lxd_instance = lxd_client.instances.get(requirer_machine.hostname)
        requirer_lxd_instance.files.put("/root/haproxy_juju_fqdn", bytes(haproxy_fqdn, "utf-8"))
    else:
        logger.info(
            f"Could not transfer haproxy charm fqdn to dev-requirer because the charms did not exist. Applications {application_keys}]"
        )
        return


@pytest_asyncio.fixture(scope="function")
async def deploy_dev_requirer_and_tls_secure(ops_test: OpsTest, build_charms: dict) -> dict:
    """Deploy the dev requirer an the tls secure application with default config.

    And cleaning up after every test function.
    """
    tls_secure_deployment = await deploy_tls_secure(
        ops_test.model, build_charms["acmesh_charm"]
    )
    tls_secure_app: Application = tls_secure_deployment["app"]
    tls_secure_machine: Machine = tls_secure_deployment["machine"]
    requirer_app = await deploy_dev_requirer(build_charms["requirer_charm"], ops_test.model)

    assert requirer_app.status == "active"
    assert tls_secure_app.status == "active"

    yield {
        "requirer_app": requirer_app,
        "tls_secure_app": tls_secure_app,
        "tls_secure_machine": tls_secure_machine ,
    }

    await ops_test.model.remove_application(requirer_app.entity_id, block_until_done=True)
    await ops_test.model.remove_application(tls_secure_app.entity_id, block_until_done=True)

@pytest_asyncio.fixture(scope="function")
async def deploy_haproxy(ops_test: OpsTest) -> Application:
    haproxy_config = {"services": "", "source": "ppa:vbernat/haproxy-2.4"}
    haproxy_app: Application = await ops_test.model.deploy(
        "haproxy", config=haproxy_config, num_units=1, series="jammy"
    )

    await ops_test.model.wait_for_idle()

    assert haproxy_app.status == "active"

    yield haproxy_app

    await ops_test.model.remove_application(haproxy_app.entity_id, block_until_done=True)

@pytest.mark.skip
@pytest.mark.abort_on_fail
@pytest.mark.asyncio
async def test_signed_certificate_relation_and_certificate_generation(
    ops_test: OpsTest, deploy_dev_requirer_and_tls_secure: dict
):
    """Build the charm-under-test and deploy it together with related charms.

    Assert on the unit status before any relations/configurations take place.
    """
    requirer_app: Application = deploy_dev_requirer_and_tls_secure["requirer_app"]

    app: Application = deploy_dev_requirer_and_tls_secure["tls_secure_app"]
    tls_secure_machine: Machine = deploy_dev_requirer_and_tls_secure["tls_secure_machine"]

    # Relate the two applications
    # The requirer app will ask for a certificate
    await ops_test.model.add_relation(app.entity_id, requirer_app.entity_id)
    await ops_test.model.wait_for_idle(apps=[ACMESH_APP_NAME, REQUIRER_APP_NAME])

    # TODO: Checkout the relation data

    # Test running the certificate actions
    fqdn = (
        tls_secure_machine.hostname + ".lxd"
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

@pytest.mark.skip
@pytest.mark.abort_on_fail
@pytest.mark.asyncio
async def test_connection_with_haproxy(
    ops_test: OpsTest, deploy_dev_requirer_and_tls_secure: dict, deploy_haproxy: Application
) -> Application:
    """Test connection to Haproxy."""
    requirer_app: Application = deploy_dev_requirer_and_tls_secure["requirer_app"]
    tls_secure_app: Application = deploy_dev_requirer_and_tls_secure["tls_secure_app"]
    haproxy_app = deploy_haproxy

    await transfer_haproxy_fqdn_to_dev_requirer(ops_test.model)

    # This will (by default) add an entry in the haproxy.cfg to proxy all acme requests to
    # the tls_secure app.
    await ops_test.model.add_relation(tls_secure_app.entity_id, haproxy_app.entity_id)
    await ops_test.model.wait_for_idle(apps=[tls_secure_app.entity_id, haproxy_app.entity_id])

    # The dev requirer will ask the tls-secure charm for a certificate for the domain of
    # the machine where haproxy is running.
    await ops_test.model.add_relation(tls_secure_app.entity_id, requirer_app.entity_id)
    await ops_test.model.wait_for_idle(apps=[tls_secure_app.entity_id, requirer_app.entity_id])

    assert tls_secure_app.status == "active"
    assert haproxy_app.status == "active"
    assert requirer_app.status == "active"

@pytest.mark.abort_on_fail
@pytest.mark.asyncio
async def test_connection_with_haproxy_when_no_relation_from_start(
    ops_test: OpsTest, deploy_dev_requirer_and_tls_secure: dict, deploy_haproxy: Application
) -> Application:
    """Test that if a proxy service is configured the charm waits for that relation
    to be established before attempting to issue a certificate"""
    requirer_app: Application = deploy_dev_requirer_and_tls_secure["requirer_app"]
    tls_secure_app: Application = deploy_dev_requirer_and_tls_secure["tls_secure_app"]
    haproxy_app = deploy_haproxy
    await transfer_haproxy_fqdn_to_dev_requirer(ops_test.model)

    # By default the haproxy service is configured so adding this relation would mean that
    # the certificate creation event should be defered and the charm should be in a waiting
    # status.
    await ops_test.model.add_relation(tls_secure_app.entity_id, requirer_app.entity_id)
    await ops_test.model.wait_for_idle(apps=[tls_secure_app.entity_id, requirer_app.entity_id])
    # assert tls_secure_app.status == "waiting"
    async with ops_test.fast_forward(fast_interval="30s"):
        # When the relation is established the certificate should be issued
        await ops_test.model.add_relation(tls_secure_app.entity_id, haproxy_app.entity_id)
        await ops_test.model.wait_for_idle(apps=[tls_secure_app.entity_id, haproxy_app.entity_id])
    #TODO: Verify that certificates have been created
    assert tls_secure_app.status == "active"
    assert haproxy_app.status == "active"
    assert requirer_app.status == "active"


@pytest_asyncio.fixture(scope="module")
async def test_fixture() -> str:
    logger.info(f"Fixture time: {datetime.datetime.now()}")
    await asyncio.sleep(5)
    return "hello"

@pytest.mark.skip
@pytest.mark.asyncio
async def test_async_fixture(ops_test: OpsTest, test_fixture: str):
    """Some other test."""
    logger.info(f"test_async_fixture: {datetime.datetime.now()}")
    assert test_fixture == "hello"


@pytest.mark.skip
@pytest.mark.asyncio
async def test_async_fixture_2(ops_test: OpsTest, test_fixture: str):
    """Some other test."""
    logger.info(f"test_async_fixture_2: {datetime.datetime.now()}")
    assert test_fixture == "hello"
