<!--
Avoid using this README file for information that is maintained or published elsewhere, e.g.:

* metadata.yaml > published on Charmhub
* documentation > published on (or linked to from) Charmhub
* detailed contribution guide > documentation or CONTRIBUTING.md

Use links instead.
-->

# acmesh-operator

Charmhub package name: acmesh

More information: https://charmhub.io/acmesh

A subordinate charm to get signed certificates using acme.sh.
Integrates to a principal requirer charm via the "tls-certificates" interface and relation name "signed-certificates".

## Limitations

ONLY http-01 challenge in standalone mode.

ONLY rsa certificates.

Does not support IP addresses in the certificate signing request (csr) because of how acme.sh handles issuing certificates from an existing csr.

## How to use the acmesh charm

In your charm:

```yaml
requires:
  signed-certificates:
      interface: tls-certificates
      limit: 1
```

Use the charms.tls_certificates_interface.v2.tls_certificates lib to handle the integration in your charm. Checkout the [settings](#settings) and [certificate signing request sections](#certificate-signing-request). Also look at the examples of a requirer charm from the [documentation of the TLS Certificates Interface lib](https://charmhub.io/tls-certificates-interface/libraries/tls_certificates). There is also a [requirer charm](tests/integration/juju/dev_requirer_charm/src/charm.py) used for integration testing to take a look at if inspiration is required but it is purely for development.

On juju command line:

```shell
juju deploy acmesh --config email=<email_for_cert_expiry_notifications>@example.com
juju integrate acmesh:signed-certificates your-charm:signed-certificates
```

### Settings

Set the `expiry_notification_time` in `TLSCertificatesRequiresV2()` to (<CA's_max_lifetime> - 60 + 1) x 24.

Why:
acme.sh automatically by default renews certificates every 60 days. Since there is no connection/IPC (yet) between acme.sh and the charm code it is best to renew the certificates from charm code before acme.sh does. This is so that unnecessary requests to the CA is avoided. So please set the `expiry_notification_time` on the requester side to the (CA's max lifetime - 60 + 1) x 24. Eg for zeroSSL that has 90 days lifetime set it to (90 - 60 + 1) x 24 = 744.

### Certificate signing request

Add the SubjectAlternativeName extension to the certificate signing request with the DNS name you want the certificate to be valid for. Probably the same as the subject/CN.

For example using the TLSCertificates lib in a charm:

```python
private_key = get_private_key_from_somewhere_or_generate()
subject = example.domain.com
sans_dns = [subject]
csr = generate_csr(private_key=private_key, subject=subject, sans_dns=sans_dns)
```

### Allow incoming requests to the acme.sh standalone server

The charm uses http-01 challenge and for this to succeed there needs to be a way for the CA to reach the standalone server that acme.sh spins up as part of the signing process. The server listens on port 80 (not yet configurable). For example using Haproxy in front of a webservice it could look like this:

```python
#### Please note that this is only an example and may not work in your code ####
binding = self.model.get_binding("juju-info")
server_address = str(binding.network.ingress_address)
server_port = 1234
if not server_address or not server_port:
  return
signed_certificate_relation = self.model.get_relation("signed-certificates")
acme_server_name = "acme-server"
if signed_certificate_relation:
  acme_server_name = signed_certificate_relation.app.name

# Haproxy services configuration
haproxy_services = []
acme_and_redirect_service = {
  "service_name": "<requirer-app-name>-http",
  "service_host": "0.0.0.0",
  "service_port": "80",
  "service_options": [
      "mode http",
      "acl is_acme_challenge path_beg -i /.well-known/acme-challenge/",
      "http-request redirect scheme https if !{ ssl_fc } !is_acme_challenge",
  ],
  # acmesh is a subordinate charm so the server_address is the same as the principal
  "servers": [[acme_server_name, server_address, 80, None]],
}
haproxy_services.append(acme_and_redirect_service)
# If there is a certificate for Haproxy (that you get through the signed-certificates integration) then setup the service with that certificate.
if self.haproxy_certificate is not None:
  https_service = {
    "service_name": "<requirer-app-name>",
    "service_host": "0.0.0.0",
    "service_port": "443",
    "crts": [self.haproxy_certificate],
    "service_options": [
      "mode http",
      "balance leastconn",
      "cookie SRVNAME insert",
      # Other options to Haproxy here
    ],
    # Cannot verify ssl as Haproxy-charm does not allow inserting CA cert. Bug filed in charm code.
    "servers": [[unit_id, server_address, server_port, "cookie S{{i}} check ssl verify none"]],
  }
  haproxy_services.append(https_service)

relation.data[self.unit].update(
  {
    "host": server_address,
    "port": str(server_port),
    "services": yaml.dump(haproxy_services),
  }
)
```

## Other resources

<!-- If your charm is documented somewhere else other than Charmhub, provide a link separately. -->

- [Contributing](CONTRIBUTING.md) <!-- or link to other contribution documentation -->

- See the [Juju SDK documentation](https://juju.is/docs/sdk) for more information about developing and improving charms.
