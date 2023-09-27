<!--
Avoid using this README file for information that is maintained or published elsewhere, e.g.:

* metadata.yaml > published on Charmhub
* documentation > published on (or linked to from) Charmhub
* detailed contribution guide > documentation or CONTRIBUTING.md

Use links instead.
-->

# tls-secure-operator

Charmhub package name: tls-secure

More information: https://charmhub.io/tls-secure

A charm to get signed certificates to protect (web) services. It attempts to integrate with reverse proxies in order to complete the http-01 challenge.
Uses the "tls-certificates" interface and relation name "signed-certificates".
Uses (currently) acme.sh under the hood for fetching and handling certificates.

## Limitations

ONLY use ONE instance of the charm

ONLY http-01 challenge in standalone mode.

ONLY rsa certificates.

ONLY Haproxy supported as proxy service at the moment.

Does not support IP addresses in the certificate signing request (csr) because of how acme.sh handles issuing certificates from an existing csr.

## How to use

In your charm:

```yaml
requires:
  signed-certificates:
      interface: tls-certificates
      limit: 1
```

Use the charms.tls_certificates_interface.v2.tls_certificates lib to handle the integration in your charm. Checkout the [settings](#settings) and [certificate signing request sections](#certificate-signing-request). Also look at the examples of a requirer charm from the [documentation of the TLS Certificates Interface lib](https://charmhub.io/tls-certificates-interface/libraries/tls_certificates). There is also a [requirer charm](tests/integration/juju/dev_requirer_charm/src/charm.py) used for integration testing to take a look at if inspiration is required but it is purely for development.

On juju command line when using Haproxy as the proxy service:

```shell
juju deploy tls-secure --config email=email_for_cert_expiry_notifications@example.com
juju deploy haproxy --config services=""
juju integrate tls-secure:haproxy haproxy:reverseproxy
juju integrate tls-secure:signed-certificates your-charm:signed-certificates
```

On juju command line when not using a proxy service:

```shell
juju deploy tls-secure --config email=email_for_cert_expiry_notifications@example.com --config proxy-service=none
juju integrate tls-secure:signed-certificates your-charm:signed-certificates
```

Please note that somehow the ACME server needs to be able to reach the standalone server in
the charm. See [Allow incoming requests to the standalone server](#allow-incoming-requests-to-the-standalone-server).

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

### Allow incoming requests to the standalone server

The charm uses http-01 challenge and for this to succeed there needs to be a way for the CA to reach the standalone server that acme.sh spins up as part of the signing process. The server listens on port 80 (not yet configurable). This means that if not used with a local ACME server, the domain name in the csr for which a certificate is requested needs to be set so that a request will reach the standalone ACME server. This means that when using proxy mode a record should be added at your dns provider that points to the proxy instance or is somehow able to reach it. When not using proxy mode there needs to be a way for the ACME server to reach the standalone server in the charm directly.

When using a proxy-service with the charm, for example "haproxy" the tls-secure charm automatically adds a listener service on port 80 that forwards acme challenges to itself and
redirects all other requests to https (port 443). This means that your charm only has to configure the https service. See config.yaml for more information.

For example using Haproxy in front of a webservice it could look something like this:

```python
#### Please note that this is only an example and may not work in your code ####
binding = self.model.get_binding("juju-info")
server_address = str(binding.network.ingress_address)
server_port = 1234
if not server_address:
  return

# Haproxy services configuration
haproxy_services = []
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
