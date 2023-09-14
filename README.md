<!--
Avoid using this README file for information that is maintained or published elsewhere, e.g.:

* metadata.yaml > published on Charmhub
* documentation > published on (or linked to from) Charmhub
* detailed contribution guide > documentation or CONTRIBUTING.md

Use links instead.
-->

# acmesh-operator

Charmhub package name: operator-template
More information: https://charmhub.io/acmesh-operator

Describe your charm in one or two sentences.

## Limitations

ONLY http-01 challenge.

Does not support ip addresses in the certificate signing request (csr) because of how acme.sh handles issuing certificates from an existing csr.

## Settings

Set the `expiry_notification_time` in `TLSCertificatesRequiresV2()` to (<CA's_max_lifetime> - 60 + 1) x 24.

Why:
acme.sh automatically by default renews certificates every 60 days. Since there is no connection/IPC (yet) between acme.sh and the charm code it is best to renew the certificates from charm code before acme.sh does. This is so that unecessary requests to the CA is avoided. So please set the `expiry_notification_time` on the requester side to the (CA's max lifetime - 60 + 1) x 24. Eg for zeroSSL that has 90 days lifetime set it to (90 - 60 + 1) x 24 = 744.

## Certificate signing request

Add the SubjectAlternativeName extension to the certificate signing request with the DNS name you want the certificate to be valid for. Probably the same as the subject/CN.

For example using the TLSCertificates lib in a charm:

```python
private_key = get_private_key_from_somewhere_or_generate()
subject = example.domain.com
sans_dns = [subject]
csr = generate_csr(private_key=private_key, subject=subject, sans_dns=sans_dns)
```

## Other resources

<!-- If your charm is documented somewhere else other than Charmhub, provide a link separately. -->

- [Read more](https://example.com)

- [Contributing](CONTRIBUTING.md) <!-- or link to other contribution documentation -->

- See the [Juju SDK documentation](https://juju.is/docs/sdk) for more information about developing and improving charms.
