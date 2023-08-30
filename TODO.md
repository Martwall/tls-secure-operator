# TODO List

- [ ] Fix issue with acme.sh not handling IP addresses in sans. Perhaps it would be easier to disect the csr before passing it on to acme.sh. But that would mean using acme.sh issue mechanism and not a csr. Better to add issue to acme.sh.
- [ ] Handle the error logging and handling
- [ ] Testing: What does the cronjob in acme.sh look like?
- [ x ] Add actions for create, renew, and revoke. This would also enable better integration testing of those actions.
- [ ] Is it possible to check if the certificate has already been renewed by acme.sh before responding to a certificate_creation_request? This would avoid the need to set the configuration value of `expiry_notification_time`
- [ ] Add dns validation
- [ ] Add the possibilty to add EAB credentials in acme.sh and in the config.
- [ ] Handle adding the days flag for [buypass](https://github.com/acmesh-official/acme.sh/wiki/BuyPass.com-CA)
