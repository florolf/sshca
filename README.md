# ssh-ca

*Note: This is still experimental software, rely on it at your own risk*

This is a small self-service SSH CA implementation for short-lived
certificates. Notably, it delegates all the hard stuff (authentication,
cryptography) to OpenSSH and supports an experimental certificate transparency
mechanism.

## Rationale

[SSH certificates](https://datatracker.ietf.org/doc/draft-miller-ssh-cert/) are
an alternative mechanism to manually maintaining `authorized_keys` files on
multiple systems. However, they suffer from similar issues to X.509
certificates in that you now need a mechanism to revoke individual certificates
across all the systems that trust a given CA. OpenSSH has a CRL mechanism, but
that just shifts the problem from deploying `authorized_keys` files to
deploying revocation lists to your systems (with the difference that problems
with the former have more of a "fail closed" behavior that will likely be
noticed while the latter fails open).

One of the recent trends in the PKIX ecosystem is to move towards much
shorter-lived certificates and automatic renewal to soften the impact of key
compromise. While the SSH world is not entirely comparable, we can still use a
similar mechanism to expire keys relatively quickly without having to
distribute CRLs. This is what `ssh-ca` implements. Users use SSH to connect to
a special account on a dedicated machine (e.g. `sshca@sshca.example.com`). If
the key used for logging in matches one listed in the configuration, a new
certificate with a configurable short (e.g. 24h) expiry time is generated and
returned back to the user. They can then use it to authenticate to other hosts.
Revocation simply means removing that key from the configuration. Then, the
user won't be able to refresh their certificate and is unable to authenticate
to other hosts anymore after the expiry interval has passed.

An additional issue with SSH certificates is that a key compromise is
potentially much more dangerous than with the regular `authorized_keys`
mechanism. For example, depending on the exact configuration used when using
the `principals` feature, the CA can decide to allow root access on arbitrary
machines for a given key.
