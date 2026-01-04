# ssh-ca

*Note: This is still experimental software, rely on it at your own risk*

This is a small self-service SSH CA implementation for short-lived
certificates. Notably, it delegates all the hard stuff (authentication,
cryptography) to OpenSSH and supports an experimental certificate transparency
mechanism.

See the [accompanying blog
post](https://blog.n621.de/2026/01/ssh-certificate-transparency) for more
details. The server-side component can be found in the `go/` directory. A
worked example of the CT setup can be found [here](doc/ssh-ct.md).
