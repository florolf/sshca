# Problem statement

SSH certificates suffer from similar problems to Web PKI certificates with regards to misissuance. Arguably, the situation is even worse since SSH is a trusted service and a CA issuing certificates for the root principal can (given a suitable configuration) lead to privilege escalation across a fleet of machines.

While misissuance cannot be prevented, we can use a transparency log to at least detect it.

# Approach

The approach here is inspired by [opkssh](https://github.com/openpubkey/opkssh): We can tack on additional information (like a transparency log inclusion proof) to a certificate using an extension field and use the `AuthorizedKeysCommand` mechanism of the OpenSSH sshd implementation to add additional verification steps without modifying existinc code. In particular, in this implementation, it can be verified pretty easily that we can only ever *narrow down* the set of certificates that are accepted, so this mechanism is never less secure than plain SSH certificates.

We do the following:

 * We generate a regular SSH certificate to our liking, leaving out the CT extension (`ssh-ct-proof-v1@n621.de`) and the trailing signature field that normally contains the CA signature, this is the pre-cert.
 * We submit the pre-cert (prefixed with `ssh-ct-proof-v1@n621.de\0`) to a [sigsum](https://sigsum.org) log.
 * The resulting proof is an ASCII document. This is compressed using zlib and the pre-cert extension list is extended with a `ssh-ct-proof-v1@n621.de` field which contains the compressed proof as payload.
 * The CA signs this certificate

On the server side, the proof can be extracted and verified by re-deriving the pre-cert from the supplied certificate (by stripping the CT extension and the signature) and calculating its checksum. If the proof is valid, the `AuthorizedKeysCommand` implementation simply outputs a pre-configured `authorized_keys` line (with optional additional limits as supported by sshd). sshd then uses it to verify the certificate supplied by the user. If the proof is invalid, nothing is output and the certificate verification will fail.

While this double signature (once as part of the sigsum proof and once as part of the regular certificate) is somewhat redundant, this is the price to pay for relying entirely on existing unmodified mechanisms (namely sigsum and the native OpenSSH certificate implementation). Since there is no domain separation in SSH CA signatures, we use distinct Ed25519 keys for the sigsum submission and the CA signature respectively.

# Example implementation

This repo contains an example implementation of both the CA and the verifier. The CA-side implementation is part of a distinct experiment with short-lived certificates for SSH, which makes it a little more complex to set up, but otherwise doesn't infringe on the mechanism described here. The sigsum submission simply shells out to the sigsum-go CLI tools. The verifier implementation uses the upstream sigsum libraries.

## Setting up the CA

Install the package in a virtualenv (e.g. using `uv sync`). Create a CA directory (the absolute path is referred to as `CA_DIR` below) and generate the CA signing and sigsum submission keys (these could be hardware-backed but for simplicity we use an unencrypted plain Ed25519 key here):

```
$ mkdir $CA_DIR
$ cd $CA_DIR
$ ssh-keygen -t ed25519 -C 'CA key' -N '' -f ca
$ ssh-keygen -t ed25519 -C 'sigsum submission key' -N '' -f submit
```

Now create the CA configuration file (`CA_DIR/config.toml`):

```
[ca]
agent = '/tmp/agent'
db = 'CA_DIR/ca.db'

# contents of ca.pub, with or without the comment
pubkey = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIM43OqbV3S+J8MdR0NpHbqRhfxETerB90AeewQUwQ/1i CA key'

[ca.sigsum]
policy = 'CA_DIR/policy'
signing_key = 'CA_DIR/submit'

# can also use the pubkey and an agent:
# signing_key = 'CA_DIR/submit.pub'
# agent = '...'

# optionally set the path to the sigsum-submit binary here if it is not in PATH
# submit_tool = '/tmp/sigsum-submit'

[group.default]
valid_duration = 3600

[key."ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILd/KSc395etZEYZpH61Af/Z16zpaPpAUEekQZOiZQ/8 florolf@eos"]
principals = ['myprincipal']
submit_ct = true
```

And create a sigsum policy (`CA_DIR/policy`):

```
log 4644af2abd40f4895a003bca350f9d5912ab301a49c77f13e5b6d905c20a5fe6 https://test.sigsum.org/barreleye

witness poc.sigsum.org/nisse 1c25f8a44c635457e2e391d1efbca7d4c2951a0aef06225a881e46b98962ac6c
witness rgdd.se/poc-witness  28c92a5a3a054d317c86fc2eeb6a7ab2054d6217100d0be67ded5b74323c5806

group  demo-quorum-rule any poc.sigsum.org/nisse rgdd.se/poc-witness
quorum demo-quorum-rule
```

In another terminal, start an ssh agent and add the CA key:

```
$ ssh-agent -d -a /tmp/agent
[...]
$ SSH_AUTH_SOCK=/tmp/agent ssh-add ca
```

For convenience, get the keyhash of the supplied user key using the `authorized-keys` subcommand:

```
$ sshca config.toml authorized-keys
command="[...]/.venv/bin/sshca [...]/config.toml ssh \"1nf9nSLcCRfgNHtL2iSMrAzZwWCRzm7cB9blR+yCa9E\"",restrict ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILd/KSc395etZEYZpH61Af/Z16zpaPpAUEekQZOiZQ/8 florolf@eos
```

(The keyhash is used here because this is what appears in the sshd log file)

We can now generate a certificate:

```
$ sshca config.toml ssh "1nf9nSLcCRfgNHtL2iSMrAzZwWCRzm7cB9blR+yCa9E"
ssh-ed25519-cert-v01@openssh.com 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
Successfully generated certificate for key "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILd/KSc395etZEYZpH61Af/Z16zpaPpAUEekQZOiZQ/8 florolf@eos"
Valid until: Tue Sep 30 01:08:29 2025 UTC
```

(The certificate is output on stdout so the user can do `ssh ca@ssh-ca.example.com > ~/.ssh/id_ed25519-cert.pub`)

# SSH server configuration

Build the verifier binary in the `go/` subdirectory and copy it to the SSH server (`/root/ssh-ct-verify` in this example) and add the `AuthorizedKeysCommand` to the sshd configuration (and reload sshd afterwards):

```
AuthorizedKeysCommand /root/ssh-ct-verify verify %h/.ssh/ct "%k"
AuthorizedKeysCommandUser root
```

Now, for a given user, create `~/.ssh/ct/` with the following contents:
 * Copy the `submit.pub` and `policy` files from above
 * Create an `authorized_keys` file that contains the CA public key (use the literal contents of the `ca.pub` file but prepend `cert-authority,principals="myprincipal" `, see `sshd(8)`)
 * Create an empty `crl` file (more on this later)

You should now be able to log in as the user using the certificate. Invalidating the inclusion proof (e.g. by changing the log pubkey in the policy file) will prevent a login.

The `crl` file can optionally list sigsum checksums (one per line, hex encoded) that will be rejected even with a valid proof. This can be used to deny suspicious log entries (we cannot use the regular SSH CRL mechanism here since we might only know the sigsum checksum of an entry we want to deny, which SSH is unaware of).

# Monitoring

`sshca` provides a lookup from a checksum to a certificate. The [sigmon](https://github.com/florolf/sigmon/) `leaf_info` hook in this directory (`ssh_ca`) can be used to include the verified certificate contents in alerts that it sends out:

```
From: ...
To: ...
Subject: New valid signature from "demo-SSH-CA" on https://test.sigsum.org/barreleye (index 8600)
Message-Id: ...

Log: https://test.sigsum.org/barreleye
Leaf index: 8600
Keyhash: 275b407207d36df418255e8dadb015d47becddfb931541edc1060c5c7132ee29
Checksum: f8a3ceb6b29cd8303a847e3273fc7995da6b59ae303e06465a45b3217fcd5b9d

Auxiliary leaf info (ssh_ca):
------------------------------------------------------------------------
(stdin):1:
        Type: ssh-ed25519-cert-v01@openssh.com user certificate
        Public key: ED25519-CERT SHA256:1nf9nSLcCRfgNHtL2iSMrAzZwWCRzm7cB9blR+yCa9E
        Signing CA: ED25519 SHA256:s687PXSKMr0gh5jiIesqUuE8puXNkYopGkxRaMJd5KQ (using ssh-ed25519)
        Key ID: "florolf@eos"
        Serial: 2
        Valid: from 2025-09-30T02:08:29 to 2025-09-30T03:08:29
        Principals: 
                myprincipal
        Critical Options: (none)
        Extensions: 
                permit-X11-forwarding
                permit-agent-forwarding
                permit-port-forwarding
                permit-pty
                permit-user-rc
                ssh-ct-proof-v1@n621.de UNKNOWN OPTION: 000004c8789c5d554d8e9c370eddd7297c0452a44471d167092891740c046ec0ce0c829c7edee759a43b8bee85aa4a22dfef7febc7cf6fefdfdfc6eb8ff7af6f5adbef9dbc2637a5cf96bb78d8e5591c3a4a32db48d79d87edd81c0bdf571a6526e768befea8e8b761f328d9204b59d9ca7bcc593b230ff14cb55317171d179eca959769d19dd75846d5f02f22353182e2b9e5e545db4f147e403135289872f20d3bc285b3b2669fb61c0f87e17cddc82db983436ee32e77cba5e93b7a9fea45712afc1a15561aac26a5f35013ef081aafd7cf6f7fd7db5ec4af1fefef7ffef67bfcfcfd8da83a426337e6c41541293493689eda008c8faaaeb18f8c99bd9d7029160bef4b12f3e2d2afdfe3cffffca8b7b4d01c7a9b30b0ca740290b57a2dc340ad374665a76e89688f0634a4151567cbb14b74ecf064f376c586f81050829a1180c539ebb01203830dc4d87562fd9ec6b1789352bceefb3fc3506aeb8ac11e47c86f85ee9be5c6e035b7eed5d77dd3e86dc2360b6318f5d97ab467e8179c393b39cb97030a0cc84e5d3279ec9190c05d8a6dbad3b8d35b6bb4773660f2312eaf35716c8a9fe655607909bccf737654d60d9903630c650b9a77e1306baf33e9ba1d0265b5db4e2660a94f8b31c6b6b1c0ccaa559b93a5759013c5983a42cf0a52bf23dd970cad9a78279cf0a640911f17c31b74659d5d346c80a5613631e7e8c72cf00000d60121af04f667b1e7c40f7d1ca8722597c4909dc0cb4da4835df06974f9015bb08a8ab8f319fb1740cc62ccf3723447d8bf16c3cc7a13ce548861da6891a9b9f137e93c7b1148c0786d7b4163c224973c0b4f5cc8483e2ec65dbd6ff4ba09954d238ebb46838eb369ca4d487ecea15ec9236e322b8b9fdb16dd5b65b1cc7d20725dd0d13d2008643087cb7539eb0a48eef95c01825692a40ae05eda710fd9e7c506541348083dc32f2139ac93eebeb68cd65c022dca9046e278683505dc37ebd26208e5ee4f8c1592230ca27dd492a9097b39a8da3631541f68e0f2011b9b004028c207fff79407efb33a8b350a388c58b0272d9d02757a2c448bd079e2043e99607b156c9eb0890df7c886c7eea7c58cce5e1cc4d4639250c2ecbd02016a45c7279711f685100e12466e2117ad0fa0f463b8f8e362541988e725c23d7c4c64ef981d6ace1d0b0b680c084dc0c0034a036a24ad98079c193c276285b8ef582adb02c11d4fe6f3c9550c665837b4027f886153437e40189c2b00dd412d7c5a0cb3570b54dd7d9044a80ed840602b983f0505701ae9a5a9e42061962f73186c4ae2c0767c5c0c11a8f94864edb9137ebff68427d462084cc80d41b410890ddcbd194a8307a0446a24630cb03b6d23e7d1447e408919b6bfea0399ad4f54ed0d33a288728d5367fa05570b461f4310e5f6fa555fbf7dfb9ef5d713fef4fafe9ef5fff0f749264f6d98a3d286489e864ece72aaabea9eb81d012cc01175a5508c8c406b990dbcdf1faee241c3d5d08188c5b12a1616be50056a0ac18bbc04a3537d316a948f14c25fe63d105edbddf5712a2dd9486602b9d8559fb950a063d78128e7c9eb08cb81e80af48ac55c388e14cf8b6e1f1fa7ca757dcf0183417be87dc4072e401f1a100729eb6988a398770f3f48a9f20d69959ca771467eb8aaf6396e0f67056520a36a3e9d04f63143471262ef97ea41160a072e68dd781645618e907dfd0f40af65c4 (len 1228)
------------------------------------------------------------------------
```
