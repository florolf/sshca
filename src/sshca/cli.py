import sys
import logging
import argparse
import tomllib
import time
import shlex
import os
import zlib

from pathlib import Path
from typing import Any, Optional
from collections import defaultdict

from . import ssh, sigsum
from .db import DB
from .utils import b64enc, b64dec, sha256

logger = logging.getLogger(__name__)


def build_parser():
    parser = argparse.ArgumentParser(prog="sshca", description="SSH CA")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("config", type=Path, help="config file")

    subparsers = parser.add_subparsers(title="subcommands", dest="command", required=True)

    subparsers.add_parser("authorized-keys", help="Generate authorized keys file")

    lookup_checksum_parser = subparsers.add_parser("lookup-checksum", help="Resolve a sigsum checksum to a certificate")
    lookup_checksum_parser.add_argument("checksum", type=bytes.fromhex, help='hex-encoded checksum')

    sign_parser = subparsers.add_parser("ssh", help="SSH command handler for key")
    sign_parser.add_argument("pubkey", help='hex-encoded pubkey')

    return parser


def build_parser_ssh():
    parser = argparse.ArgumentParser(prog="sshca", description="SSH CA")
    subparsers = parser.add_subparsers(title="subcommands", dest="command", required=True)

    sign_parser = subparsers.add_parser("sign", help="generate a certificate for the current key")
    sign_parser.add_argument("--valid-duration", type=int, help='set maximum validity duration in seconds')

    return parser


def load_config(path: Path) -> dict[str, Any]:
    with path.open('rb') as f:
        toml = tomllib.load(f)

    config = defaultdict(dict)

    if 'sigsum' in toml['ca']:
        config['ca']['sigsum'] = toml['ca']['sigsum']

    config['ca']['pubkey'] = ssh.Pubkey.from_line(toml['ca']['pubkey'])
    config['ca']['agent'] = Path(toml['ca']['agent'])
    config['ca']['db'] = Path(toml['ca']['db'])

    groups = toml.get('group', {})
    default = {
        'extensions': ['permit-X11-forwarding', 'permit-agent-forwarding', 'permit-port-forwarding', 'permit-pty', 'permit-user-rc']
    }
    default.update(groups.get('default', {}))

    keys = {}
    for key_str, body in toml.get('key', {}).items():
        pubkey = ssh.Pubkey.from_line(key_str)

        params = {}
        params.update(default)

        for group in body.get('groups', []):
            params.update(groups[group])

        if 'groups' in body:
            del body['groups']

        if pubkey.comment is not None:
            params['comment'] = pubkey.comment

        params.update(body)

        params['_obj'] = pubkey

        duplicate = keys.get(pubkey.hash, None)
        if duplicate is not None:
            logging.error(f'duplicate pubkey "{pubkey}"')
            continue

        keys[pubkey.hash] = params

    config['keys'] = keys

    return config


def do_authorized_keys(config_path: Path, config: dict[str, Any]):
    cmd = Path(sys.argv[0]).resolve()

    for pubkey, body in config['keys'].items():
        line = f'command="{cmd} {config_path.resolve()} ssh \\"{b64enc(pubkey, pad=False)}\\"",restrict {body["_obj"]}'

        print(line)


def build_extensions(kcfg: dict[str, Any]) -> Optional[list[tuple[str, bool, bytes]]]:
    wellknown = {
        'no-touch-required': (False, None),
        'permit-X11-forwarding': (False, None),
        'permit-agent-forwarding': (False, None),
        'permit-port-forwarding': (False, None),
        'permit-pty': (False, None),
        'permit-user-rc': (False, None),

        'force-command': (True, lambda x: x.encode()),
        'source-address': (True, lambda x: x.encode()),
    }

    extensions = []
    for ext in kcfg['extensions']:
        if type(ext) is str:
            k = ext
            v = None
        else:
            k = ext['name']
            v = ext

        if k in wellknown:
            critical = wellknown[k][0]
            converter = wellknown[k][1]

            if converter is None:
                extensions.append((k, critical, b''))
                continue

            if v is None:
                logging.error(f'extension {k} needs a value')
                return None

            extensions.append((k, critical, converter(v['value'])))
        else:
            if '@' not in k:
                logging.error(f'unknown extension {k}, skipping')
                return None

            if v is None:
                logging.error(f'custom extension {k} needs payload')
                return None

            if 'raw' in v:
                payload = bytes.fromhex(v['raw'])
            else:
                payload = v['data'].encode()

            extensions.append((k, v['critical'], payload))

    return extensions


def do_sign(config: dict[str, Any], pubkey, args):
    kcfg = config['keys'][pubkey]
    obj = kcfg['_obj']

    if 'id' in kcfg:
        identifier = kcfg['id']
    elif 'comment' in kcfg:
        identifier = kcfg['comment']
    else:
        logging.error(f'no identifier given for {obj}')
        sys.exit(1)

    now = int(time.time())
    extensions = build_extensions(kcfg)
    if extensions is None:
        logging.error(f'failed to build extensions for "{obj}"')
        sys.exit(1)

    valid_before = now + kcfg['valid_duration']
    if args.valid_duration is not None:
        valid_before = min(valid_before, now + args.valid_duration)

    if kcfg.get('no_valid_after', False):
        valid_after = None
    else:
        valid_after = now - kcfg.get('valid_after_delta', 0)

    db = DB(config['ca']['db'])

    with db:
        serial = db.next_serial()

        cert = ssh.Certificate(
            pubkey = obj,
            identifier = identifier,
            principals = kcfg.get('principals', []),
            extensions = extensions,
            valid_after = valid_after,
            valid_before = valid_before,
            serial = serial
        )

        sigsum_checksum = None
        if kcfg.get('submit_ct', False):
            pre_cert = cert.make_unsigned(config['ca']['pubkey'])
            sigsum_data = b'ssh-ct-proof-v1@n621.de\0' + pre_cert
            sigsum_hash = sha256(sigsum_data)
            sigsum_checksum = sha256(sigsum_hash)

            proof = sigsum.submit(config['ca']['sigsum'], sigsum_hash)

            if proof is None:
                logging.error('failed to retrieve sigsum proof')
                sys.exit(1)

            cert.extensions.append(('ssh-ct-proof-v1@n621.de', False, zlib.compress(proof.encode())))

        agent = ssh.Agent(config['ca']['agent'])
        raw = cert.make(agent, config['ca']['pubkey'])

        db.add_cert(serial, raw, update=True)

        if sigsum_checksum:
            db.add_checksum(serial, sigsum_checksum)

    print(f'{cert.cert_type} {b64enc(raw)}')

    print(f'Successfully generated certificate for key "{obj}"', file=sys.stderr)
    print(f'Valid until: {time.asctime(time.gmtime(valid_before))} UTC', file=sys.stderr)


def do_lookup_checksum(config: dict[str, Any], checksum: bytes):
    db = DB(config['ca']['db'])
    cert_raw = db.cert_by_checksum(checksum)

    if cert_raw is None:
        print('No matching certificate found', file=sys.stderr)
    else:
        cert, _ = ssh.Certificate.from_bytes(cert_raw)
        print(f'{cert.cert_type} {b64enc(cert_raw)}')


def main():
    args = build_parser().parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    config = load_config(args.config)

    match args.command:
        case 'authorized-keys':
            do_authorized_keys(args.config, config)
        case 'lookup-checksum':
            do_lookup_checksum(config, args.checksum)
        case 'ssh':
            pubkey = b64dec(args.pubkey, padded=False)

            if pubkey not in config['keys']:
                logging.error(f'key "{args.pubkey}" not in configuration')
                sys.exit(1)

            argv = shlex.split(os.environ.get('SSH_ORIGINAL_COMMAND', 'sign'))
            inner_args = build_parser_ssh().parse_args(argv)

            match inner_args.command:
                case 'sign':
                    do_sign(config, pubkey, inner_args)
                case _:
                    logging.error(f'unknown command "{inner_args.command}"')
                    sys.exit(1)
        case _:
            logging.error(f'unknown command "{args.command}"')
            sys.exit(1)
