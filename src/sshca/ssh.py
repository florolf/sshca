import socket
import enum
import logging
import secrets

from pathlib import Path
from typing import Optional, Self

from .utils import b64dec, b64enc, sha256

logger = logging.getLogger(__name__)


def msg_get_uint(bits: int, data: bytes) -> tuple[int, bytes]:
    assert bits % 8 == 0
    data_bytes = bits//8

    return int.from_bytes(data[0:data_bytes]), data[data_bytes:]


def msg_get_byte(data: bytes) -> tuple[int, bytes]:
    return data[0], data[1:]


def msg_get_bytes(data: bytes) -> tuple[bytes, bytes]:
    l = int.from_bytes(data[0:4])
    return data[4:4+l], data[4+l:]


def msg_get_string(data: bytes) -> tuple[str, bytes]:
    s, rest = msg_get_bytes(data)
    return s.decode(), rest


class MsgBuilder:
    def __init__(self):
        self.buf = bytearray()

    def put_int(self, bits: int, value: int):
        assert bits % 8 == 0
        data_bytes = bits//8

        self.buf.extend(value.to_bytes(data_bytes))

    def put_bytes(self, data: bytes):
        self.put_int(32, len(data))
        self.buf.extend(data)

    def put_string(self, s: str):
        self.put_bytes(s.encode())

    def append_raw(self, data: bytes):
        self.buf.extend(data)

    def get(self) -> bytes:
        return bytes(self.buf)


class Pubkey:
    def __init__(self, key_type: str, key_data: bytes, comment: Optional[str] = None):
        self.key_type = key_type
        self.key_data = key_data

        blob = MsgBuilder()
        blob.put_string(self.key_type)
        blob.append_raw(self.key_data)

        self.blob = blob.get()
        self.comment = comment

        self.hash = sha256(self.blob)

    @classmethod
    def from_blob(cls, blob: bytes, comment: Optional[str] = None) -> Self:
        key_type, key_data = msg_get_string(blob)

        return cls(key_type, key_data, comment)

    @classmethod
    def from_line(cls, pubkey: str) -> Self:
        elements = pubkey.split(maxsplit=3)
        if len(elements) == 1:
            blob = elements[0]
            comment = None
        elif len(elements) == 2:
            blob = elements[1]
            comment = None
        else:
            blob = elements[1]
            comment = elements[2]

        blob = b64dec(blob)
        return cls.from_blob(blob, comment)

    def __str__(self) -> str:
        line = f'{self.key_type} {b64enc(self.blob)}'

        if self.comment is not None:
            line += f' {self.comment}'

        return line


class AgentCodes(enum.IntEnum):
    FAILURE                           = 5
    SUCCESS                           = 6
    CMD_REQUEST_IDENTITIES            = 11
    IDENTITIES_ANSWER                 = 12
    CMD_SIGN_REQUEST                  = 13
    SIGN_RESPONSE                     = 14
    CMD_ADD_IDENTITY                  = 17
    CMD_REMOVE_IDENTITY               = 18
    CMD_REMOVE_ALL_IDENTITIES         = 19
    CMD_ADD_SMARTCARD_KEY             = 20
    CMD_REMOVE_SMARTCARD_KEY          = 21
    CMD_LOCK                          = 22
    CMD_UNLOCK                        = 23
    CMD_ADD_ID_CONSTRAINED            = 25
    CMD_ADD_SMARTCARD_KEY_CONSTRAINED = 26
    CMD_EXTENSION                     = 27
    EXTENSION_FAILURE                 = 28
    EXTENSION_RESPONSE                = 29


class Agent:
    def __init__(self, path: Path):
        self.path = path
        self.socket = None

    def ensure_connected(self):
        if self.socket:
            return

        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.connect(str(self.path))

    def _recv(self, l: int) -> bytes:
        assert self.socket is not None

        result = bytearray()

        while len(result) < l:
            data = self.socket.recv(l - len(result))
            if not data:
                self.socket = None
                raise RuntimeError('socket closed unexpectedly')

            result.extend(data)

        return bytes(result)

    def recv(self) -> tuple[AgentCodes, bytes]:
        header = self._recv(5)
        l = int.from_bytes(header[0:4])
        retcode = AgentCodes(header[4])

        return retcode, self._recv(l-1)

    def call(self, cmd: AgentCodes, payload: bytes) -> tuple[AgentCodes, bytes]:
        tx = bytearray()

        l = 1 + len(payload)
        tx.extend(l.to_bytes(4))
        tx.extend(cmd.to_bytes(1))
        tx.extend(payload)

        self.ensure_connected()
        self.socket.sendall(tx)

        return self.recv()

    def sign(self, key: Pubkey, data: bytes) -> Optional[bytes]:
        request = MsgBuilder()
        request.put_bytes(key.blob)
        request.put_bytes(data)
        request.put_int(32, 0)

        retcode, response = self.call(AgentCodes.CMD_SIGN_REQUEST, request.get())

        if retcode != AgentCodes.SIGN_RESPONSE:
            logger.error(f'got unexpected response {retcode}')
            return None

        signature_blob, response = msg_get_bytes(response)
        signature_type = msg_get_string(signature_blob)[0]
        if signature_type != key.key_type:
            logger.error(f'unexpected signature type {signature_type}')
            return None

        # depending on the signature type this might be multiple fields, so
        # instead of parsing it, just return the entire blob
        return signature_blob


class Certificate:
    # The "copy paste payload directly into certificate" hack works for all
    # cert types to date, so we can handle them generically here. DSA is
    # excluded because it is deprecated all over the place anyway.
    # TODO: Understand how this works for the different RSA subvariants

    CERT_MAP = {
        'ssh-ed25519': 'ssh-ed25519-cert-v01@openssh.com',

        'ecdsa-sha2-nistp256': 'ecdsa-sha2-nistp256-cert-v01@openssh.com',
        'ecdsa-sha2-nistp384': 'ecdsa-sha2-nistp384-cert-v01@openssh.com',
        'ecdsa-sha2-nistp521': 'ecdsa-sha2-nistp521-cert-v01@openssh.com',

        # 'ssh-rsa',

        'sk-ssh-ed25519@openssh.com': 'sk-ssh-ed25519-cert-v01@openssh.com',
        'sk-ecdsa-sha2-nistp256@openssh.com': 'sk-ecdsa-sha2-nistp256-cert-v01@openssh.com'
    }

    def __init__(self,
                 pubkey:        Pubkey,
                 identifier:    str,
                 nonce:         Optional[bytes] = None,
                 serial:        Optional[int] = None,
                 principals:    Optional[list[str]] = None,
                 valid_before:  Optional[int] = None,
                 valid_after:   Optional[int] = None,
                 extensions:    Optional[list[tuple[str, bool, bytes]]] = None):
        self.pubkey = pubkey
        self.identifier = identifier

        if self.pubkey.key_type not in self.CERT_MAP:
            raise ValueError(f'unsupported key type "{self.pubkey.key_type}"')

        self.cert_type = self.CERT_MAP[self.pubkey.key_type]

        if nonce is None:
            self.nonce = secrets.token_bytes(32)
        else:
            if len(nonce) < 16:
                raise ValueError('nonce is too short')

            self.nonce = nonce

        if serial is None:
            serial = secrets.randbits(64)
        self.serial = serial

        if principals is None:
            principals = []
        self.principals = principals

        if valid_after is None:
            valid_after = 0
        self.valid_after = valid_after

        if valid_before is None:
            valid_before = 0xffffffffffffffff
        self.valid_before = valid_before

        if extensions is None:
            extensions = []
        self.extensions = extensions

        self.reserved = b''

    @classmethod
    def from_bytes(cls, data: bytes) -> tuple[Self, Pubkey]:
        cert_type, data = msg_get_string(data)
        nonce, data = msg_get_bytes(data)

        cert_fragment = MsgBuilder()

        key_type, fragment_entries = {
            "ssh-ed25519-cert-v01@openssh.com": ("ssh-ed25519", 1),
        }[cert_type]

        for _ in range(0, fragment_entries):
            entry, data = msg_get_bytes(data)
            cert_fragment.put_bytes(entry)

        serial, data = msg_get_uint(64, data)

        cert_role, data = msg_get_uint(32, data)
        if cert_role != 1:
            raise ValueError(f'unsupported certificate role "{cert_role}"')

        identifier, data = msg_get_string(data)

        sub_msg, data = msg_get_bytes(data)
        principals = []
        while sub_msg:
            principal, sub_msg = msg_get_string(sub_msg)
            principals.append(principal)

        valid_after, data = msg_get_uint(64, data)
        valid_before, data = msg_get_uint(64, data)

        extensions = []

        # critical
        sub_msg, data = msg_get_bytes(data)
        while sub_msg:
            name, sub_msg = msg_get_string(sub_msg)
            ext_data, sub_msg = msg_get_bytes(sub_msg)

            extensions.append((name, True, ext_data))

        # regular
        sub_msg, data = msg_get_bytes(data)
        while sub_msg:
            name, sub_msg = msg_get_string(sub_msg)
            ext_data, sub_msg = msg_get_bytes(sub_msg)

            extensions.append((name, False, ext_data))

        reserved, data = msg_get_bytes(data)
        ca_key, data = msg_get_bytes(data)

        pubkey = Pubkey(key_type, cert_fragment.get())

        cert = cls(pubkey, identifier, nonce, serial, principals, valid_before, valid_after, extensions)
        cert.reserved = reserved

        return cert, Pubkey.from_blob(ca_key)

    def _add_extensions(self, builder: MsgBuilder, critical: bool):
        extensions = MsgBuilder()
        for name, is_critical, data in sorted(self.extensions, key=lambda x: x[0]):
            if is_critical != critical:
                continue

            extensions.put_string(name)

            if data:
                ext_data = MsgBuilder()
                ext_data.put_bytes(data)

                extensions.put_bytes(ext_data.get())
            else:
                extensions.put_bytes(b'')

        builder.put_bytes(extensions.get())

    def make_unsigned(self, ca_key: Pubkey) -> bytes:
        cert = MsgBuilder()
        cert.put_string(self.cert_type)
        cert.put_bytes(self.nonce)
        cert.append_raw(self.pubkey.key_data)
        cert.put_int(64, self.serial)
        cert.put_int(32, 1)  # SSH2_CERT_TYPE_USER
        cert.put_string(self.identifier)

        principals = MsgBuilder()
        for principal in self.principals:
            principals.put_string(principal)
        cert.put_bytes(principals.get())

        cert.put_int(64, self.valid_after)
        cert.put_int(64, self.valid_before)

        self._add_extensions(cert, True)  # critical
        self._add_extensions(cert, False)  # extensions

        cert.put_bytes(self.reserved)
        cert.put_bytes(ca_key.blob)

        return cert.get()

    def make(self, agent: Agent, ca_key: Pubkey) -> bytes:
        unsigned = self.make_unsigned(ca_key)

        signature_blob = agent.sign(ca_key, unsigned)
        if signature_blob is None:
            raise RuntimeError('signing certificate failed')

        cert = MsgBuilder()
        cert.append_raw(unsigned)
        cert.put_bytes(signature_blob)

        return cert.get()
