import base64
import hashlib


def b64enc(data: bytes, pad: bool = True) -> str:
    s = base64.b64encode(data).decode('ascii')
    if not pad:
        s = s.rstrip('=')

    return s


def b64dec(data: str, padded: bool = True) -> bytes:
    if not padded and len(data) % 4 != 0:
        data = data + '=' * (4 - (len(data) % 4))

    return base64.b64decode(data)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()
