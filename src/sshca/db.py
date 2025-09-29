from pathlib import Path
from typing import Optional

import apsw
import apsw.bestpractice

apsw.bestpractice.apply(apsw.bestpractice.recommended)

MIGRATIONS = [
    # 1
    [
        """
        CREATE TABLE certificates (
            serial INTEGER PRIMARY KEY AUTOINCREMENT,
            cert BLOB
        );

        CREATE TABLE checksums (
            checksum TEXT,
            serial INTEGER REFERENCES certificates(serial)
        );
        """
    ],
]


class DB:
    def __init__(self, path: Path):
        self.db = apsw.Connection(str(path))
        self._check_migrations()

    def _check_migrations(self):
        version = self.db.pragma('user_version')

        if version > len(MIGRATIONS):
            raise RuntimeError(f'database version ({version}) is higher than supported version ({len(MIGRATIONS)})')

        for level in MIGRATIONS[version:]:
            with self.db:
                version += 1

                for step in level:
                    if type(step) is str:
                        self.db.execute(step)
                    elif callable(step):
                        step(self)
                    else:
                        raise AssertionError('invalid step in version %d: %s' % (version, step))

                self.db.pragma('user_version', version)

    def __enter__(self):
        self.db.__enter__()

    def __exit__(self, *args, **kwargs):
        self.db.__exit__(*args, **kwargs)

    def next_serial(self) -> int:
        cur = self.db.execute('INSERT INTO certificates DEFAULT VALUES RETURNING serial')

        serial = cur.fetchall()[0][0]
        assert type(serial) is int

        return serial

    def add_cert(self, serial: int, raw: bytes, update: Optional[bool] = False):
        self.db.execute(f'''
                        INSERT {"OR REPLACE" if update else ""} INTO certificates(serial, cert)
                        VALUES (?, ?)
        ''', (serial, raw))

    def add_checksum(self, serial: int, checksum: bytes):
        self.db.execute('''
                        INSERT INTO checksums(checksum, serial)
                        VALUES (?, ?)
        ''', (checksum.hex(), serial))

    def cert_by_checksum(self, checksum: bytes) -> Optional[bytes]:
        row = self.db.execute('''
                         SELECT cert
                         FROM certificates JOIN checksums
                         ON certificates.serial = checksums.serial
                         WHERE checksums.checksum = ?
        ''', (checksum.hex(),)).fetchone()

        if row is None:
            return None

        return row[0]
