import subprocess
import logging
import os

from typing import Any, Optional

logger = logging.getLogger(__name__)


def submit(config: dict[str, Any], raw_hash: bytes) -> Optional[str]:
    cmd = [
        config.get('submit_tool', 'sigsum-submit'),
        f'--policy={config["policy"]}',
        f'--signing-key={config["signing_key"]}',
        '--raw-hash'
    ]

    if 'token-domain' in config:
        cmd.extend([
            f'--token-domain={config["token_domain"]}',
            f'--token-signing-key={config["token_signing_key"]}'
        ])

    env = None
    if 'agent' in config:
        env = os.environ.copy()
        env['SSH_AGENT_SOCK'] = config['agent']

    result = subprocess.run(cmd, env=env, input=raw_hash.hex().encode(), capture_output=True)
    if result.returncode != 0:
        logger.error('sigsum submission failed:')
        logger.error(result.stderr.decode())
        return None

    return result.stdout.decode()
