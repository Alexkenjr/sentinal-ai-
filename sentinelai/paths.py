"""Application-owned files must not depend on the working directory."""
import os
from pathlib import Path


def data_directory():
    override = os.environ.get('SENTINELAI_DATA_DIR')
    if override:
        path = Path(override).expanduser()
        if not path.is_absolute():
            raise ValueError('SENTINELAI_DATA_DIR must be an absolute path')
        return path
    local = os.environ.get('LOCALAPPDATA')
    if os.name == 'nt' and local and Path(local).is_absolute():
        return Path(local) / 'SentinelAI'
    return Path.home() / '.sentinelai'
