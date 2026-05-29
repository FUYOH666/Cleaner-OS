"""Security analyzer tests."""

import os
import stat
from pathlib import Path

from syscleaner.analyzer.security import check_ssh_permissions
from syscleaner.platform.paths import PlatformPaths


def test_ssh_permissions_too_open(tmp_path: Path) -> None:
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir(mode=0o700)
    key = ssh_dir / "id_rsa"
    key.write_text("fake-key")
    os.chmod(key, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)

    paths = PlatformPaths(home=tmp_path)
    issues = check_ssh_permissions(paths)
    assert len(issues) >= 1
    assert any("ssh" in i.category.lower() for i in issues)
