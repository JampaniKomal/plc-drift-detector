from importlib import resources
from pathlib import Path

import pytest
from lxml import etree

from otguard import config, simulate

KEY = b"test-key-0123456789abcdef"


def sample_bytes() -> bytes:
    return resources.files("otguard").joinpath("data/WaterPlant.L5X").read_bytes()


def edit(data: bytes, change) -> bytes:
    """Apply a function to the parsed L5X and serialize it again."""
    parser = etree.XMLParser(strip_cdata=False)
    root = etree.fromstring(data, parser)
    change(root)
    return etree.tostring(root, xml_declaration=True, encoding="UTF-8", standalone=True)


@pytest.fixture
def workspace(tmp_path, monkeypatch) -> config.Config:
    """A demo workspace with the sample project; nothing approved yet."""
    monkeypatch.setenv(config.KEY_ENV, KEY.decode())
    path = simulate.init_demo(tmp_path / "demo")
    return config.load(path)


@pytest.fixture
def project_file(workspace) -> Path:
    return workspace.watched[0]
