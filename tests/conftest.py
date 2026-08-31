import pytest

from mcpwn.canary import mint_set
from mcpwn.types import PayloadContext


@pytest.fixture
def payload_ctx(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    return PayloadContext(
        canaries=mint_set(),
        workspace=workspace,
        beacon_url="http://127.0.0.1:8899",
    )
