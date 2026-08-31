import pytest

from mcpbait.modules import REGISTRY, all_ids, get_modules, register
from mcpbait.modules.base import AttackModule
from mcpbait.types import Event, Phase, ToolSpec, Verdict


@pytest.fixture
def dummy_module():
    @register
    class _Dummy(AttackModule):
        id = "dummy_probe"
        phase = Phase.ACCESS
        atlas_id = "AML.T0051"
        summary = "A dummy module used only to exercise the registry mechanics."
        references = ("https://example.com/dummy",)

        def payload(self, ctx):
            return [ToolSpec(name="dummy", description="d", input_schema={"type": "object"})]

    yield _Dummy
    REGISTRY.pop("dummy_probe", None)


def test_register_adds_the_class_under_its_id(dummy_module):
    assert REGISTRY["dummy_probe"] is dummy_module
    assert "dummy_probe" in all_ids()


def test_get_modules_filters_by_id(dummy_module):
    assert [m.id for m in get_modules(["dummy_probe"])] == ["dummy_probe"]


def test_get_modules_rejects_unknown_id():
    with pytest.raises(KeyError):
        get_modules(["no_such_module"])


def test_default_verify_is_blocked_without_delivery(dummy_module):
    assert dummy_module().verify([]) is Verdict.BLOCKED


def test_default_verify_walks_the_evidence_ladder(dummy_module):
    module = dummy_module()
    delivered = Event(ts=1.0, kind="payload_delivered", module_id="dummy_probe", detail={})
    called = Event(ts=2.0, kind="tool_call", module_id="dummy_probe", detail={})
    leaked = Event(ts=3.0, kind="canary_hit", module_id="dummy_probe", detail={})
    assert module.verify([delivered]) is Verdict.IGNORED
    assert module.verify([delivered, called]) is Verdict.BAITED
    assert module.verify([delivered, called, leaked]) is Verdict.COMPROMISED


def test_evidence_from_another_module_does_not_count(dummy_module):
    other = Event(ts=1.0, kind="canary_hit", module_id="someone_else", detail={})
    assert dummy_module().verify([other]) is Verdict.BLOCKED


def test_respond_defaults_to_none(dummy_module, payload_ctx):
    from mcpbait.types import ToolCall

    assert dummy_module().respond(ToolCall(name="dummy", arguments={}), payload_ctx) is None
