from acceptance.model import Verdict
from acceptance.supervision import classify_process


async def test_success_is_pass() -> None:
    assert await classify_process("success") is Verdict.PASS


async def test_crash_and_hang_are_infrastructure_errors() -> None:
    assert await classify_process("crash") is Verdict.INFRA_ERROR
    assert await classify_process("hang") is Verdict.INFRA_ERROR
