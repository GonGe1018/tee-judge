from pydantic import BaseModel


class JudgeTask(BaseModel):
    submission_id: int
    problem_id: int
    language: str
    code: str
    time_limit_ms: int
    memory_limit_kb: int
    testcases: list[dict]
    nonce: str


class JudgeResultRequest(BaseModel):
    submission_id: int
    actual_outputs: list[dict]
    outputs_hash: str
    time_ms: int
    memory_kb: int
    attestation_quote: str | None = None
    verdict_signature: str | None = None
    nonce: str
