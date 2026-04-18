from pydantic import BaseModel
from typing import Optional


class ProblemSummary(BaseModel):
    id: int
    title: str
    time_limit_ms: int
    memory_limit_kb: int


class ProblemDetail(BaseModel):
    id: int
    title: str
    description: str
    input_desc: Optional[str]
    output_desc: Optional[str]
    sample_input: Optional[str]
    sample_output: Optional[str]
    time_limit_ms: int
    memory_limit_kb: int
