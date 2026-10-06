from pydantic import BaseModel, Field


class CreateSessionRequest(BaseModel):
    creator_id: str = Field(min_length=8, max_length=80)


class JoinSessionRequest(BaseModel):
    security_code: str = Field(pattern=r"^\d{6}$")
    participant_id: str = Field(min_length=8, max_length=80)


class LeaveSessionRequest(BaseModel):
    participant_id: str = Field(min_length=8, max_length=80)

