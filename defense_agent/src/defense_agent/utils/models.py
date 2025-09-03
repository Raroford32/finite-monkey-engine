from __future__ import annotations
from enum import Enum
from typing import List, Optional, Dict
from pydantic import BaseModel, Field
from datetime import datetime


class Capability(BaseModel):
	name: str
	description: str
	inputs: List[str] = Field(default_factory=list)
	outputs: List[str] = Field(default_factory=list)
	version: str = "0.1.0"
	safety_flags: List[str] = Field(default_factory=list)


class Finding(BaseModel):
	id: str
	category: str
	severity: str
	description: str
	confidence: float = 0.0
	artifacts: Dict[str, str] = Field(default_factory=dict)


class ForkSpec(BaseModel):
	chain_id: int
	rpc_url: str
	block_number: Optional[int] = None


class AnalysisJob(BaseModel):
	job_id: str
	target_name: str
	artifact_urls: List[str]
	budget_seconds: int
	max_cost_units: int
	forks: List[ForkSpec] = Field(default_factory=list)


class JobStatus(str, Enum):
	queued = "queued"
	running = "running"
	succeeded = "succeeded"
	failed = "failed"


class JobRecord(BaseModel):
	job: AnalysisJob
	status: JobStatus
	findings: List[Finding] = Field(default_factory=list)
	error_message: Optional[str] = None
	created_at: datetime = Field(default_factory=datetime.utcnow)
	updated_at: datetime = Field(default_factory=datetime.utcnow)


class RegistryResponse(BaseModel):
	capabilities: List[Capability]
