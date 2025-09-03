from __future__ import annotations
from typing import List, Optional, Dict
from pydantic import BaseModel, Field

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

class AnalysisJob(BaseModel):
	job_id: str
	target_name: str
	artifact_urls: List[str]
	budget_seconds: int
	max_cost_units: int

class RegistryResponse(BaseModel):
	capabilities: List[Capability]
