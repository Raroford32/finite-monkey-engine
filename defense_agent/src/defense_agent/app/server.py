from fastapi import FastAPI, HTTPException
from fastapi.responses import ORJSONResponse
from pydantic import BaseModel, Field
from typing import List, Optional

from defense_agent.orchestrator.core import Orchestrator
from defense_agent.plugins.registry import CapabilityRegistry
from defense_agent.utils.models import JobRecord

app = FastAPI(title="Defense Agent", default_response_class=ORJSONResponse)
registry = CapabilityRegistry()
orchestrator = Orchestrator(registry=registry)

class AnalyzeRequest(BaseModel):
	target_name: str = Field(..., description="Human-readable target identifier")
	artifact_urls: List[str] = Field(default_factory=list, description="User-provided code/binary URLs")
	scope_token: str = Field(..., description="Authorization token for allowed targets")
	budget_seconds: int = Field(600, ge=60, le=14400)
	max_cost_units: int = Field(100, ge=1, le=10000)

class AnalyzeResponse(BaseModel):
	job_id: str
	message: str

@app.get("/registry")
def get_registry():
	return registry.list_capabilities()

@app.post("/analyze", response_model=AnalyzeResponse)
def start_analysis(req: AnalyzeRequest):
	if not orchestrator.safety.is_scope_authorized(req.scope_token, req.target_name):
		raise HTTPException(status_code=403, detail="Unauthorized scope")
	job_id = orchestrator.start_job(
		target_name=req.target_name,
		artifact_urls=req.artifact_urls,
		budget_seconds=req.budget_seconds,
		max_cost_units=req.max_cost_units,
	)
	return AnalyzeResponse(job_id=job_id, message="Job started")

@app.get("/jobs/{job_id}", response_model=JobRecord)
def get_job_status(job_id: str):
	record = orchestrator.jobs.get(job_id)
	if record is None:
		raise HTTPException(status_code=404, detail="Job not found")
	return record
