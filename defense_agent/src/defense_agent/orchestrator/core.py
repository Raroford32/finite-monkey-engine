import uuid
from typing import List

from defense_agent.plugins.registry import CapabilityRegistry
from defense_agent.utils.safety import Safety
from defense_agent.utils.models import Finding, AnalysisJob

class Orchestrator:
	def __init__(self, registry: CapabilityRegistry):
		self.registry = registry
		self.safety = Safety()

	def start_job(self, target_name: str, artifact_urls: List[str], budget_seconds: int, max_cost_units: int) -> str:
		job_id = str(uuid.uuid4())
		job = AnalysisJob(
			job_id=job_id,
			target_name=target_name,
			artifact_urls=artifact_urls,
			budget_seconds=budget_seconds,
			max_cost_units=max_cost_units,
		)
		# Planner: create initial hypotheses (stub)
		# Explorer: schedule exploration (stub)
		# Verifier/Economist: validate findings (stub)
		# Judge: gate outputs (stub)
		# Reporter: persist report (stub)
		return job.job_id

	def run_planner(self, job: AnalysisJob) -> None:
		pass

	def run_explorer(self, job: AnalysisJob) -> List[Finding]:
		return []

	def run_verifier(self, job: AnalysisJob, findings: List[Finding]) -> List[Finding]:
		return findings
