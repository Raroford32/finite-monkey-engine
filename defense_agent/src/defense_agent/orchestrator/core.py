import uuid
import threading
from typing import List

from defense_agent.plugins.registry import CapabilityRegistry
from defense_agent.plugins.manager import PluginManager
from defense_agent.utils.safety import Safety
from defense_agent.utils.models import Finding, AnalysisJob, JobStatus
from defense_agent.orchestrator.jobs import InMemoryJobStore


class Orchestrator:
	def __init__(self, registry: CapabilityRegistry):
		self.registry = registry
		self.safety = Safety()
		self.plugins = PluginManager()
		self.jobs = InMemoryJobStore()

	def start_job(self, target_name: str, artifact_urls: List[str], budget_seconds: int, max_cost_units: int) -> str:
		job_id = str(uuid.uuid4())
		job = AnalysisJob(
			job_id=job_id,
			target_name=target_name,
			artifact_urls=artifact_urls,
			budget_seconds=budget_seconds,
			max_cost_units=max_cost_units,
		)
		self.jobs.create(job)
		thread = threading.Thread(target=self._run_pipeline, args=(job.job_id,), daemon=True)
		thread.start()
		return job.job_id

	def _run_pipeline(self, job_id: str) -> None:
		self.jobs.update(job_id, status=JobStatus.running)
		record = self.jobs.get(job_id)
		if not record:
			return
		job = record.job
		findings: List[Finding] = []
		try:
			# Planner (stub)
			invariants: List[str] = []
			miner = self.plugins.create("InvariantMiner")
			if miner:
				out = miner.execute({"source_code": "", "bytecode": "", "traces": []})
				invariants = out.get("invariants", [])

			# Explorer (stub)
			explorer = self.plugins.create("Explorer")
			if explorer:
				_ = explorer.execute({"invariants": invariants, "fork_env": None})

			self.jobs.update(job_id, status=JobStatus.succeeded, findings=findings)
		except Exception as exc:
			self.jobs.update(job_id, status=JobStatus.failed, error_message=str(exc))
