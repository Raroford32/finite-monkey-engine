import uuid
import threading
from typing import List

from defense_agent.plugins.registry import CapabilityRegistry
from defense_agent.plugins.manager import PluginManager
from defense_agent.utils.safety import Safety
from defense_agent.utils.models import Finding, AnalysisJob, JobStatus, ForkSpec
from defense_agent.orchestrator.jobs import InMemoryJobStore
from defense_agent.harness.fork import ForkEnv
from defense_agent.harness.executor import ForkExecutor
from defense_agent.orchestrator.agent import Agent
from defense_agent.memory.store import MemoryStore


class Orchestrator:
	def __init__(self, registry: CapabilityRegistry):
		self.registry = registry
		self.safety = Safety()
		self.plugins = PluginManager()
		self.jobs = InMemoryJobStore()
        self.memory = MemoryStore()

	def start_job(self, target_name: str, artifact_urls: List[str], budget_seconds: int, max_cost_units: int, forks: List[ForkSpec] | None = None) -> str:
		job_id = str(uuid.uuid4())
		job = AnalysisJob(
			job_id=job_id,
			target_name=target_name,
			artifact_urls=artifact_urls,
			budget_seconds=budget_seconds,
			max_cost_units=max_cost_units,
			forks=forks or [],
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
			# Connectivity checks for provided forks
			for fs in job.forks:
				env = ForkEnv(chain_id=fs.chain_id, rpc_url=fs.rpc_url, block_number=fs.block_number)
				exec = ForkExecutor(env)
				cid = exec.get_chain_id()
				bn = exec.get_block_number()
				if cid == -1 or bn == -1 or cid != fs.chain_id:
					findings.append(Finding(
						id=str(uuid.uuid4()),
						category="infrastructure",
						severity="medium",
						description=f"Fork RPC connectivity issue for chain {fs.chain_id}",
						confidence=0.6,
						artifacts={"rpc_url": fs.rpc_url, "reported_chain_id": str(cid), "block_number": str(bn)},
					))
				else:
					findings.append(Finding(
						id=str(uuid.uuid4()),
						category="infrastructure",
						severity="info",
						description=f"Fork RPC OK for chain {fs.chain_id} at block {bn}",
						confidence=0.9,
						artifacts={"rpc_url": fs.rpc_url, "block_number": str(bn)},
					))
			# Agent plan/act/reflect loop (single iteration for now)
			agent = Agent(memory=self.memory)
			plan = agent.plan(goal=f"Analyze {job.target_name}")
			obs = agent.act(step_hint=plan)
			ref = agent.reflect(observations=obs)

			self.jobs.update(job_id, status=JobStatus.succeeded, findings=findings)
		except Exception as exc:
			self.jobs.update(job_id, status=JobStatus.failed, error_message=str(exc))
