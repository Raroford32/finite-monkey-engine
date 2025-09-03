import threading
from typing import Dict, Optional
from datetime import datetime

from defense_agent.utils.models import JobRecord, AnalysisJob, JobStatus


class InMemoryJobStore:
	def __init__(self) -> None:
		self._lock = threading.Lock()
		self._jobs: Dict[str, JobRecord] = {}

	def create(self, job: AnalysisJob) -> JobRecord:
		record = JobRecord(job=job, status=JobStatus.queued)
		with self._lock:
			self._jobs[job.job_id] = record
		return record

	def get(self, job_id: str) -> Optional[JobRecord]:
		with self._lock:
			return self._jobs.get(job_id)

	def update(self, job_id: str, **kwargs) -> Optional[JobRecord]:
		with self._lock:
			record = self._jobs.get(job_id)
			if not record:
				return None
			for k, v in kwargs.items():
				setattr(record, k, v)
			record.updated_at = datetime.utcnow()
			return record
