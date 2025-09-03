import argparse
import json
import sys
from typing import List

sys.path.append('/workspace/defense_agent/src')

from defense_agent.plugins.registry import CapabilityRegistry
from defense_agent.orchestrator.core import Orchestrator
from defense_agent.utils.models import ForkSpec
from defense_agent.utils.codebase import read_text_files
from defense_agent.memory.store import MemoryStore
from defense_agent.utils.config import load_dotenv, Settings


def cmd_registry() -> None:
	reg = CapabilityRegistry()
	print(json.dumps(reg.list_capabilities(), indent=2))


def cmd_analyze(args: argparse.Namespace) -> None:
	load_dotenv(args.env)
	reg = CapabilityRegistry()
	orc = Orchestrator(registry=reg)
	settings = Settings.from_env()
	forks: List[ForkSpec] = [ForkSpec(chain_id=f.chain_id, rpc_url=f.rpc_url, block_number=f.block_number) for f in settings.forks]
	job_id = orc.start_job(
		target_name=args.target,
		artifact_urls=[],
		budget_seconds=args.budget,
		max_cost_units=args.cost,
		forks=forks,
	)
	# Wait briefly for background thread to run connectivity
	import time
	time.sleep(1.5)
	rec = orc.jobs.get(job_id)
	print(json.dumps(rec.model_dump(), indent=2, default=str))


def cmd_index(args: argparse.Namespace) -> None:
	load_dotenv(args.env)
	memory = MemoryStore()
	docs = read_text_files(args.path)
	memory.add_documents(docs)
	print(json.dumps({"indexed_files": len(docs)}, indent=2))


def main() -> None:
	parser = argparse.ArgumentParser(prog="defense-agent")
	sub = parser.add_subparsers(dest="cmd", required=True)

	p_reg = sub.add_parser("registry", help="List capabilities")
	p_reg.set_defaults(func=lambda a=None: cmd_registry())

	p_an = sub.add_parser("analyze", help="Run analysis over forks from .env")
	p_an.add_argument("--target", required=True)
	p_an.add_argument("--env", default=".env")
	p_an.add_argument("--budget", type=int, default=600)
	p_an.add_argument("--cost", type=int, default=100)
	p_an.set_defaults(func=cmd_analyze)

	p_ix = sub.add_parser("index", help="Index a local codebase for memory")
	p_ix.add_argument("--env", default=".env")
	p_ix.add_argument("--path", required=True)
	p_ix.set_defaults(func=cmd_index)

	args = parser.parse_args()
	args.func(args)


if __name__ == "__main__":
	main()
