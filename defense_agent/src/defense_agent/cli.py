import argparse
import json
import sys
from typing import List

sys.path.append('/workspace/defense_agent/src')

from defense_agent.plugins.registry import CapabilityRegistry
from defense_agent.orchestrator.core import Orchestrator
from defense_agent.utils.models import ForkSpec


def cmd_registry() -> None:
	reg = CapabilityRegistry()
	print(json.dumps(reg.list_capabilities(), indent=2))


def cmd_analyze(args: argparse.Namespace) -> None:
	reg = CapabilityRegistry()
	orc = Orchestrator(registry=reg)
	forks: List[ForkSpec] = []
	for pair in args.forks:
		url, cid = pair.split(" ")
		forks.append(ForkSpec(chain_id=int(cid), rpc_url=url))
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


def main() -> None:
	parser = argparse.ArgumentParser(prog="defense-agent")
	sub = parser.add_subparsers(dest="cmd", required=True)

	p_reg = sub.add_parser("registry", help="List capabilities")
	p_reg.set_defaults(func=lambda a=None: cmd_registry())

	p_an = sub.add_parser("analyze", help="Run analysis over forks")
	p_an.add_argument("--target", required=True)
	p_an.add_argument("--fork", dest="forks", action="append", required=True, help="Format: '<RPC_URL> <CHAIN_ID>'")
	p_an.add_argument("--budget", type=int, default=600)
	p_an.add_argument("--cost", type=int, default=100)
	p_an.set_defaults(func=cmd_analyze)

	args = parser.parse_args()
	args.func(args)


if __name__ == "__main__":
	main()
