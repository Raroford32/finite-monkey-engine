from typing import List, Dict, Any

from defense_agent.utils.llm import OpenRouterClient
from defense_agent.memory.store import MemoryStore
from defense_agent.plugins.manager import PluginManager


class Agent:
    def __init__(self, memory: MemoryStore, model: str = "openai/gpt-5") -> None:
        self.memory = memory
        self.llm = OpenRouterClient(model=model)
        self.plugins = PluginManager()

    def plan(self, goal: str) -> str:
        if not self.llm.is_configured():
            return "Plan: run invariant miner, then explorer, summarize findings."
        prompt = [
            {"role": "system", "content": "You are a security analysis planner. Output concise steps."},
            {"role": "user", "content": f"Goal: {goal}"},
        ]
        plan = self.llm.chat(prompt, temperature=0.1, max_tokens=256)
        self.memory.add_documents(["PLAN:\n" + plan])
        return plan

    def act(self, step_hint: str) -> Dict[str, Any]:
        # For now, run miner then explorer stubs
        miner = self.plugins.create("InvariantMiner")
        explorer = self.plugins.create("Explorer")
        invariants: List[str] = []
        if miner:
            out = miner.execute({"source_code": "", "bytecode": "", "traces": []})
            invariants = out.get("invariants", [])
        if explorer:
            _ = explorer.execute({"invariants": invariants, "fork_env": None})
        return {"invariants": invariants}

    def reflect(self, observations: Dict[str, Any]) -> str:
        text = f"OBSERVATIONS: {observations}"
        self.memory.add_documents([text])
        if not self.llm.is_configured():
            return "Reflection: Continue exploring edge cases and summarize."
        msg = [
            {"role": "system", "content": "Summarize key observations and next actions."},
            {"role": "user", "content": text},
        ]
        return self.llm.chat(msg, temperature=0.2, max_tokens=200)

