import os
from dataclasses import dataclass, field
from typing import List


def load_dotenv(path: str = ".env") -> None:
    if not os.path.isfile(path):
        # also try cwd/.env
        alt = os.path.join(os.getcwd(), ".env")
        if os.path.isfile(alt):
            path = alt
        else:
            return
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                if "=" not in s:
                    continue
                k, v = s.split("=", 1)
                k = k.strip()
                v = v.strip().strip('"').strip("'")
                os.environ.setdefault(k, v)
    except Exception:
        return


@dataclass
class ForkConfig:
    rpc_url: str
    chain_id: int
    block_number: int | None = None


@dataclass
class Settings:
    openrouter_api_key: str = ""
    model_name: str = "openai/gpt-5"
    forks: List[ForkConfig] = field(default_factory=list)

    @staticmethod
    def from_env() -> "Settings":
        key = os.getenv("OPENROUTER_API_KEY", "").strip()
        model = os.getenv("MODEL_NAME", "openai/gpt-5").strip()
        forks_env = os.getenv("FORKS", "").strip()
        forks: List[ForkConfig] = []
        # Expected format: FORKS="<url> <chainId>[ @block];<url> <chainId>"
        # Example: FORKS="https://eth... 1;https://bnb... 56"
        if forks_env:
            for item in forks_env.split(";"):
                s = item.strip()
                if not s:
                    continue
                # support optional @block at end
                parts = s.split()
                if len(parts) < 2:
                    continue
                url = parts[0]
                cid_part = parts[1]
                block = None
                if len(parts) >= 3 and parts[2].startswith("@"):
                    try:
                        block = int(parts[2][1:])
                    except Exception:
                        block = None
                try:
                    cid = int(cid_part)
                except Exception:
                    continue
                forks.append(ForkConfig(rpc_url=url, chain_id=cid, block_number=block))
        # Alternatively support ETH_RPC_URL/ETH_CHAIN_ID etc. (ETH, BNB prefixes)
        for prefix in ["ETH", "BNB", "POLY", "ARB", "OPT"]:
            url = os.getenv(f"{prefix}_RPC_URL", "").strip()
            cid = os.getenv(f"{prefix}_CHAIN_ID", "").strip()
            blk = os.getenv(f"{prefix}_BLOCK_NUMBER", "").strip()
            if url and cid.isdigit():
                forks.append(ForkConfig(rpc_url=url, chain_id=int(cid), block_number=int(blk) if blk.isdigit() else None))
        return Settings(openrouter_api_key=key, model_name=model, forks=forks)

