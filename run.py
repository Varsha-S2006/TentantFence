import argparse
import asyncio
import json
import uuid

import httpx

from engine.executor import ensure_local_target, execute_scan
from engine.policy import load_policy


async def run(args: argparse.Namespace) -> int:
    policy = load_policy()
    if args.target_url:
        policy["target_url"] = args.target_url.rstrip("/")
    ensure_local_target(policy["target_url"])

    if args.mode:
        async with httpx.AsyncClient(
            base_url=policy["target_url"], timeout=5
        ) as client:
            response = await client.post("/admin/mode", json={"mode": args.mode})
            response.raise_for_status()

    report = await execute_scan(str(uuid.uuid4()), policy)
    print(json.dumps(report.as_dict(), indent=2))
    return 1 if args.fail_on_findings and report.findings else 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the TenantFence authorization suite")
    parser.add_argument("--target-url", help="Loopback API base URL (default: policy.json)")
    parser.add_argument("--mode", choices=("vulnerable", "secure"))
    parser.add_argument(
        "--fail-on-findings",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Exit with status 1 when findings are present",
    )
    args = parser.parse_args()
    raise SystemExit(asyncio.run(run(args)))


if __name__ == "__main__":
    main()
