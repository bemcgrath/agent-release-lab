"""Opt-in external validation on all five isolated Ledger Finch scenarios."""

import argparse
import json
from decimal import Decimal, InvalidOperation
from os import environ
from pathlib import Path

from ..demo import demo
from .contracts import ReviewerConfig, ReviewerProvider
from .providers import ChatCompletions


SCENARIOS = ("ready", "blocked", "suspicious", "conflict", "approved")


def run_smoke(config: ReviewerConfig, provider: ReviewerProvider, input_rate: Decimal, output_rate: Decimal,
              *, scenario: str | None = None) -> list[dict]:
    scenarios = SCENARIOS if scenario is None else (scenario,)
    if scenario is not None and scenario not in SCENARIOS:
        raise ValueError("Unknown Ledger Finch scenario")
    if len(scenarios) * config.max_total_tokens > config.cumulative_token_budget:
        raise ValueError("The cumulative budget must cover the selected scenario reservations")
    remaining = config.cumulative_token_budget
    reports = []
    for scenario in scenarios:
        if remaining < config.max_total_tokens:
            reports.append({"scenario": scenario, "status": "unavailable", "reason": "cumulative_budget_exceeded"})
            continue

        def project(_governance, store, actor, assessment_id):
            return store.run(actor, assessment_id, config, provider)

        record = demo(scenario, project, include_fake_review=False)["detail"]
        usage = record["usage"]
        cost = None
        if usage["source"] != "unknown":
            cost = (
                input_rate * usage["input_tokens"] + output_rate * usage["output_tokens"]
            ) / Decimal(1000000)
        remaining -= record["budget"]["charged_tokens"]
        reports.append({"scenario": scenario, "estimated_cost_usd": str(cost) if cost is not None else None,
                        **record})
    return reports


def rate(value: str) -> Decimal:
    try:
        number = Decimal(value)
    except InvalidOperation as error:
        raise argparse.ArgumentTypeError("Rate must be a nonnegative USD amount per million tokens") from error
    if not number.is_finite() or number < 0:
        raise argparse.ArgumentTypeError("Rate must be a nonnegative USD amount per million tokens")
    return number


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-charges", action="store_true", help="Confirm maintainer authorization for billable calls")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--scenario", choices=SCENARIOS, help="Limit the smoke run to one scenario")
    parser.add_argument("--input-usd-per-million", type=rate, required=True)
    parser.add_argument("--output-usd-per-million", type=rate, required=True)
    args = parser.parse_args()
    if not args.allow_charges:
        parser.error("Maintainer authorization and --allow-charges are required before any external call")
    try:
        config = ReviewerConfig.from_json(args.config.read_bytes())
        if config.provider != "chat-completions":
            parser.error("Live smoke requires the chat-completions provider")
        provider = ChatCompletions(config.endpoint, environ.get("AGENT_RELEASE_LAB_REVIEWER_TOKEN"))
        reports = run_smoke(config, provider, args.input_usd_per_million, args.output_usd_per_million,
                            scenario=args.scenario)
    except (OSError, ValueError, RecursionError):
        parser.error("Live smoke configuration or budget is invalid")
    print(json.dumps({"schema_version": 1, "scenarios": reports}, indent=2))
    return 0 if all(report["status"] == "completed" for report in reports) else 1


if __name__ == "__main__":
    raise SystemExit(main())
