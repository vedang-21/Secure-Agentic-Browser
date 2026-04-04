"""Run the firewall analyzers against a static HTML file.

Usage:
  python scripts/run_dom_threat_check.py files/vul1.html --goal "Track shipment"

This runs:
- DOMAnalyzer
- NLPThreatClassifier (visible + hidden text)
- (optional) LLMThreatReasoner via SecurityMediator when risk crosses threshold

Note: LLM layer requires GEMINI_API_KEY (or config gemini_api_key).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

# Allow running as a script without installing the repo as a package
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from firewall.core.security_mediator import SecurityMediator


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("html_path", type=str, help="Path to a local HTML file")
    parser.add_argument("--goal", type=str, default="", help="Agent goal (used for prompt-injection context)")
    parser.add_argument(
        "--no-llm",
        action="store_true",
        help="Disable the LLM layer even if risk exceeds threshold",
    )
    parser.add_argument(
        "--llm-threshold",
        type=float,
        default=0.4,
        help="Risk threshold above which the LLM layer is used",
    )
    args = parser.parse_args()

    html_file = Path(args.html_path).expanduser().resolve()
    if not html_file.exists() or not html_file.is_file():
        raise SystemExit(f"HTML file not found: {html_file}")

    html = html_file.read_text(encoding="utf-8", errors="replace")

    mediator = SecurityMediator(
        {
            "use_llm_layer": not args.no_llm,
            "llm_threshold": args.llm_threshold,
            # API key is picked up via GEMINI_API_KEY env var by default
            "gemini_api_key": None,
        }
    )

    report = mediator.analyze_page(page_content=html, agent_goal=args.goal)

    # Stable, machine-readable output
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
