#!/usr/bin/env python3
"""OOB Integration Helper — inject canary URLs into payloads and retrieve callbacks.

Used by other skills (api, ssrf, sqli, xss) to automatically:
  1. Get a fresh canary URL
  2. Inject it into a payload template
  3. Optionally poll for callbacks

Usage:
    oob_integration.py inject --template '{{CANARY}}' --purpose ssrf-test --test-id api-001
    oob_integration.py poll --wait 30
    oob_integration.py inject-and-poll --template '{{CANARY}}' --purpose xss-test --wait 60
"""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

OOB_DIR = Path(".bb/oob")
SESSION_FILE = OOB_DIR / "session.json"
CANARIES_FILE = OOB_DIR / "canaries.jsonl"
INTERACTIONS_FILE = OOB_DIR / "interactions.jsonl"
CORRELATION_FILE = OOB_DIR / "correlation.jsonl"


def log(msg: str) -> None:
    print(f"[{datetime.now(timezone.utc).isoformat()}] {msg}", file=sys.stderr)


def get_canary(purpose: str, test_id: str) -> dict:
    """Generate a new canary and return its details."""
    OOB_DIR.mkdir(parents=True, exist_ok=True)
    if not SESSION_FILE.exists():
        log("No OOB session found. Run 'bb-run oob-infra auto-setup' first.")
        sys.exit(1)

    script = Path(".claude/skills/oob-infra/scripts/oob_manager.py")
    result = subprocess.run(
        [
            sys.executable, str(script),
            "--action", "canary",
            "--session", str(SESSION_FILE),
            "--purpose", purpose,
            "--test-id", test_id,
            "--output", str(CANARIES_FILE),
        ],
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        log(f"Canary generation failed: {result.stderr}")
        sys.exit(1)
    data = json.loads(result.stdout)
    return data


def poll_once() -> list:
    """Poll for interactions once."""
    script = Path(".claude/skills/oob-infra/scripts/oob_manager.py")
    result = subprocess.run(
        [
            sys.executable, str(script),
            "--action", "poll",
            "--session", str(SESSION_FILE),
            "--output", str(INTERACTIONS_FILE),
        ],
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        log(f"Poll failed: {result.stderr}")
        return []
    data = json.loads(result.stdout)
    return data.get("interactions", [])


def correlate() -> dict:
    """Correlate interactions with canaries."""
    script = Path(".claude/skills/oob-infra/scripts/oob_manager.py")
    result = subprocess.run(
        [
            sys.executable, str(script),
            "--action", "correlate",
            "--canaries", str(CANARIES_FILE),
            "--interactions", str(INTERACTIONS_FILE),
            "--output", str(CORRELATION_FILE),
        ],
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        log(f"Correlation failed: {result.stderr}")
        return {}
    return json.loads(result.stdout)


def inject_payload(template: str, purpose: str, test_id: str) -> str:
    """Inject a canary URL into a payload template."""
    canary_data = get_canary(purpose, test_id)
    canary_url = canary_data.get("url", "")
    if not canary_url:
        log("Failed to get canary URL")
        sys.exit(1)
    injected = template.replace("{{CANARY}}", canary_url)
    injected = injected.replace("{{CANARY_HTTP}}", f"http://{canary_url}")
    injected = injected.replace("{{CANARY_HTTPS}}", f"https://{canary_url}")
    injected = injected.replace("{{CANARY_DNS}}", canary_url)
    print(json.dumps({
        "canary_url": canary_url,
        "injected_payload": injected,
        "purpose": purpose,
        "test_id": test_id,
    }, indent=2))
    return injected


def poll_and_wait(wait_seconds: int = 60) -> dict:
    """Poll repeatedly for a set duration."""
    log(f"Polling for {wait_seconds} seconds...")
    start = time.time()
    all_interactions = []
    while time.time() - start < wait_seconds:
        count = poll_once()
        all_interactions.extend(count)
        time.sleep(10)
    result = correlate()
    result["total_interactions"] = len(all_interactions)
    return result


def main():
    parser = argparse.ArgumentParser(description="OOB Integration Helper")
    sub = parser.add_subparsers(dest="command", help="Commands")

    p_inject = sub.add_parser("inject", help="Inject canary into payload template")
    p_inject.add_argument("--template", required=True, help="Payload template with {{CANARY}} placeholder")
    p_inject.add_argument("--purpose", required=True, help="Canary purpose label")
    p_inject.add_argument("--test-id", required=True, help="Test case ID")

    p_poll = sub.add_parser("poll", help="Poll for callbacks")
    p_poll.add_argument("--wait", type=int, default=30, help="Seconds to wait/poll")

    p_both = sub.add_parser("inject-and-poll", help="Inject canary and poll for callbacks")
    p_both.add_argument("--template", required=True, help="Payload template")
    p_both.add_argument("--purpose", required=True, help="Canary purpose")
    p_both.add_argument("--test-id", required=True, help="Test case ID")
    p_both.add_argument("--wait", type=int, default=60, help="Seconds to poll")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "inject":
        inject_payload(args.template, args.purpose, args.test_id)

    elif args.command == "poll":
        result = poll_and_wait(args.wait)
        print(json.dumps(result, indent=2))

    elif args.command == "inject-and-poll":
        inject_payload(args.template, args.purpose, args.test_id)
        result = poll_and_wait(args.wait)
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
