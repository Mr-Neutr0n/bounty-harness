#!/usr/bin/env python3
"""XS-Leak Probe — uses Playwright to detect cross-origin information leakage via timing differentials."""

import argparse
import json
import os
import sys
import time
import statistics
import tempfile
from datetime import datetime, timezone


def build_parser():
    p = argparse.ArgumentParser(description="Detect cross-site leaks via timing differentials")
    p.add_argument("--url", required=True, help="Target URL to probe")
    p.add_argument("--context", default="default", help="Assessment context label")
    p.add_argument("--output", default=None, help="Output path for findings.jsonl")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--headless", action="store_true", default=True)
    p.add_argument("--trials", type=int, default=15, help="Number of probe trials per test")
    p.add_argument("--threshold", type=float, default=50.0, help="Timing differential threshold in ms")
    p.add_argument("--timeout", type=int, default=15000, help="Navigation timeout in ms")
    return p


XSLEAK_PROBE_PAGE = """<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>XSLeak Probe</title></head>
<body>
<div id="log"></div>
<script>
function log(msg) {
  const el = document.getElementById("log");
  if (el) el.textContent += msg + "\\n";
}

async function probeFrame(url, timeout) {
  return new Promise((resolve) => {
    const start = performance.now();
    const iframe = document.createElement("iframe");
    iframe.style.display = "none";
    iframe.src = url;
    let resolved = false;

    const done = (value) => {
      if (resolved) return;
      resolved = true;
      const elapsed = performance.now() - start;
      try { document.body.removeChild(iframe); } catch (_) {}
      resolve({ elapsed_ms: elapsed, result: value });
    };

    iframe.onload = () => done("loaded");
    iframe.onerror = () => done("error");
    setTimeout(() => done("timeout"), timeout);

    document.body.appendChild(iframe);
  });
}

async function probeObject(url, timeout) {
  return new Promise((resolve) => {
    const start = performance.now();
    const obj = document.createElement("object");
    obj.style.display = "none";
    obj.data = url;
    let resolved = false;

    const done = (value) => {
      if (resolved) return;
      resolved = true;
      const elapsed = performance.now() - start;
      try { document.body.removeChild(obj); } catch (_) {}
      resolve({ elapsed_ms: elapsed, result: value });
    };

    obj.onload = () => done("loaded");
    obj.onerror = () => done("error");
    setTimeout(() => done("timeout"), timeout);

    document.body.appendChild(obj);
  });
}

async function probeEmbed(url, timeout) {
  return new Promise((resolve) => {
    const start = performance.now();
    const embed = document.createElement("embed");
    embed.style.display = "none";
    embed.src = url;
    let resolved = false;

    const done = (value) => {
      if (resolved) return;
      resolved = true;
      const elapsed = performance.now() - start;
      try { document.body.removeChild(embed); } catch (_) {}
      resolve({ elapsed_ms: elapsed, result: value });
    };

    embed.onload = () => done("loaded");
    embed.onerror = () => done("error");
    setTimeout(() => done("timeout"), timeout);

    document.body.appendChild(embed);
  });
}

async function probePostMessage(url, timeout) {
  return new Promise((resolve) => {
    const start = performance.now();
    const iframe = document.createElement("iframe");
    iframe.style.display = "none";
    iframe.src = url;
    let resolved = false;
    let responded = false;

    const done = () => {
      if (resolved) return;
      resolved = true;
      const elapsed = performance.now() - start;
      try { document.body.removeChild(iframe); } catch (_) {}
      resolve({ elapsed_ms: elapsed, result: responded ? "pm_response" : "no_response" });
    };

    const listener = (e) => {
      responded = true;
    };
    window.addEventListener("message", listener, { once: false });

    iframe.onload = () => {
      try { iframe.contentWindow.postMessage("xsleak_probe", "*"); } catch (_) {}
      setTimeout(() => {
        window.removeEventListener("message", listener);
        done();
      }, 500);
    };
    iframe.onerror = () => {
      window.removeEventListener("message", listener);
      done();
    };
    setTimeout(() => {
      window.removeEventListener("message", listener);
      done();
    }, timeout);

    document.body.appendChild(iframe);
  });
}

window.XSLEAK_PROBE = {
  probeFrame, probeObject, probeEmbed, probePostMessage
};
</script>
</body>
</html>"""


def run_timing_test(page, test_name, url, trials, timeout):
    func_name = "probeFrame"
    if test_name == "object_error":
        func_name = "probeObject"
    elif test_name == "embed_error":
        func_name = "probeEmbed"
    elif test_name == "postmessage":
        func_name = "probePostMessage"

    timings = []
    results = []
    errors = 0

    for i in range(trials):
        try:
            result = page.evaluate(
                f"window.XSLEAK_PROBE.{func_name}('{url}', {timeout})"
            )
            timings.append(result.get("elapsed_ms", 0))
            results.append(result.get("result", "unknown"))
        except Exception:
            errors += 1
            continue

        if i < trials - 1:
            time.sleep(0.15)

    if not timings:
        return {"test": test_name, "trials_attempted": trials, "errors": errors, "timings": [], "stats": {}}

    mean_val = statistics.mean(timings)
    stdev_val = statistics.stdev(timings) if len(timings) > 1 else 0.0
    min_val = min(timings)
    max_val = max(timings)
    median_val = statistics.median(timings)

    return {
        "test": test_name,
        "trials_attempted": trials,
        "errors": errors,
        "timings": timings,
        "results_distribution": {r: results.count(r) for r in set(results)},
        "stats": {
            "mean_ms": round(mean_val, 3),
            "median_ms": round(median_val, 3),
            "stdev_ms": round(stdev_val, 3),
            "min_ms": round(min_val, 3),
            "max_ms": round(max_val, 3),
            "range_ms": round(max_val - min_val, 3),
        }
    }


def assess_test(test_result, baseline_mean, threshold):
    stats = test_result.get("stats", {})
    mean_val = stats.get("mean_ms", 0)
    stdev_val = stats.get("stdev_ms", 0)

    if mean_val <= 0:
        return {"leaky": False, "confidence": 0.0, "notes": "No timing data collected"}

    diff = abs(mean_val - baseline_mean)
    conf = min(diff / max(threshold, 1.0), 1.0)

    if diff > threshold and stdev_val < diff * 0.5:
        return {"leaky": True, "confidence": round(conf, 2), "notes": f"Timing differential {diff:.1f}ms exceeds threshold {threshold}ms"}
    elif diff > threshold:
        return {"leaky": True, "confidence": round(conf * 0.7, 2), "notes": f"Timing differential {diff:.1f}ms but high variance (±{stdev_val:.1f}ms)"}
    else:
        return {"leaky": False, "confidence": 0.0, "notes": f"Differential {diff:.1f}ms below threshold"}


def run_probe(url, trials, threshold, timeout, headless, context_label, dry_run):
    finding = {
        "tool": "xsleak_probe",
        "context": context_label,
        "target": url,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tests": [],
        "leaks_detected": [],
        "risk_level": "none",
        "risk_notes": "",
        "errors": [],
    }

    if dry_run:
        finding["dry_run"] = True
        finding["risk_notes"] = "DRY RUN — would navigate target and run timing probes"
        return finding

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        finding["errors"].append("playwright not installed")
        finding["risk_level"] = "unknown"
        finding["risk_notes"] = "Cannot execute: playwright missing"
        return finding

    tmpfile = None
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=headless)
            ctx = browser.new_context()

            tmpfile = tempfile.NamedTemporaryFile(suffix=".html", mode="w", delete=False, prefix="xsleak_")
            tmpfile.write(XSLEAK_PROBE_PAGE)
            tmpfile.flush()
            tmpfile.close()

            page = ctx.new_page()
            page.goto("file://" + tmpfile.name, wait_until="load")

            baselines = {}
            control_page = ctx.new_page()
            control_page.goto("about:blank", wait_until="load")

            for test_name, test_fn in [
                ("frame_count", "probeFrame"),
                ("object_error", "probeObject"),
                ("embed_error", "probeEmbed"),
                ("postmessage", "probePostMessage"),
            ]:
                try:
                    result = page.evaluate(
                        f"window.XSLEAK_PROBE.{test_fn}('about:blank', {timeout})"
                    )
                    baselines[test_name] = result.get("elapsed_ms", 0)
                except Exception as exc:
                    baselines[test_name] = 0
                    finding["errors"].append(f"Baseline {test_name} failed: {exc}")

            time.sleep(0.5)

            test_names = ["frame_count", "object_error", "embed_error", "postmessage"]
            for tn in test_names:
                baseline_ms = baselines.get(tn, 0)
                test_result = run_timing_test(page, tn, url, trials, timeout)
                test_result["baseline_ms"] = baseline_ms

                assessment = assess_test(test_result, baseline_ms, threshold)
                test_result["leak_assessment"] = assessment

                finding["tests"].append(test_result)

                if assessment.get("leaky"):
                    finding["leaks_detected"].append({
                        "test": tn,
                        "confidence": assessment["confidence"],
                        "notes": assessment["notes"],
                    })

            browser.close()
    except Exception as exc:
        finding["errors"].append(f"Probe execution failed: {exc}")
    finally:
        if tmpfile and os.path.exists(tmpfile.name):
            try:
                os.unlink(tmpfile.name)
            except Exception:
                pass

    leak_count = len(finding["leaks_detected"])
    if leak_count >= 2:
        finding["risk_level"] = "high"
        finding["risk_notes"] = f"{leak_count} cross-site leak(s) detected — potential information disclosure"
    elif leak_count == 1:
        finding["risk_level"] = "medium"
        finding["risk_notes"] = "1 potential cross-site leak detected"
    elif finding["errors"]:
        finding["risk_level"] = "unknown"
        finding["risk_notes"] = "Some tests encountered errors"
    else:
        finding["risk_level"] = "low"
        finding["risk_notes"] = "No timing differentials above threshold detected"

    return finding


def main():
    parser = build_parser()
    args = parser.parse_args()

    finding = run_probe(args.url, args.trials, args.threshold, args.timeout, args.headless, args.context, args.dry_run)

    line = json.dumps(finding, default=str)

    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "a") as f:
            f.write(line + "\n")
        print(f"Wrote finding to {args.output}", file=sys.stderr)
    else:
        print(line)
        sys.stdout.flush()


if __name__ == "__main__":
    main()