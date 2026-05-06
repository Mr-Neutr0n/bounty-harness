#!/usr/bin/env python3
"""WebGPU Fingerprinting Surface Probe — uses Playwright to enumerate GPU adapters and limits."""

import argparse
import json
import sys
import time
import os
from datetime import datetime, timezone


def build_parser():
    p = argparse.ArgumentParser(description="Probe WebGPU fingerprinting surface on a target URL")
    p.add_argument("--url", required=True, help="Target URL to probe")
    p.add_argument("--context", default="default", help="Assessment context label")
    p.add_argument("--output", default=None, help="Output path for findings.jsonl (default: stdout)")
    p.add_argument("--dry-run", action="store_true", help="Show what would be done without executing")
    p.add_argument("--timeout", type=int, default=30000, help="Page navigation timeout in ms")
    p.add_argument("--headless", action="store_true", default=True, help="Run browser in headless mode")
    return p


WEBGPU_PROBE_JS = r"""
(async () => {
  const result = {
    gpu_available: false,
    timestamp: new Date().toISOString(),
    adapter_info: null,
    adapter_limits: null,
    adapter_features: [],
    adapter_count: 0,
    adapter_details: [],
    errors: []
  };

  if (typeof navigator === "undefined" || !navigator.gpu) {
    result.errors.push("navigator.gpu not available");
    return result;
  }

  result.gpu_available = true;

  try {
    const adapter = await navigator.gpu.requestAdapter();
    if (!adapter) {
      result.errors.push("requestAdapter returned null — no GPU adapter found");
      return result;
    }

    result.adapter_count = 1;

    const info = await adapter.requestAdapterInfo();
    result.adapter_info = {
      vendor: info.vendor || "",
      architecture: info.architecture || "",
      device: info.device || "",
      description: info.description || ""
    };

    result.adapter_limits = {};
    if (adapter.limits) {
      for (const [key, value] of Object.entries(adapter.limits)) {
        result.adapter_limits[key] = value;
      }
    }

    result.adapter_features = [];
    if (adapter.features) {
      try {
        for (const feat of adapter.features) {
          result.adapter_features.push(feat);
        }
      } catch (_) {}
    }

    result.adapter_details.push({
      is_fallback: adapter.isFallbackAdapter || false,
      info: result.adapter_info,
      limits: result.adapter_limits,
      features: result.adapter_features
    });

    const fingerprintable = {};
    const sensitive = ["vendor", "architecture", "device", "description"];
    for (const key of sensitive) {
      if (result.adapter_info[key]) {
        fingerprintable[key] = result.adapter_info[key];
      }
    }
    if (result.adapter_limits && Object.keys(result.adapter_limits).length > 0) {
      const notable = [
        "maxTextureDimension1D", "maxTextureDimension2D", "maxTextureDimension3D",
        "maxTextureArrayLayers", "maxBindGroups", "maxBindingsPerBindGroup",
        "maxDynamicUniformBuffersPerPipelineLayout",
        "maxDynamicStorageBuffersPerPipelineLayout",
        "maxSampledTexturesPerShaderStage", "maxSamplersPerShaderStage",
        "maxStorageBuffersPerShaderStage", "maxStorageTexturesPerShaderStage",
        "maxUniformBuffersPerShaderStage", "maxUniformBufferBindingSize",
        "maxStorageBufferBindingSize", "minUniformBufferOffsetAlignment",
        "minStorageBufferOffsetAlignment", "maxVertexBuffers",
        "maxBufferSize", "maxVertexAttributes", "maxVertexBufferArrayStride",
        "maxInterStageShaderComponents", "maxInterStageShaderVariables",
        "maxColorAttachments", "maxColorAttachmentBytesPerSample",
        "maxComputeWorkgroupStorageSize", "maxComputeInvocationsPerWorkgroup",
        "maxComputeWorkgroupSizeX", "maxComputeWorkgroupSizeY", "maxComputeWorkgroupSizeZ",
        "maxComputeWorkgroupsPerDimension"
      ];
      result.fingerprinting_limits = {};
      for (const key of notable) {
        if (result.adapter_limits[key] !== undefined) {
          result.fingerprinting_limits[key] = result.adapter_limits[key];
        }
      }
    }

    result.fingerprinting_surface = {
      gpu_available: true,
      adapter_info_fingerprintable: fingerprintable,
      limits_fingerprintable: result.fingerprinting_limits || {},
      feature_count: result.adapter_features.length,
      unique_feature_ids: result.adapter_features.slice(0, 50)
    };

  } catch (e) {
    result.errors.push("GPU enumeration error: " + e.message);
  }

  return result;
})()
"""


def compute_risk_summary(data):
    risk = "none"
    surface = data.get("fingerprinting_surface", {})
    if not surface.get("gpu_available"):
        return {"risk_level": "none", "risk_notes": "WebGPU not available — no fingerprinting surface"}
    risk = "low"
    notes = []
    fp_info = surface.get("adapter_info_fingerprintable", {})
    if len(fp_info) >= 2:
        risk = "medium"
        notes.append("Multiple GPU adapter info fields exposed for fingerprinting")
    fp_limits = surface.get("limits_fingerprintable", {})
    if len(fp_limits) > 5:
        risk = "medium"
        notes.append(f"GPU limits expose {len(fp_limits)} unique fields")
    if len(fp_info) >= 3 and len(fp_limits) > 5:
        risk = "high"
        notes.append("Rich GPU fingerprinting surface — adapter info + detailed limits exposed")
    feature_count = surface.get("feature_count", 0)
    if feature_count > 10:
        notes.append(f"{feature_count} GPU features enumerable")
    return {"risk_level": risk, "risk_notes": "; ".join(notes) if notes else "Minimal fingerprinting surface"}


def run_probe(url, timeout, headless, context_label, dry_run):
    finding = {
        "tool": "webgpu_probe",
        "context": context_label,
        "target": url,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "gpu_available": False,
        "adapter_info": None,
        "fingerprinting_surface": None,
        "risk_level": "none",
        "errors": []
    }

    if dry_run:
        finding["dry_run"] = True
        finding["risk_notes"] = "DRY RUN — would navigate to URL and probe navigator.gpu"
        return finding

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        finding["errors"].append("playwright not installed — pip install playwright && playwright install chromium")
        finding["risk_level"] = "unknown"
        finding["risk_notes"] = "Could not execute: playwright missing"
        return finding

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=headless)
            page = browser.new_page()
            page.goto(url, timeout=timeout, wait_until="domcontentloaded")
            time.sleep(1)

            raw = page.evaluate(WEBGPU_PROBE_JS)

            finding["gpu_available"] = raw.get("gpu_available", False)
            finding["adapter_info"] = raw.get("adapter_info")
            finding["adapter_limits"] = raw.get("adapter_limits")
            finding["adapter_features"] = raw.get("adapter_features")
            finding["fingerprinting_surface"] = raw.get("fingerprinting_surface")
            finding["errors"] = raw.get("errors", [])
            finding["adapter_count"] = raw.get("adapter_count", 0)

            risk = compute_risk_summary(raw)
            finding["risk_level"] = risk["risk_level"]
            finding["risk_notes"] = risk["risk_notes"]

            browser.close()
    except Exception as exc:
        finding["errors"].append(f"Probe execution failed: {exc}")
        finding["risk_level"] = "unknown"
        finding["risk_notes"] = f"Execution error: {exc}"

    return finding


def main():
    parser = build_parser()
    args = parser.parse_args()

    finding = run_probe(args.url, args.timeout, args.headless, args.context, args.dry_run)

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