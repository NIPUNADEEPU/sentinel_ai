# ruff: noqa
# Copyright 2026 Google LLC
# SentinelAI Enterprise DevSecOps Core Engine

import os
import re
from typing import Dict, List, Literal
from pydantic import BaseModel, Field
from google import genai

import config

os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "False"

# Initialize standard client
try:
    ai_client = genai.Client(api_key=config.GEMINI_API_KEY)
except Exception:
    ai_client = None

class SentinelState(BaseModel):
    source_code: str = Field(default="")
    file_name: str = Field(default="app.py")
    vulnerabilities_found: List[Dict[str, str]] = Field(default_factory=list)
    risk_score: int = Field(default=0)
    risk_level: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = Field(default="LOW")
    ai_report: str = Field(default="")
    scan_report: str = Field(default="")
    waiting_for_input: bool = Field(default=False)
    rollback_counter: int = Field(default=0)
    current_status: str = Field(default="Initialized")

def scan_code_base(source_code: str) -> dict:
    flags = []
    score = 0

    # 1. Catch ASCII Shifting and character arrays mixed with global namespace lookups
    if ("chr(" in source_code or "ord(" in source_code) and ("globals()" in source_code or "locals()" in source_code):
        flags.append("🚨 CRITICAL: Cryptic Obfuscation Detection (Dynamic Namespace Resolution via Byte Array)")
        score += 85

    # 2. Existing standard rules
    if "chr(ord(" in source_code or "ord(c)" in source_code:
        flags.append("🚨 CRITICAL: Cryptic Obfuscation Detection (ASCII Shifting/Cipher Hiding Input)")
        score += 50

    if re.search(r"\bimport\s+(socket|Crypto|cryptography)\b", source_code):
        flags.append("⚠️ HIGH RISK: Unauthorized Core Modules (Potential Reverse Shell Socket or Ransomware Encryption Hook)")
        score += 30

    if "exec(" in source_code or "eval(" in source_code:
        flags.append("🚨 CRITICAL: Arbitrary Code Injection Vector (Dynamic Execution using eval/exec)")
        score += 50

    if ".py" in source_code and ("inject" in source_code or "write" in source_code) and "os.listdir" in source_code:
        flags.append("🚨 CRITICAL: Self-Replicating File Injection Profile (Worm/Virus behavior mimicking)")
        score += 60

    if "pynput" in source_code or "ImageGrab" in source_code or "requests.post" in source_code:
        flags.append("⚠️ HIGH RISK: Spyware/Surveillance Indicators (Keylogging or Active Screen Grab Data Exfiltration)")
        score += 40

    secret_pattern = re.compile(r'(api_key|secret|password|token)\s*=\s*["\'][A-Za-z0-9_\-]{8,}["\']', re.IGNORECASE)
    if secret_pattern.search(source_code):
        flags.append("⚠️ HIGH RISK: Hardcoded Secret Exposed")
        score += 45

    # Clamp scores properly
    if score > 100:
        score = 100
    elif score == 0:
        score = 10

    return {"flags": flags, "score": score}


def security_analysis_node(state: SentinelState) -> SentinelState:
    print("[*] Running Multilayered Security Inspection Engine...")
    scan_metrics = scan_code_base(state.source_code)
    state.risk_score = scan_metrics["score"]
    state.vulnerabilities_found = [{"type": flag, "severity": "HIGH" if "HIGH" in flag else "CRITICAL"} for flag in scan_metrics["flags"]]
    
    analysis_prompt = f"""
    You are an Elite Enterprise DevSecOps Agent. Analyze this source code payload for compliance risks.
    DETERMINISTIC ANALYSIS FLAGS IDENTIFIED: {", ".join(scan_metrics["flags"]) if scan_metrics["flags"] else "None"}
    SOURCE CODE ENVELOPE: {state.source_code}
    Provide a technical markdown report identifying vulnerabilities and detailing remediation steps.
    """
    
    try:
        if ai_client is None:
            raise ValueError("Client not configured")
        ai_response = ai_client.models.generate_content(
            model="gemini-2.0-flash",
            contents=analysis_prompt
        )
        state.ai_report = ai_response.text
        state.scan_report = ai_response.text
    except Exception as e:
        if scan_metrics["flags"]:
            fallback_msg = f"### ⚠️ Heuristic Threat Alert (Deterministic Engine Match)\n\nAnomalies were intercepted prior to container compilation.\n\n**Identified Structural Flags:**\n" + "\n".join([f"- {flag}" for flag in scan_metrics["flags"]])
        else:
            fallback_msg = "### ✅ Code Base Evaluation Clear\n\nNo deterministic malware signatures or exposed secrets were uncovered during this pass layer."
        state.ai_report = fallback_msg
        state.scan_report = fallback_msg

    if state.risk_score >= 50:
        state.risk_level = "HIGH"
        state.current_status = "⏸️ Blocked: Awaiting Senior Security Approval"
    elif state.risk_score >= 30:
        state.risk_level = "MEDIUM"
        state.current_status = "Conditional Approval Path Triggered"
    else:
        state.risk_level = "LOW"
        state.current_status = "✅ System Live and Verified Healthy."
        
    return state

def decision_router_node(state: SentinelState) -> str:
    if state.risk_level in ["CRITICAL", "HIGH"]:
        return "human_triage_path"
    elif state.risk_level == "MEDIUM":
        return "conditional_approval_path"
    else:
        return "safe_deployment_path"

def human_triage_node(state: SentinelState) -> SentinelState:
    state.current_status = "⏸️ Blocked: Awaiting Senior Security Review"
    state.waiting_for_input = True
    return state

def deploy_and_monitor_node(state: SentinelState) -> SentinelState:
    if state.rollback_counter > 1:
        state.current_status = "❌ Rollback Loop Detected. Terminating to save token costs."
        return state
        
    if "mock_crash" in state.source_code:
        state.rollback_counter += 1
        state.current_status = f"⚠️ Runtime Error Tracked. Rolling back (Attempt #{state.rollback_counter})"
    else:
        state.current_status = "✅ System Live and Verified Healthy."
    return state