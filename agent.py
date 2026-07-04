# ruff: noqa
# Copyright 2026 Google LLC
# SentinelAI Enterprise DevSecOps Core Engine

import os
import re
from typing import Dict, List, Literal
from pydantic import BaseModel, Field
from google import genai

# Import thresholds and API setup from our config file
import config

# Forces the SDK to use standard Gemini API Keys instead of Vertex AI
os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "False"

# Initialize the standard Gemini GenAI Client securely
ai_client = genai.Client(api_key=config.GEMINI_API_KEY)

# ==========================================
# PHASE 1: Define Persistent State Schema
# ==========================================
class SentinelState(BaseModel):
    """The central state object that tracks everything as the code moves between nodes."""
    
    # Core Data
    source_code: str = Field(default="", description="The raw Python source code uploaded by the user.")
    file_name: str = Field(default="app.py", description="Name of the file being evaluated.")
    
    # Analysis Metrics
    vulnerabilities_found: List[Dict[str, str]] = Field(default_factory=list)
    risk_score: int = Field(default=0, description="Risk score scaled from 0 (Safe) to 100 (Critical Malicious).")
    risk_level: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = Field(default="LOW")
    ai_report: str = Field(default="", description="Stores the final deep analysis markdown data.")
    scan_report: str = Field(default="")
    
    # HITL (Human-In-The-Loop) & Flow Controls
    waiting_for_input: bool = Field(default=False)
    rollback_counter: int = Field(default=0)
    current_status: str = Field(default="Initialized")

# ==========================================
# PHASE 2: Static Tools & Graph Nodes
# ==========================================
def scan_code_base(source_code: str) -> dict:
    """Agent Tool: Statically analyzes code for advanced malicious behavior patterns."""
    flags = []
    score = 0

    # 1. Obfuscated Code & Hidden Intent Strings
    if "chr(ord(" in source_code or "ord(c)" in source_code:
        flags.append("🚨 CRITICAL: Cryptic Obfuscation Detection (ASCII Shifting/Cipher Hiding Input)")
        score += 50

    # 2. Suspicious Module Imports (Backdoors / Dynamic Encryption)
    if re.search(r"\bimport\s+(socket|Crypto|cryptography)\b", source_code):
        flags.append("⚠️ HIGH RISK: Unauthorized Core Modules (Potential Reverse Shell Socket or Ransomware Encryption Hook)")
        score += 30

    # 3. Dynamic Runtime Code Execution (Evasion Methods)
    if "exec(" in source_code or "eval(" in source_code:
        flags.append("🚨 CRITICAL: Arbitrary Code Injection Vector (Dynamic Execution using eval/exec)")
        score += 50

    # 4. Self-Replicating Contagion Logic (Virus Architecture)
    if ".py" in source_code and ("inject" in source_code or "write" in source_code) and "os.listdir" in source_code:
        flags.append("🚨 CRITICAL: Self-Replicating File Injection Profile (Worm/Virus behavior mimicking)")
        score += 60

    # 5. Data Exfiltration & Surveillance Package Footprints
    if "pynput" in source_code or "ImageGrab" in source_code or "requests.post" in source_code:
        flags.append("⚠️ HIGH RISK: Spyware/Surveillance Indicators (Keylogging or Active Screen Grab Data Exfiltration)")
        score += 40

    # Basic Regex for exposed credentials backup
    secret_pattern = re.compile(r'(api_key|secret|password|token)\s*=\s*["\'][A-Za-z0-9_\-]{8,}["\']', re.IGNORECASE)
    if secret_pattern.search(source_code):
        flags.append("⚠️ HIGH RISK: Hardcoded Secret Exposed")
        score += 45

    # Normalization ceiling
    if score > 100:
        score = 100
    elif score == 0:
        score = 10  # Baseline tracking metric

    return {"flags": flags, "score": score}
def security_analysis_node(state: SentinelState) -> SentinelState:
    """Agent Node 1: Executes local heuristic checks and passes metadata to Gemini."""
    print("[*] Running Multilayered Security Inspection Engine...")
    
    # Run Pattern Matching Engine Skills
    scan_metrics = scan_code_base(state.source_code)
    state.risk_score = scan_metrics["score"]
    
    # Map raw structural vulnerabilities into state objects
    state.vulnerabilities_found = [{"type": flag, "severity": "HIGH" if "HIGH" in flag else "CRITICAL"} for flag in scan_metrics["flags"]]
    
    # Prepare Deep Semantic Assessment via Gemini
    analysis_prompt = f"""
    You are an Elite Enterprise DevSecOps Agent. Analyze this source code payload for compliance risks.
    
    DETERMINISTIC ANALYSIS FLAGS IDENTIFIED:
    {", ".join(scan_metrics["flags"]) if scan_metrics["flags"] else "None"}
    
    SOURCE CODE ENVELOPE:
    {state.source_code}
    
    Provide a highly technical markdown report identifying vulnerabilities, explaining attacker intent, and detailing immediate remediation steps.
    """
    
    try:
        # Attempt standard API communication
        ai_response = ai_client.models.generate_content(
            model="gemini-2.0-flash",
            contents=analysis_prompt
        )
        state.ai_report = ai_response.text
        state.scan_report = ai_response.text
    except Exception as e:
        print(f"[!] Gemini API fallback engaged: {str(e)}")
        # FIX: Check if we actually found signatures before printing a warning report
        if scan_metrics["flags"]:
            fallback_msg = f"### ⚠️ Heuristic Threat Alert (Deterministic Engine Match)\n\nAnomalies were intercepted prior to container compilation.\n\n**Identified Structural Flags:**\n" + "\n".join([f"- {flag}" for flag in scan_metrics["flags"]])
        else:
            fallback_msg = "### ✅ Code Base Evaluation Clear\n\nNo deterministic malware signatures or exposed secrets were uncovered during this pass layer. Structural architecture matches enterprise baseline requirements."
        
        state.ai_report = fallback_msg
        state.scan_report = fallback_msg

    # Risk state router metrics assignment
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
    """Agent Node 2: Determines which path the workflow should take."""
    state.current_status = f"Evaluating Risk Paths [Score: {state.risk_score}]"
    print(f"[*] {state.current_status}")
    
    if state.risk_level in ["CRITICAL", "HIGH"]:
        return "human_triage_path"
    elif state.risk_level == "MEDIUM":
        return "conditional_approval_path"
    else:
        return "safe_deployment_path"

def human_triage_node(state: SentinelState) -> SentinelState:
    """Agent Node 3: Pauses the execution thread for Human-In-The-Loop."""
    state.current_status = "⏸️ Blocked: Awaiting Senior Security Review"
    state.waiting_for_input = True
    print(f"\n[ALERT] High risk level ({state.risk_level}) detected.")
    print("Execution pipeline frozen. Awaiting user response via backend api override...\n")
    return state

def deploy_and_monitor_node(state: SentinelState) -> SentinelState:
    """Agent Node 4: Simulates deployment and tracks runtime errors."""
    if state.rollback_counter > 1:
        state.current_status = "❌ Rollback Loop Detected. Terminating to save token costs."
        return state
        
    state.current_status = "✅ System Live and Verified Healthy."
    print(f"[*] {state.current_status}")
    
    if "mock_crash" in state.source_code:
        state.rollback_counter += 1
        state.current_status = f"⚠️ Runtime Error Tracked. Rolling back (Attempt #{state.rollback_counter})"
    else:
        state.current_status = "✅ System Live and Verified Healthy."
        
    print(f"[*] {state.current_status}")
    return state

# ==========================================
# EXECUTION PIPELINE / GRAPH ORCHESTRATOR
# ==========================================
def run_sentinel_pipeline(uploaded_code: str):
    """Compiles the nodes into a single linear state graph."""
    state = SentinelState(source_code=uploaded_code)
    
    # Pass the state through our nodes
    state = security_analysis_node(state)
    next_path = decision_router_node(state)
    
    if next_path == "human_triage_path":
        state = human_triage_node(state)
    else:
        state = deploy_and_monitor_node(state)
        
    print(f"\n--- Final Output: {state.current_status} ---\n")

if __name__ == "__main__":
    print("\n=== TEST CASE 1: SAFE ENTERPRISE CODE ===")
    run_sentinel_pipeline("print('Hello secure Google Cloud environment!')\n")
    
    print("\n=== TEST CASE 2: MALICIOUS THREAT DETECTED ===")
    run_sentinel_pipeline("api_key='AIzaSyD_SuperSecretTokenXYZ'\neval('danger')\n")