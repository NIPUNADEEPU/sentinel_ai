import os
import re
from typing import Dict, List, Literal
from pydantic import BaseModel, Field
from google import genai

# Import thresholds and API setup from our config file
import config

# Initialize the Gemini GenAI Client (Day 2 of workshop)
# We pull the API key securely from config so we don't leak it!
ai_client = genai.Client(api_key=config.GEMINI_API_KEY)

# ==========================================
# PHASE 1: Define ADK Persistent State Schema
# ==========================================
class SentinelState(BaseModel):
    """The central state object that tracks everything as the code moves between agents."""
    
    # Core Data
    source_code: str = Field(default="", description="The raw Python source code uploaded by the user.")
    file_name: str = Field(default="app.py", description="Name of the file being evaluated.")
    
    # Analysis Metrics (Day 4 Eval Data)
    vulnerabilities_found: List[Dict[str, str]] = Field(default_factory=list)
    risk_score: int = Field(default=0, description="Risk score scaled from 0 (Safe) to 100 (Critical Malicious).")
    risk_level: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = Field(default="LOW")
    scan_report: str = Field(default="")
    
    # HITL (Human-In-The-Loop) & Flow Controls
    waiting_for_input: bool = Field(default=False)
    rollback_counter: int = Field(default=0)
    current_status: str = Field(default="Initialized")

# ==========================================
# PHASE 2: Static Tools & Graph Nodes
# ==========================================
def native_security_scan(source_code: str) -> dict:
    """Agent Tool: Statically analyzes code for hardcoded secrets and basic vulnerabilities."""
    vulnerabilities = []
    score_penalty = 0
    
    # Basic Regex for exposed credentials
    secret_pattern = re.compile(r'(api_key|secret|password|token)\s*=\s*["\'][A-Za-z0-9_\-]{8,}["\']', re.IGNORECASE)
    if secret_pattern.search(source_code):
        vulnerabilities.append({"type": "Hardcoded Secret", "severity": "HIGH"})
        score_penalty += 45
        
    # Check for dangerous execution commands (OWASP)
    if "eval(" in source_code or "exec(" in source_code:
        vulnerabilities.append({"type": "Code Injection", "severity": "CRITICAL"})
        score_penalty += 50

    return {"vulnerabilities": vulnerabilities, "risk_score": score_penalty}

def security_analysis_node(state: SentinelState) -> SentinelState:
    """Agent Node 1: Executes local tools and passes results to Gemini for reasoning."""
    state.current_status = "Scanning Code Base..."
    print(f"[*] {state.current_status}")
    
    # 1. Run the native tool first
    tool_results = native_security_scan(state.source_code)
    state.vulnerabilities_found = tool_results["vulnerabilities"]
    base_score = tool_results["risk_score"]
    
    # 2. Use Gemini for deeper semantic reasoning
    prompt = f"""
    Analyze the following Python source code for security flaws.
    CODE:
    {state.source_code}
    
    CURRENT TOOL FINDINGS: {state.vulnerabilities_found}
    
    Provide a concise Markdown risk report.
    """
    
    try:
        # We skip calling Gemini if no API key is provided so the script doesn't crash during basic tests
        if config.GEMINI_API_KEY:
            response = ai_client.models.generate_content(
                model='gemini-2.0-flash',
                contents=prompt,
            )
            state.scan_report = response.text
            print("[*] Gemini semantic analysis complete.")
        else:
            state.scan_report = "Mocked AI report (Missing API Key)."
    except Exception as e:
        state.scan_report = f"AI Analysis failed: {e}"
        
    state.risk_score = min(base_score + 10, 100) # Added +10 to simulate Gemini finding edge-case issues
    
    if state.risk_score >= config.HIGH_RISK_THRESHOLD:
        state.risk_level = "CRITICAL" if state.risk_score >= 80 else "HIGH"
    elif state.risk_score >= config.MEDIUM_RISK_THRESHOLD:
        state.risk_level = "MEDIUM"
    else:
        state.risk_level = "LOW"
        
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
        
    state.current_status = f"Deploying to {config.GCP_PROJECT_ID} Cloud Run..."
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

# This test block will automatically run when we test the script!
if __name__ == "__main__":
    print("\n=== TEST CASE 1: SAFE ENTERPRISE CODE ===")
    run_sentinel_pipeline("print('Hello secure Google Cloud environment!')\n")
    
    print("\n=== TEST CASE 2: MALICIOUS THREAT DETECTED ===")
    run_sentinel_pipeline("api_key='AIzaSyD_SuperSecretTokenXYZ'\neval('danger')\n")