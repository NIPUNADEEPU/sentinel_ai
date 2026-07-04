from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uuid

# Import tracking schemas
from agent import SentinelState, security_analysis_node, decision_router_node, deploy_and_monitor_node

app = FastAPI(title="SentinelAI Enterprise Agent API", version="2.0")

state_store = {}

class CodeUploadRequest(BaseModel):
    file_name: str = "app.py"
    source_code: str

class HumanApprovalRequest(BaseModel):
    scan_id: str
    approved: bool

@app.get("/")
def read_root():
    return {"status": "online", "engine": "SentinelAI Enterprise DevSecOps Agent"}

@app.post("/api/v1/analyze")
def analyze_code_payload(request: CodeUploadRequest):
    scan_id = str(uuid.uuid4())
    state = SentinelState(source_code=request.source_code, file_name=request.file_name)
    state.current_status = "Analysis Request Received"
    
    # Process Node Graph Actions
    state = security_analysis_node(state)
    routing_decision = decision_router_node(state)
    
    # Hard override backup if AI analysis matches suspicious string metrics
    if "requests.post" in request.source_code and "pynput" in request.source_code:
        routing_decision = "human_triage_path"
        state.risk_level = "HIGH"
        state.risk_score = 92
        state.scan_report = "### ⚠️ Heuristic Threat Alert (Deterministic Engine Match)\n\nAnomalies were intercepted prior to container compilation.\n\n**Identified Structural Flags:**\n- ⚠️ HIGH RISK: Spyware/Surveillance Indicators (Keylogging or Active Screen Grab Data Exfiltration)"
        state.ai_report = state.scan_report

    if routing_decision == "human_triage_path" or state.risk_level in ["HIGH", "CRITICAL"]:
        state.current_status = "⏸️ Blocked: Awaiting Senior Security Review Override"
        state.waiting_for_input = True
    else:
        state = deploy_and_monitor_node(state)
        state.waiting_for_input = False
        
    state_store[scan_id] = state
    
    return {
        "scan_id": scan_id,
        "risk_level": state.risk_level,
        "risk_score": state.risk_score,
        "current_status": state.current_status,
        "waiting_for_input": state.waiting_for_input,
        "vulnerabilities": state.vulnerabilities_found,
        "ai_report": state.scan_report
    }

@app.post("/api/v1/approve")
def human_override_callback(request: HumanApprovalRequest):
    if request.scan_id not in state_store:
        raise HTTPException(status_code=404, detail="Requested Scan ID profile not identified.")
        
    state = state_store[request.scan_id]
    
    if request.approved:
        state.waiting_for_input = False
        state.risk_level = "LOW"
        state.current_status = "🔓 Override Approved. Re-engaging operational pipeline..."
        state = deploy_and_monitor_node(state)
    else:
        state.waiting_for_input = False
        state.risk_level = "HIGH"
        state.current_status = "⛔ Rejected: Deployment Blocked Permanently by Security Operations Center."
        
    state_store[request.scan_id] = state
    
    return {
        "scan_id": request.scan_id,
        "current_status": state.current_status,
        "deployment_url": "https://sentinel-sandbox.run.internal/live" if request.approved else "NONE"
    }

@app.get("/api/v1/status/{scan_id}")
def check_agent_telemetry(scan_id: str):
    if scan_id not in state_store:
        raise HTTPException(status_code=404, detail="Scan profile not indexed.")
    return state_store[scan_id]