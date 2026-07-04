# 🏆 SentinelAI Enterprise Operations Dashboard

An Autonomous Human-in-the-Loop Security Agent built with the Google GenAI SDK and Gemini to parse Python deployments for spyware footprints, vulnerable anomalies, obfuscation bypasses, and configuration risks.

---

## 🚀 Concept & Multi-Agent Architecture
SentinelAI acts as an isolated sandbox guardrail that intercepts scripts using stateful node graphs. It leverages dynamic heuristics to update payload metrics and freeze execution pipelines if data exfiltration risks or dynamic byte-reconstruction evasion techniques are detected, demanding manual senior administrative oversight before continuation.

## 📁 Key Features Covered
* **Agent System Design (State Graphs):** Orchestrates isolated code evaluation layers using a stateful Pydantic data bus.
* **Cognitive Security Interventions:** Leverages Gemini 2.0 Flash to scan live code structures for high-risk dependencies, hidden intentions, and credential signatures.
* **Dynamic Guardrail Analytics:** Provides an active, real-time UI matrix tracking payload resilience, secret scanning coverage, and rollback latency metrics.

---

## ⚙️ Quick Installation and Setup

### 1. Clone the Repository

git clone [https://github.com/NIPUNADEEPU/sentinel_ai.git](https://github.com/NIPUNADEEPU/sentinel_ai.git)
cd sentinel_ai
### 2. Install System Dependencies
Make sure you install the core web dependencies along with the official Google GenAI SDK library:

Bash
pip install fastapi uvicorn streamlit requests pydantic google-genai

### 3. Configure Your Environment Variables
SentinelAI requires an active Gemini API key to run its cognitive evaluation nodes. Create a config.py file in your root folder (or ensure your environment variable is set):

Python
# Inside your local config.py or environment configuration
GEMINI_API_KEY = "YOUR_GEMINI_API_KEY_HERE"

### 4. Start the FastAPI Backend Server Layer
Bash
python -m uvicorn app:app --reload

### 5. Launch the Streamlit Operations Interface
Open a second terminal window and run:

Bash
streamlit run dashboard.py
