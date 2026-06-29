import os

# Google AI Studio Integration Setup
# The framework requires a valid Gemini API Key.
# DO NOT hardcode your key here. Run 'export GEMINI_API_KEY="your-key"' or set it in Windows Env.
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

if not GEMINI_API_KEY:
    print("⚠️ WARNING: GEMINI_API_KEY is currently empty. Please set your environment variable.")

# Google Cloud Platform Target Setup (Day 5 Production Infrastructure)
GCP_PROJECT_ID = os.getenv("GCP_PROJECT_ID", "sentinel-ai-sandbox")
GCP_REGION = os.getenv("GCP_REGION", "us-central1")

# Thresholds for SentinelAI Guardrail Decision Engine
MEDIUM_RISK_THRESHOLD = 25
HIGH_RISK_THRESHOLD = 65