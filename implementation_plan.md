\# Blueprint: SentinelAI Enterprise 🚀

An Autonomous Human-in-the-Loop Security Operations Agent built using Google's Agent Development Kit (ADK 2.0).



\## 📋 Project Architectural Phase Tasks



\### Phase 1: Basic Scaffolding \& State Schema (Current)

\- \[x] Create project file directory structure and configure environment parameters.

\- \[x] Protect API variables against repository exposure utilizing `.gitignore`.

\- \[ ] Define the explicit central `SentinelState` using Pydantic tracking schemas.



\### Phase 2: Static Evaluation Tools \& Graph Workflows

\- \[ ] Implement Regex-based AST structural security analysis scanning tools.

\- \[ ] Construct the ADK 2.0 graph workflow processing framework using `security\_analysis\_node`.

\- \[ ] Establish conditional routing pathways (`decision\_router\_node`) parsing Low, Medium, and High risk profiles.



\### Phase 3: Human-in-the-Loop Triage \& Long-Running State Pause

\- \[ ] Configure execution thread pausing engine when high-severity threats are detected.

\- \[ ] Construct mock API callback logic to simulate senior engineer security override approvals.



\### Phase 4: Day 4 Evaluation Dashboard \& Day 5 Deployment Simulation

\- \[ ] Build defensive metrics logging tracking prompt injection blocks and false-positive rates.

\- \[ ] Script the simulated rollout engine targeting Google Cloud Run with circuit-breaking self-healing rollback automation.

