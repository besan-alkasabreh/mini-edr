# Mini EDR

> **Lightweight AI-assisted Endpoint Detection and Response (EDR) System**
>
> Graduation Project developed for educational purposes, demonstrating endpoint monitoring, threat detection, AI-assisted analysis, and incident management.

---

# Overview

Mini EDR is a lightweight Endpoint Detection and Response (EDR) system designed to monitor Windows endpoints, collect telemetry, analyze suspicious behavior using both **Rule-Based Detection** and **AI-Assisted Analysis**, and visualize incidents through a modern React dashboard.

This project is intended for **education, research, demonstration, and controlled lab environments**. It is **not** intended to replace enterprise EDR solutions.

---

# System Architecture

```text
+----------------------+
|  Windows Endpoint    |
|        Agent         |
+----------+-----------+
           |
           | Telemetry
           v
+----------------------+
|   FastAPI Backend    |
| Rule Engine + AI     |
+----------+-----------+
           |
           v
+----------------------+
| SQLite / PostgreSQL  |
+----------+-----------+
           |
           v
+----------------------+
|   React Dashboard    |
+----------------------+
```

---

# Screenshots

## Dashboard

![Dashboard](screenshots/dashboard)

## Backend

![Backend](screenshots/backend)


# Main Features

- Windows Endpoint Agent
- Real-time telemetry collection
- Rule-Based threat detection
- AI-assisted threat classification
- Hybrid detection engine
- Risk score calculation (0–100)
- Severity classification (Low → Critical)
- Incident management dashboard
- Live monitoring
- REST API (FastAPI)
- SQLite (default) with optional PostgreSQL support
- WebSocket live updates

---

# Project Structure

```text
mini-edr/
├── agent/
├── backend/
├── dashboard/
├── endpoints/
├── data/
├── screenshots/
├── .gitignore
└── README.md
```

---

# Technologies Used

## Backend
- Python
- FastAPI
- SQLAlchemy
- SQLite
- PostgreSQL

## Frontend
- React
- Vite
- JavaScript

## AI
- Scikit-learn
- Random Forest

---

# Detection Methods

- Rule-Based Detection
- AI-Assisted Detection
- Hybrid Detection

---

# Risk Levels

| Risk Score | Severity |
|------------|----------|
| 0–30 | Low |
| 31–60 | Medium |
| 61–80 | High |
| 81–100 | Critical |

---

# Requirements

- Python 3.10+
- Node.js 20+
- npm
- Git
- Windows (for Agent)

---

# Local URLs

Backend API

http://127.0.0.1:8000/docs

Dashboard

http://127.0.0.1:5173

---

# Default Dashboard Login

Username

admin

Password

admin123

Environment variables:

DASHBOARD_USERNAME

DASHBOARD_PASSWORD

---

# Running the Project

## Backend

```powershell
cd backend
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload
```

## Dashboard

```powershell
cd dashboard
npm install
npm run dev
```

## Agent

```powershell
cd agent
pip install -r requirements.txt
python agent.py
```

---

# Detection Engine

The backend receives telemetry through:

POST /telemetry

It calculates:

- Rule Score
- AI Score
- Final Risk Score
- Severity
- AI Attack Category
- AI Confidence
- AI Explanation

Final severity always depends on the **final calculated risk score**.

---

# CPU Thresholds

| CPU Usage | Level |
|-----------|------|
| <60% | Normal |
| 60–80% | Medium |
| 81–90% | High |
| >90% | Critical |

---

# Rule-Based Detection Examples

- Suspicious PowerShell
- Encoded Commands
- Temp/AppData Execution
- Suspicious Ports
- Credential Access
- Event Log Clearing
- Shadow Copy Deletion
- Scheduled Tasks
- High CPU Usage
- Suspicious Processes
- Network Anomalies

Mapped where applicable to MITRE ATT&CK techniques.

---

# AI Categories

- Credential Access
- Execution
- Persistence
- Discovery
- Defense Evasion
- Command & Control
- Impact
- Suspicious Execution Path

---

# Important Files

## Backend

- backend/main.py
- backend/detection.py
- backend/ai_model.py
- backend/database.py
- backend/models.py
- backend/schemas.py

## Agent

- agent/agent.py
- agent/config.json
- agent/agent_setup.py

## Dashboard

- dashboard/src/App.jsx
- dashboard/src/api.js
- dashboard/src/index.css

---

# API Endpoints

- GET /health
- POST /auth/login
- POST /register
- POST /telemetry
- GET /telemetry
- GET /agents
- GET /events/live
- POST /response-actions
- GET /response-actions

Swagger:

http://127.0.0.1:8000/docs

---

# Screenshots

Create a folder named:

```text
screenshots/
```

Add dashboard screenshots here, for example:

- Dashboard Overview
- Live Activity
- Incident Management
- Agent List

---

# GitHub

```bash
git clone https://github.com/YOUR_USERNAME/mini-edr.git
cd mini-edr
```

Then run the Backend, Dashboard, and Agent.

---

# Troubleshooting

**Port 8000 already in use**

```powershell
netstat -ano | findstr :8000
taskkill /PID PID_NUMBER /F
```

If the dashboard cannot connect:

- Verify the backend is running.
- Check `dashboard/.env.local`.
- Open `/health`.

---

# Notes

- Designed for Windows endpoints.
- Intended for educational and research purposes.
- Test only inside a controlled lab environment.

---

# Author

**Besan Alkasabreh**

Graduation Project

Cybersecurity Student
