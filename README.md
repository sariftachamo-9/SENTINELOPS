# SENTINELOPS

![SENTINELOPS logo](static/soc%20logo.png)

[![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

SENTINELOPS is a local Security Operations Center (SOC) platform and analyst training lab. It combines a FastAPI telemetry and alert API, a browser command center, detection and correlation engines, threat-intelligence and SOAR workflows, and synthetic alert generation for safe hands-on practice.

## Screenshots and Demo

![SENTINELOPS dashboard](static/soc%20dashboard.png)

![SENTINELOPS report](static/soc%20report.png)

Run the platform locally and open the dashboard at `http://127.0.0.1:8002`.

- API: `http://127.0.0.1:8001`
- API documentation: `http://127.0.0.1:8001/docs`
- API health: `http://127.0.0.1:8001/health`
- Web command center: `http://127.0.0.1:8002`

## Features

- Real-time telemetry ingestion, normalization, validation, deduplication, and storage.
- Alert generation, triage, severity classification, risk scoring, and incident management.
- Rule-based detection and event correlation.
- Machine-learning anomaly detection support.
- Threat hunting across normalized telemetry.
- Asset and entity inventory with MITRE ATT&CK coverage.
- Case management, evidence, notes, audit logs, and reports.
- SOAR playbooks and controlled response-action workflows.
- Synthetic continuous alert feed for demonstrations and training.
- Dashboard charts for alert severity and 24-hour alert activity.
- Automatic dashboard polling every 15 seconds plus manual telemetry refresh.
- JWT authentication, role-based access control, request validation, and rate limiting.

## Technology Stack

- **Python 3.9+**
- **FastAPI** and **Uvicorn** for local API and web services.
- **SQLite** for local lab state and telemetry storage.
- **PyYAML**, **python-dotenv**, and data-processing and ML libraries listed in `soc-python-platform/requirements.txt`.
- **HTML, CSS, JavaScript**, Chart.js, and Vis.js for the web command center.
- **Pytest** for automated tests.

## Architecture

```text
Telemetry sources or synthetic feed
                |
                v
      FastAPI ingestion API :8001
                |
                v
 Normalization, validation, and SQLite storage
                |
        +-------+--------+
        |                |
        v                v
 Detection, ML,      Hunting, metrics,
 and correlation      assets, and health
        |                |
        +-------+--------+
                v
       Alerts and incidents
                |
                v
 Cases, evidence, SOAR, reports, and dashboard :8002
```

The main services are:

1. `src.api:app` exposes authentication, telemetry, alerts, incidents, assets, detection, and operational endpoints on port 8001.
2. `src.web_ui:app` serves the analyst command center on port 8002.
3. `scripts/generate_realistic_alerts.py` publishes synthetic lab alerts when run in continuous mode.

## Installation

### Requirements

- Python 3.9 or newer.
- `pip` and `venv`.
- A Unix-like shell for the `.sh` launch scripts. Windows users can run the manual commands from PowerShell.

### Create an environment

Windows PowerShell:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

Linux or macOS:

```bash
python3 -m venv venv
source venv/bin/activate
```

### Install dependencies

```bash
python -m pip install --upgrade pip
python -m pip install -r soc-python-platform/requirements.txt
```

The dependency manifest includes optional integrations and ML packages. Install system packages required by any integration you enable.

### Configure local secrets

Create a `.env` file in the project root. Keep it local and never commit it.

```env
JWT_SECRET=replace-with-a-random-secret
LAB_ADMIN_PASSWORD=replace-with-a-strong-password
PLATFORM_MODE=lab
DATABASE_URL=sqlite:///soc_data.db
```

Generate a secret with:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

## Running SENTINELOPS

### Automated launch

From a Unix-like shell:

```bash
./production_start.sh
```

This starts the API, web command center, and synthetic alert feed. Stop the services with:

```bash
./production_stop.sh
```

### Manual launch

After activating the virtual environment and loading `.env`, run each command in its own terminal:

```bash
python -m uvicorn src.api:app --host 127.0.0.1 --port 8001
python -m uvicorn src.web_ui:app --host 127.0.0.1 --port 8002
python scripts/generate_realistic_alerts.py --continuous
```

Open `http://127.0.0.1:8002` in a browser. The synthetic alert generator is optional; omit it when testing with your own API requests.

### API smoke test

With the API running:

```bash
python test_api.py
```

## Project Structure

```text
SENTINELOPS/
├── config/                    # Runtime configuration and detection rules
├── data/rules/                # Default rule catalog
├── dashboards/                # Standalone dashboard entry points
├── docs/                      # Analyst, integration, and workflow documentation
├── scripts/                   # Simulation, maintenance, reports, and validation
├── src/                       # API, UI, storage, detection, SOAR, and domain modules
├── static/                    # Logo, dashboard, and report images
├── templates/                 # Web templates
├── tests/                     # Automated test suite
├── soc-python-platform/       # Dependency manifest and auxiliary platform bundle
├── production_start.sh        # Starts local platform services
├── production_stop.sh         # Stops local platform services
├── test_api.py                # API smoke-test script
└── README.md                  # Project documentation
```

The local `soc_data.db` database, SQLite sidecars, logs, caches, credentials, and archive files are runtime or private artifacts and are excluded from version control.

## Documentation

- [Lab setup](docs/LAB_SETUP.md)
- [Telemetry](docs/TELEMETRY.md)
- [Ingestion](docs/INGESTION.md)
- [Threat hunting](docs/THREAT_HUNTING.md)
- [Investigation](docs/INVESTIGATION.md)
- [Case management](docs/CASE_MANAGEMENT.md)
- [SOAR](docs/SOAR.md)
- [Analyst training](docs/ANALYST_TRAINING.md)

Additional component and workflow documentation is available in `docs/`.

## Testing

Run the full test suite:

```bash
python -m pytest -q
```

Run a Python syntax check:

```bash
python -m compileall -q src dashboards scripts tests test_api.py
```

Tests that use live endpoints require the API service and the expected local environment configuration.

## Security and Privacy

- Store `JWT_SECRET` and `LAB_ADMIN_PASSWORD` only in local environment configuration.
- Use synthetic data for training and demonstrations by default.
- Review integrations and response actions before enabling them.
- Do not expose the development servers directly to the public internet.
- Only ingest telemetry and perform response actions when authorized.

## License

SENTINELOPS is distributed under the MIT License. See [LICENSE](LICENSE).
