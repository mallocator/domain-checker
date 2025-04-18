# Domain Checker

A simple, self‑hosted tool to monitor domain availability and expiry, sending email alerts when a domain becomes available or is about to expire.

## Table of Contents
- [Introduction](#introduction)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Running Locally](#running-locally)
- [Running with Docker](#running-with-docker)
- [Configuration](#configuration)
- [Development](#development)
- [Troubleshooting](#troubleshooting)
- [License](#license)

## Introduction
Monitor one or more domains for:

- **New availability**: get alerted when a previously registered domain expires and becomes free.
- **Upcoming expiry**: receive advance notice (configurable, default 7 days) before a domain you own expires.

Alerts are delivered via email using your SMTP server (e.g., Gmail App Password).

## Features
- DNS SOA checks for fast availability filtering
- WHOIS expiry lookup with configurable threshold
- Email notifications via SMTP
- Easy configuration via environment variables or JSON file
- Stateful tracking (per‑domain state files) to avoid duplicate alerts
- Lightweight: single binary or Docker container

## Prerequisites
- **SMTP credentials** for sending mail (host, port, user, password)
- **Docker** engine (if using the container)
- *(optional)* **Go 1.24+** (if building locally)

## Running Locally

1. **Download** a prebuilt binary from the [Releases](https://github.com/youruser/domain-checker/releases) page (replace `youruser`).

2. **Set your environment variables**:
   ```bash
   export DOMAINS="example.com,mydomain.net"
   export STATE_DIR="./data"
   export SMTP_HOST="smtp.gmail.com"
   export SMTP_PORT="587"
   export SMTP_USER="you@gmail.com"
   export SMTP_PASS="YOUR_APP_PASSWORD"
   export EMAIL_FROM="you@gmail.com"
   export EMAIL_TO="alerts@you.com"
   export THRESHOLD_DAYS=7      # days before expiry to alert
   export DEBUG=true           # optional, for verbose logs
   ```

3. **Create the data folder** for state files:
   ```bash
   mkdir -p ./data
   ```

4. **Run the checker**:
   ```bash
   ./domain-checker
   ```

Logs will show each domain check and notification status.

## Running with Docker

The Docker container will execute just like the binary, but with the added benefit of isolation and easy deployment.
This will not run a long-running service, but rather a one-off check. You can schedule it with cron or Synology Task Scheduler.

1. **Pull your container** (replace `youruser`):
   ```bash
   docker pull mallox/domain-checker:latest
   ```

2. **Run the container once** with volume mapping and env vars:
   ```bash
   docker run --rm \
     -v /path/to/data:/data \
     -e DOMAINS="example.com,mydomain.net" \
     -e STATE_DIR=/data \
     -e SMTP_HOST=smtp.gmail.com \
     -e SMTP_PORT=587 \
     -e SMTP_USER=you@gmail.com \
     -e SMTP_PASS=YOUR_APP_PASSWORD \
     -e EMAIL_FROM=you@gmail.com \
     -e EMAIL_TO=alerts@you.com \
     -e THRESHOLD_DAYS=7 \
     -e DEBUG=true \
     youruser/domain-checker:latest
   ```

3. *(Optional)* **Schedule** via cron or Synology Task Scheduler using the same Docker command.

## Configuration

All settings can be provided via **environment variables** or a JSON **config file** (`CONFIG_FILE`).

### Common Variables
| Variable         | Description                        | Default  |
|------------------|------------------------------------|----------|
| `DOMAINS`        | Comma‑separated list of domains    | _none_   |
| `STATE_DIR`      | Path to store state JSON files     | `/data`  |
| `THRESHOLD_DAYS` | Days before expiry to alert        | `7`      |
| `SMTP_HOST`      | SMTP server address                | _none_   |
| `SMTP_PORT`      | SMTP port                          | _none_   |
| `SMTP_USER`      | SMTP login (email address)         | _none_   |
| `SMTP_PASS`      | SMTP password or app password      | _none_   |
| `EMAIL_FROM`     | From address for alert emails      | _none_   |
| `EMAIL_TO`       | Recipient address                  | _none_   |
| `DEBUG`          | Enable verbose logs (`true/false`) | `false`  |

### JSON Config File
Create `config.json` with any subset of settings:
```json
{
  "domains": ["example.com","mydomain.net"],
  "smtp_host": "smtp.gmail.com",
  "smtp_port": 587,
  "smtp_user": "you@gmail.com",
  "smtp_pass": "APP_PW",
  "email_from": "you@gmail.com",
  "email_to": "alerts@you.com"
}
```
Then:
```bash
export CONFIG_FILE=./config.json
```  
Envs will override any JSON values.

## Development

- **Build** locally with Go:
  ```bash
  go build -o domain-checker
  ```

- **Run tests**:
  ```bash
  go test ./... -v
  ```

- **Build Docker image**:
  ```bash
  docker build -t youruser/domain-checker:latest .
  ```

## Troubleshooting

- **Permission errors**: ensure the `STATE_DIR` folder is writable by the process/container.
- **DNS SOA lookup issues**: confirm network/DNS access in Docker (use `--network=host` if needed).

## License

MIT © Your Name
```

