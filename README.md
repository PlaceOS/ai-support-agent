# PlaceOS AI Support Agent

[PlaceOS](https://place.technology/) service that investigates incident signals and generates evidence-backed diagnostic reports. The current implementation is report-only and does not execute remediation.

## Environment Variables

### Database

- `PG_DATABASE_URL` = PostgreSQL connection URL. Required for persistence, incident claiming, and module changefeed ingestion.

The following PgORM settings can be used instead of `PG_DATABASE_URL`:

- `PG_HOST` = PostgreSQL hostname (default: `localhost`)
- `PG_PORT` = PostgreSQL port (default: `5432`)
- `PG_DATABASE` = PostgreSQL database name (default: `test`)
- `PG_USER` = PostgreSQL username (default: `postgres`)
- `PG_PASSWORD` = PostgreSQL password (default: empty)
- `PG_QUERY` = query parameters appended to the generated PostgreSQL URL (default: empty)
- `PG_LOCK_TIMEOUT` = database lock timeout in seconds (default: `5`)

### PlaceOS API

- `PLACE_URI` = PlaceOS REST API base URL. Required for PlaceOS diagnostic context.
- `PLACE_API_KEY` = PlaceOS API key with administrator access for cluster process evidence. Preferred authentication method.
- `PLACE_INSECURE` = disable TLS certificate verification when set to `1` or `true` (default: `false`)

User authentication can be used instead of `PLACE_API_KEY`. All of the following are required when using user authentication:

- `PLACE_EMAIL` = PlaceOS user email
- `PLACE_PASSWORD` = PlaceOS user password
- `PLACE_AUTH_CLIENT_ID` = PlaceOS OAuth client ID
- `PLACE_AUTH_SECRET` = PlaceOS OAuth client secret

### OpenAI

- `OPENAI_API_KEY` = OpenAI API key. Enables AI-assisted incident analysis.
- `OPENAI_API_BASE` = alternate OpenAI-compatible or Azure OpenAI API base URL
- `OPENAI_MODEL` = model used for incident analysis (default: `gpt-4o-mini`)

### Playbooks And Report Templates

- `PLAYBOOKS_PATH` = workflow and procedure catalogue root (default: auto-discovered `playbooks` directory)
- `REPORT_TEMPLATES_PATH` = report template directory (default: auto-discovered `templates/reports` directory)
- `REPORT_TEMPLATE_ID` = report template ID (default: `operator-report`)

### Report Delivery

- `REPORT_WEBHOOK_URL` = outbound webhook URL for generated reports
- `REPORT_EMAIL_TO` = comma-separated email recipients. Enables email delivery when SMTP is configured.

- `REPORT_DELIVERY_TIMEOUT_SECONDS` = webhook connect/read and SMTP DNS/connect/read/write timeout, clamped to 1-120 seconds (default: `10`)
- `REPORT_DELIVERY_MAX_ATTEMPTS` = attempts per channel, clamped to 1-10 (default: `3`). Set to `1` to disable retries.
- `REPORT_DELIVERY_RETRY_BASE_SECONDS` = first retry delay, clamped to 1-3600 seconds (default: `30`). Subsequent delays double: 30s, 60s, etc.

The first attempt on each configured channel stays inline. Connection, DNS, TLS and timeout failures, HTTP 408/425/429 and 5xx responses retry in background fibers. Other HTTP responses, configuration errors and rendering errors do not retry. Every attempt is recorded separately.

Pending retries are lost when the process stops. The escalation record keeps the first attempt's outcome even if a retry later succeeds.

- `REPORT_FALLBACK_WEBHOOK_URL` = separate webhook used when a primary channel gives up
- `REPORT_FALLBACK_EMAIL_TO` = comma-separated fallback recipients, using the same SMTP settings

Every configured fallback channel receives the same rendered report once a primary gives up, including non-retryable transport or configuration failures. Fallback starts once per incident in the background, even if both primaries fail. Fallback attempts use the same timeout and retry policy, and their failures do not trigger further fallback. Records use `fallback_generic_webhook` and `fallback_email` destinations.

Skipped deliveries (including maintenance suppression) and rendering failures do not trigger fallback. Fallback settings alone leave delivery disabled and produce a startup warning. The once-per-incident fallback guard is process-local, as are pending retry fibers.

### SMTP

- `SMTP_SERVER` = SMTP server hostname. Required when `REPORT_EMAIL_TO` is configured.
- `SMTP_PORT` = SMTP server port (default: `25`)
- `SMTP_SECURE` = SMTP transport mode: `NONE`, `STARTTLS`, or `SMTPS` (default: `NONE`)
- `SMTP_USER` = SMTP username. Must be set with `SMTP_PASS`.
- `SMTP_PASS` = SMTP password. Must be set with `SMTP_USER`.
- `SMTP_FROM_EMAIL` = report sender address. Required when `REPORT_EMAIL_TO` is configured.
- `SMTP_FROM_NAME` = report sender name (default: `PlaceOS Support Agent`)
- `SMTP_HELO_DOMAIN` = SMTP `HELO`/`EHLO` domain (default: sender email domain)

### Incident Claiming

- `INCIDENT_CLAIM_LEASE_SECONDS` = incident claim lease in seconds, clamped to 10-300 (default: `30`)
- `INCIDENT_CLAIM_WAIT_MILLISECONDS` = maximum wait for another worker to complete a claimed incident, clamped to 0-30000 (default: `2000`)
- `INCIDENT_CLAIM_POLL_MILLISECONDS` = claim polling interval, clamped to 10-1000 (default: `100`)

### Service

- `SG_ENV` = runtime environment (default: `development`)
- `SG_SERVER_HOST` = HTTP server bind address (default: `127.0.0.1`)
- `SG_SERVER_PORT` = HTTP server port (default: `3015`)
- `SG_PROCESS_COUNT` = HTTP server worker count (default: `1`)
- `LOG_LEVEL` = log severity (default: `info` in production, `debug` otherwise)
- `PLACE_COMMIT` = commit identifier embedded at build time (default: `DEV`)

## Development

```bash
shards install
./test
```
