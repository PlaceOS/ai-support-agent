# Report Templates

Report templates are runtime-loaded presentation artefacts. They control the
subject and Markdown body sent by report delivery channels; they do not control
diagnosis, escalation, or remediation behavior.

Store each template as a separate YAML file under `reports/`. Files must follow
`schemas/report.v1.json`. The service discovers new `.yml` and `.yaml` files and
rereads them for each new report delivery, so template changes do not require a
code change or process restart.

Supported placeholders are:

- `{{incident_id}}`
- `{{status}}`
- `{{severity}}`
- `{{summary}}`
- `{{report}}` for the complete canonical Markdown report

`REPORT_TEMPLATE_ID` selects a template by ID. When several versions of that
ID exist, the highest version is used. The default is `operator-report`.
