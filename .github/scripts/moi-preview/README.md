# MOI archive assistant preview

This workflow moves the already verified assistant API preview onto a GitHub-hosted
runner. It does not scan repositories, create archive rows, send WeCom messages,
test a robot connection, or change existing schedules.

Set the repository Actions secret `MOI_API_KEY` to an existing MOI personal access
token authorized for the target workspace. Never commit a token, a report body,
private scan results, or a handoff JSON file to this repository.

Run **MOI Archive Assistant Preview** from Actions with:

- `report_date`: the explicit archived date in `YYYY-MM-DD` format.
- Exactly one of `source_conversation_id` or `handoff_file_id`. The first reads a
  user message containing the verified handoff from the fixed MOI assistant; the
  second downloads an already uploaded handoff JSON from MOI.

The workflow downloads the archived body, verifies its size and SHA256, invokes
the fixed assistant in preview mode, reads the real task and saved result, and
compares returned content byte for byte. It uses a deterministic request/message
identity and checks existing MOI sessions before submission. Unknown submission
outcomes are recovered by reading MOI sessions, never by retrying the POST.
History discovery is bounded to 1,000 conversations and 200 messages each; it
fails closed when the bound is exceeded.

The model and target workspace/agent are fixed in `moi_archive_preview.py`.
Calls use only the documented public HTTPS API, even if Agent Card advertises an
internal address. Browser cookies and a locally installed Codex or MOI CLI are not
used. Only a receipt without report contents or runtime logs is published to the
workflow artifact; private inputs and model responses stay in memory and in MOI.

This is a manual/reusable workflow. No daily schedule is enabled. The next stage
must migrate scan preparation and archive creation before connecting their
successful completion to `workflow_call`. Formal 10:00 delivery remains a
separate stage and is disabled here.

## Cloud scan preparation

`MOI Cloud Scan Preparation` collects the latest current-day MatrixOne and taas
Actions reports with exact run/job/attempt and raw-report checks. It scans a
Git-blob-verified matrixflow `dev` dependency snapshot with OSV 2.7.0. The scanner
receives no API credentials. No project build, dependency repair, or protected
source-branch modification is performed. Partial extraction remains explicit.

Configure the Actions secret `SCAN_GITHUB_TOKEN` with an existing fine-grained
GitHub token: select only `matrixorigin/taas` and `matrixorigin/matrixflow`, with
Contents: read and Actions: read. Organization approval/SSO may also be required.
The cloud collector reuses the existing MatrixOne and taas scheduled scans; it
does not dispatch either scanner or replace their Feishu notifications.

Reports, stderr, evidence, and the daily body are uploaded to the fixed MOI
volume, mounted, downloaded, and hash-verified. The existing five-SQL MOI
workflow receives fresh inputs with `replace_saved_defaults=true`. Both tables
and every file are independently read back. Only then is a preview handoff
uploaded and the reusable assistant preview workflow called.

The 07:30 Asia/Shanghai schedule is gated by the repository variable
`MOI_CLOUD_PREP_ENABLED=true`. Keep it unset until a real hosted acceptance run
passes and the previous local preparation automation is retired. GitHub cron
can be delayed; this step does not enable or promise precise 10:00 delivery.
Manual dispatch accepts only today's Beijing date and does not wait for an
unstarted source workflow. Scheduled preparation waits until 09:50 and stops
starting archival after 09:55.

A verified `cloud-ready-YYYYMMDD.json` is reused without rescanning. A durable
preparation lock prevents another dispatch from repeating an incomplete run.
If an interrupted attempt has no verified ready handoff, inspect the source
run, lock, uploaded files, and MOI execution before recovery; do not blindly
remove the lock or launch another scan. Unavailable/failed repositories retain
NULL counts and explicit evidence; missing raw reports remain archive gaps.

Only sanitized preparation and preview receipts are published to GitHub
artifacts. The report body, private raw artifacts, full job logs, tokens, and
Webhook values are never published to this public repository. Actual WeCom
sending and 10:00 group scheduling remain disabled.
