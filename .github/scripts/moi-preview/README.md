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

## Cloud preparation from repository uploads

Each repository scans its own source and uploads its report and stderr to MOI using
its own Actions token and MOI_API_KEY. The companion moi-scan/moi_repo_scan.py
publishes immutable, hash-verified source manifests. Private results remain in MOI
and private repository artifacts.

MOI Cloud Scan Preparation reads only the three current-day MOI manifests. It
verifies their repository, branch, workflow, run, attempt, timestamps, report
hashes and counters before reusing the existing five-SQL archival workflow and
assistant preview. It needs MOI_API_KEY only; no GitHub access token, OSV binary,
repository checkout or private GitHub read permission is used by the aggregator.

Missing uploads stay pending with NULL counts; failed scans retain NULL counts;
partial dependency extraction stays explicit. The newest failed source cannot be
replaced with an older success. A source manifest becomes visible only after its
files have been uploaded and independently downloaded and verified.

The 07:30 Asia/Shanghai aggregate schedule remains gated by
MOI_CLOUD_PREP_ENABLED=true. Set it only after all three source workflows and the
archive/assistant chain pass hosted acceptance and the old local preparation is
retired. Scheduled preparation waits until 09:50 and stops starting archival at
09:55. Manual runs require all three uploads to have arrived before creating a
preparation lock. Actual WeCom sending remains disabled here.
