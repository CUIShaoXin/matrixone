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
