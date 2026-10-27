"""Bounded artifact recovery around the unchanged component scanner.

Only a completed, hash-verified finalize output rejected by employee_marker_missing
can receive a new workflow identity. Other scan stages and uncertain submissions
retain the original runner's resume rules.
"""
import datetime as dt
import re

from cloud_daily import Runner, Failure, json_bytes, require, sha256
from pipeline_telemetry import emit, error_fields
from workflow_lifecycle import cached_outputs

MAX_FINALIZE_ATTEMPTS = 3
FINALIZE_LABELS = {'matrixone_finalize', 'taas_finalize', 'matrixflow_finalize'}


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


class ComponentRunner(Runner):
    def __init__(self, api, objects, journal, *, context):
        super().__init__(api, objects, journal)
        self.context = context
        self.finalize_nodes = {}

    def attempt(self, label, number, *, adopted=False):
        return dict(number=number, label=label if number == 1 else label+'_recovery_'+str(number),
            validation='pending', github=None if adopted else dict(self.context.github),
            planned_at_utc=now())

    def workflow(self, label, nodes):
        if label not in FINALIZE_LABELS:
            return super().workflow(label, nodes)
        digest = sha256(json_bytes(nodes))
        previous = self.state.get('stages', {}).get(label)
        if previous:
            require(previous.get('input_sha256') == digest, 'workflow_resume_input_changed')
        recovery = self.state.setdefault('workflow_recovery', {}).setdefault(label,
            dict(input_sha256=digest, attempts=[self.attempt(label, 1, adopted=bool(previous))]))
        require(recovery['input_sha256'] == digest, 'workflow_resume_input_changed')
        self.finalize_nodes[label] = nodes
        current = recovery['attempts'][-1]
        self.journal.save()  # Freeze the selected attempt before any remote mutation.
        result = super().workflow(current['label'], nodes)
        stage = self.state['stages'][current['label']]
        current.update(workflow_id=stage['workflow_id'], execution_id=stage['execution_id'])
        self.journal.save()
        return result

    def scan(self, repo, proof):
        saved = self.state.setdefault('repositories', {}).setdefault(repo.name, {})
        if saved.get('accepted'):
            return super().scan(repo, proof)
        saved.update(scan_status='running', scan_github=dict(self.context.github))
        saved.pop('scan_failure', None)
        self.journal.save()
        label = repo.name+'_finalize'
        try:
            while True:
                try:
                    result = super().scan(repo, proof)
                except Failure as exc:
                    if str(exc) != 'employee_marker_missing' or label not in self.finalize_nodes:
                        raise
                    recovery = self.state['workflow_recovery'][label]
                    current = recovery['attempts'][-1]
                    stage = self.state['stages'].get(current['label'], {})
                    # A timeout or missing/tampered cache cannot authorize regeneration.
                    if stage.get('status') != 'completed' or cached_outputs(self, stage, self.finalize_nodes[label]) is None:
                        raise
                    if current['validation'] != 'rejected':
                        current.update(validation='rejected', rejected_at_utc=now(),
                            validated_by=dict(self.context.github),
                            failure=dict(code='employee_marker_missing', **error_fields(exc)))
                        self.journal.save()
                        emit('component_artifact_rejected', repository=repo.name,
                            attempt=current['number'], code='employee_marker_missing', **self.context.record())
                    if current['number'] >= MAX_FINALIZE_ATTEMPTS:
                        raise
                    following = self.attempt(label, current['number']+1)
                    recovery['attempts'].append(following)
                    self.journal.save()
                    emit('component_artifact_retry', repository=repo.name,
                        attempt=following['number'], **self.context.record())
                    continue
                recovery = self.state.get('workflow_recovery', {}).get(label)
                if recovery:
                    recovery['attempts'][-1].update(validation='accepted', accepted_at_utc=now(),
                        validated_by=dict(self.context.github))
                saved['scan_status'] = 'succeeded'
                self.journal.save()
                return result
        except Exception as exc:
            saved.update(scan_status='failed', scan_failure=error_fields(exc))
            if re.fullmatch(r'[a-z][a-z0-9_]{0,100}', str(exc)):
                saved['scan_failure']['code'] = str(exc)
            self.journal.save()
            raise
