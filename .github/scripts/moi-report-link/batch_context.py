"""Shared business identity for existing and MOI-triggered execution."""
from dataclasses import dataclass
import datetime as dt
import os
import re

LOCAL = dt.timezone(dt.timedelta(hours=8))


@dataclass(frozen=True)
class BatchContext:
    run_id: str
    business_date: str
    trigger_source: str
    execution_mode: str
    github: dict

    @classmethod
    def from_env(cls, env=None, now=None):
        env = os.environ if env is None else env
        date = env.get('MATRIX_BUSINESS_DATE') or (now or dt.datetime.now(LOCAL)).astimezone(LOCAL).date().isoformat()
        if not re.fullmatch(r'\d{4}-\d{2}-\d{2}', date):
            raise ValueError('invalid_business_date')
        try: dt.date.fromisoformat(date)
        except ValueError: raise ValueError('invalid_business_date') from None
        explicit, resume = env.get('MATRIX_PIPELINE_RUN_ID'), env.get('MATRIX_PIPELINE_RESUME_RUN_ID')
        if explicit and resume and explicit != resume:
            raise ValueError('batch_resume_identity_conflict')
        scheduled = env.get('MATRIX_SCHEDULED_BATCH') == 'true'
        github_id = env.get('GITHUB_RUN_ID', 'manual')
        attempt = env.get('GITHUB_RUN_ATTEMPT', '1')
        if not re.fullmatch(r'[1-9][0-9]*', attempt): raise ValueError('invalid_github_attempt')
        run_id = explicit or resume or ('daily-' + date.replace('-', '') if scheduled else github_id + '-' + attempt)
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', run_id): raise ValueError('invalid_run_id')
        source = env.get('MATRIX_TRIGGER_SOURCE') or ('github_schedule' if scheduled else 'github_manual')
        if source not in ('github_schedule', 'github_manual', 'moi_manual', 'moi_api', 'moi_schedule'):
            raise ValueError('invalid_trigger_source')
        mode = env.get('MATRIX_EXECUTION_MODE', 'production')
        if mode not in ('production', 'no_send'): raise ValueError('invalid_execution_mode')
        if source.startswith('moi_') and not (explicit and env.get('MATRIX_BUSINESS_DATE')):
            raise ValueError('moi_batch_identity_required')
        return cls(run_id, date, source, mode, dict(run_id=github_id, attempt=int(attempt)))

    @property
    def prefix(self):
        return 'receipts/' + self.business_date.replace('-', '') + '/pipeline-' + self.run_id

    def record(self):
        return dict(run_id=self.run_id, business_date=self.business_date, trigger_source=self.trigger_source,
                    execution_mode=self.execution_mode, github=self.github)
