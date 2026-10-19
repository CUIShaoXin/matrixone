"""Validated archive schema and SQL allowlist shared by cloud preparation."""
from datetime import datetime
import hashlib
import re
import uuid

WORKSPACE = 'fd3f15fe-3ac3-1c8c-5020-dffec978a0cb'

REPOS = ('matrixone', 'taas', 'matrixflow')

STATUSES = {'clean', 'vulnerabilities_found', 'scan_partial', 'scan_failed', 'pending', 'unavailable'}

COLUMNS = {
    'scan_runs': set('archive_id archive_batch_id report_date repository branch commit_sha scan_started_at scan_finished_at execution_source source_run_id source_run_attempt scan_status vulnerability_hits unique_ids packages coverage_note error_code raw_file_id stderr_file_id evidence_file_id report_sha256 source_url archived_at artifact_status scanner_version'.split()),
    'daily_reports': set('archive_batch_id report_date prepared_at matrixone_archive_id taas_archive_id matrixflow_archive_id message_file_id message_sha256 archive_status archive_error workflow_execution_id archived_at'.split()),
}

def sha(data):
    return hashlib.sha256(data).hexdigest()

def summarize(report):
    hits, identifiers, packages = 0, set(), set()
    for result in report.get('results', []):
        for item in result.get('packages', []):
            vulns = item.get('vulnerabilities', [])
            if vulns:
                packages.add(item['package']['name'])
            for vuln in vulns:
                hits += 1
                cves = [v for v in vuln.get('aliases', []) if v.startswith('CVE-')]
                identifiers.add(cves[0] if cves else vuln['id'])
    return hits, len(identifiers), len(packages)

def valid_id(value):
    uuid.UUID(value)
    return value

def sql_literal(value):
    if value is None:
        return 'NULL'
    if type(value) is int:
        return str(value)
    if not isinstance(value, str):
        raise ValueError('Unexpected SQL value type')
    return "'" + value.replace('\\', '\\\\').replace("'", "''").replace('\x00', '') + "'"

def upsert_sql(table, row, primary_key, preserve=()):
    if table not in ('scan_runs', 'daily_reports'):
        raise ValueError('Table is not whitelisted')
    if set(row) != COLUMNS[table]:
        raise ValueError('Unexpected or missing archive columns')
    if not all(re.fullmatch('[a-z_][a-z_0-9]*', k) for k in row):
        raise ValueError('Invalid column name')
    columns = ', '.join('`' + k + '`' for k in row)
    values = ', '.join(sql_literal(v) for v in row.values())
    updates = ', '.join('`' + k + '`=VALUES(`' + k + '`)' for k in row if k != primary_key and k not in preserve)
    return f'INSERT INTO security_scan_archive.{table} ({columns}) VALUES ({values}) ON DUPLICATE KEY UPDATE {updates}'

def sql_inputs(payload):
    validate(payload)
    daily = payload['daily_report']
    valid_id(daily['message_file_id'])
    batch = sql_literal(payload['archive_batch_id'])
    return dict(archive_batch_id=payload['archive_batch_id'],
                matrixone_sql=upsert_sql('scan_runs', payload['matrixone'], 'archive_id'),
                taas_sql=upsert_sql('scan_runs', payload['taas'], 'archive_id'),
                matrixflow_sql=upsert_sql('scan_runs', payload['matrixflow'], 'archive_id'),
                daily_report_sql=upsert_sql('daily_reports', daily, 'archive_batch_id'),
                verify_sql=('SELECT r.repository,r.scan_status,r.vulnerability_hits,r.unique_ids,r.packages,'
                            'r.raw_file_id,r.artifact_status,d.archive_status,d.message_file_id,d.message_sha256 '
                            'FROM security_scan_archive.scan_runs r LEFT JOIN security_scan_archive.daily_reports d '
                            'ON r.archive_batch_id=d.archive_batch_id WHERE r.archive_batch_id=' + batch + ' ORDER BY r.repository'),
                text=payload['daily_report_text'])

def validate(payload):
    batch = payload['archive_batch_id']
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', batch):
        raise ValueError('Invalid archive batch ID')
    daily = payload['daily_report']
    date = daily['report_date']
    if not re.fullmatch(r'\d{4}-\d{2}-\d{2}', date):
        raise ValueError('Invalid report date format')
    datetime.strptime(date, '%Y-%m-%d')
    if daily['archive_batch_id'] != batch:
        raise ValueError('Daily batch mismatch')
    if sha(payload['daily_report_text'].encode()) != daily['message_sha256']:
        raise ValueError('Daily message digest mismatch')
    if daily['message_file_id']:
        valid_id(daily['message_file_id'])
    for name in REPOS:
        row = payload[name]
        if row['repository'] != 'matrixorigin/' + name:
            raise ValueError('Repository mismatch')
        if row['archive_batch_id'] != batch or row['report_date'] != date:
            raise ValueError('Repository batch/date mismatch')
        if not row['archive_id'] or row['scan_status'] not in STATUSES:
            raise ValueError('Missing primary key or invalid scan status')
        counters = [row[k] for k in ('vulnerability_hits', 'unique_ids', 'packages')]
        if row['scan_status'] in {'scan_failed', 'pending', 'unavailable'}:
            if counters != [None, None, None]:
                raise ValueError('Unknown counters must be null')
        elif not all(type(v) is int and v >= 0 for v in counters):
            raise ValueError('Counters must be non-negative integers')
        elif (counters[1] > counters[0] or counters[2] > counters[0]
              or row['scan_status'] == 'clean' and counters[0] != 0
              or row['scan_status'] == 'vulnerabilities_found' and counters[0] == 0):
            raise ValueError('Inconsistent scan counters/status')
        if row['report_sha256'] and not re.fullmatch('[0-9a-f]{64}', row['report_sha256']):
            raise ValueError('Invalid report digest')
        for key in ('raw_file_id', 'stderr_file_id', 'evidence_file_id'):
            if row[key]:
                valid_id(row[key])
        if not row['evidence_file_id']:
            raise ValueError('Every scan state requires uploaded evidence')
        if row['artifact_status'] == 'files_uploaded' and not all(
                row[k] for k in ('raw_file_id', 'stderr_file_id', 'report_sha256')):
            raise ValueError('Full archive requires raw report, stderr, and digest')
        if row['artifact_status'] not in {'files_uploaded', 'summary_only', 'evidence_only'}:
            raise ValueError('Invalid artifact status')
        if daily[name + '_archive_id'] != row['archive_id']:
            raise ValueError('Daily record association mismatch')
    return payload

