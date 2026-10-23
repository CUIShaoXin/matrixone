import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const escape = value => String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;');
const digest = raw => crypto.createHash('sha256').update(raw).digest('hex');
const names = { 'golang.org/x/crypto': 'x/crypto', 'github.com/jackc/pgx/v5': 'pgx/v5', 'vitess.io/vitess': 'Vitess', 'google.golang.org/grpc': 'gRPC' };

function artifact(root, repo, result, kind) {
  const raw = fs.readFileSync(path.join(root, `${repo}-fullzip-${kind}.${kind === 'osv' ? 'json' : 'md'}`));
  const expected = result.artifacts[kind];
  if (raw.length !== expected.bytes || digest(raw) !== expected.sha256) throw Error('focus_source_hash_mismatch:' + repo + ':' + kind);
  return raw.toString('utf8');
}

export function collectFocus(batch, root) {
  const partial = batch.single_repository_test === true;
  const repos = partial ? ['matrixone'] : ['matrixone', 'taas', 'matrixflow'];
  if (!/^\d{4}-\d{2}-\d{2}$/.test(batch.date) || (!batch.three_repository_reports_accepted && !partial)
      || JSON.stringify(Object.keys(batch.results).sort()) !== JSON.stringify([...repos].sort())) throw Error('focus_unaccepted_batch');
  const editsFile = path.join(root, 'focus-edits.json');
  const edits = fs.existsSync(editsFile) ? JSON.parse(fs.readFileSync(editsFile, 'utf8')) : {};
  const groups = repos.map(repo => {
    const result = batch.results[repo];
    if (!/^[0-9a-f]{40}$/.test(result.commit) || !result.independent_readback_verified || !result.kb_marker_retrieved) throw Error('focus_source_unaccepted');
    const scan = JSON.parse(artifact(root, repo, result, 'osv'));
    if (scan.commit !== result.commit || scan.facts.report_date_shanghai !== batch.date) throw Error('focus_source_date_or_commit_mismatch');
    const employee = artifact(root, repo, result, 'employee');
    const bullets = employee.match(/(?:^|\n)[ \t]*[-•][ \t]+[\s\S]*?(?=\n[ \t]*[-•][ \t]+|$)/g) || [];
    return (scan.facts.priority_components || []).flatMap(component => {
      const bullet = bullets.find(p => p.includes(component.name));
      if (!bullet) return [];
      const edit = edits[repo]?.[component.name];
      const risk = edit?.risk || bullet.match(/影响(?:\/触发)?[：:]([\s\S]*?)(?:候选(?:评估)?|建议(?:动作)?[：:]|$)/)?.[1]?.trim();
      if (!risk) throw Error('focus_impact_summary_missing:' + component.name);
      const action = edit?.action || bullet.match(/建议(?:动作)?[：:]([\s\S]*?)(?:候选(?:评估)?|$)/)?.[1]?.trim()
        || '先确认是否使用上述功能；涉及该路径后再安排修复评估与回归。';
      const candidate = (scan.facts.candidate_evaluations || []).find(c => c.component === component.name);
      const checked = candidate?.status === 'candidate_osv_checked' && Array.isArray(candidate.remaining_ids);
      const review = checked ? (candidate.remaining_ids.length ? `仍匹配 ${candidate.remaining_ids.length} 条公告` : '本轮 OSV 未匹配')
        : candidate?.status === 'candidate_osv_query_failed' ? '复查失败，风险余量未知' : '尚未完成复查';
      return [{ repo, commit: result.commit, name: component.name, label: names[component.name] || component.name,
        versions: Object.keys(component.versions || {}), risk, action, candidate: candidate?.version || '未确认', review,
        published: candidate?.published_version_verified === true, compatible: candidate?.compatibility_tested === true }];
    }).slice(0, 3);
  });
  // Give every selected repository a place before adding further components; never fill with non-priority findings.
  const focus = [];
  for (let i = 0; i < 3 && focus.length < 5; i++) for (const group of groups) if (group[i] && focus.length < 5) focus.push(group[i]);
  return { partial, focus };
}

export function render(batch, root) {
  const { partial, focus } = collectFocus(batch, root);
  const scope = partial ? 'MatrixOne 单仓结果 · 三仓日报尚未验收' : 'MatrixOne · TaaS · MatrixFlow';
  const cards = focus.map((c, i) => `<article data-component="${escape(c.name)}"><div class="component-head"><div><span class="index">0${i + 1}</span><h2>${escape(c.label)}</h2></div><span class="version">当前 ${escape(c.versions.join(' / '))}</span></div><p class="origin">${escape(c.repo)} · ${c.commit.slice(0, 8)}</p><dl><div><dt>风险与条件</dt><dd>${escape(c.risk)}</dd></div><div class="action"><dt>先做什么</dt><dd>${escape(c.action)}</dd></div></dl><p class="candidate">评估候选 <strong>${escape(c.candidate)}</strong><span class="separator">·</span>${escape(c.review)}${c.published ? ' · 已核实发布' : ' · 发布未核实'}${c.compatible ? ' · 兼容性已测试' : ''}</p></article>`).join('');
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>依赖安全日报 · ${batch.date}</title><style>
*{box-sizing:border-box}body{margin:0;background:#f6f7f9;color:#18283a;font:16px/1.65 system-ui,-apple-system,"PingFang SC",sans-serif}main{max-width:900px;margin:auto;padding:32px 24px 38px}.eyebrow{font-size:13px;color:#627084;margin:0 0 8px;letter-spacing:.03em}h1{font-size:30px;line-height:1.3;margin:0 0 8px}.scope{color:#627084;font-size:14px;margin:0}.intro{margin:22px 0;padding:12px 16px;border-left:3px solid #3872b5;background:#eaf1f9;font-size:14px}article{background:#fff;border:1px solid #dee4ec;border-radius:10px;margin:14px 0;padding:18px 22px}.component-head{display:flex;justify-content:space-between;align-items:center;gap:12px}.component-head>div{display:flex;align-items:center;gap:12px}.index{font-size:12px;color:#8090a3;font-weight:650}h2{font-size:21px;margin:0;line-height:1.35;overflow-wrap:anywhere}.version{font-size:13px;color:#425976;white-space:nowrap;background:#eef3f9;padding:3px 9px;border-radius:5px}.origin{font-size:12px;color:#6c7b8d;margin:5px 0 12px 28px}dl{margin:0}dl>div{display:grid;grid-template-columns:90px 1fr;gap:12px;margin:8px 0}dt{font-size:14px;color:#607085}dd{margin:0;font-size:15px;overflow-wrap:anywhere}.action dd{font-weight:600}.candidate{border-top:1px solid #edf0f4;padding-top:11px;margin:13px 0 0;font-size:13px;color:#53657c;overflow-wrap:anywhere}.separator{margin:0 8px}footer{font-size:12px;color:#6b7787;margin-top:20px;line-height:1.8}footer p{margin:4px 0}@media(max-width:600px){main{padding:22px 14px}h1{font-size:26px}article{padding:16px}.component-head{align-items:flex-start;flex-direction:column;gap:7px}.origin{margin-left:0}dl>div{grid-template-columns:1fr;gap:2px;margin:12px 0}.version{margin-left:28px}dt{font-size:12px}.candidate{line-height:1.8}}@media print{body{background:white}main{padding:0;max-width:none}article{break-inside:avoid}}
</style></head><body><main><header><p class="eyebrow">MATRIX · ${batch.date}</p><h1>依赖安全日报</h1><p class="scope">${scope}</p></header><p class="intro">${focus.length ? `本期关注 ${focus.length} 个重点组件。研发先核实使用条件，再安排修复评估。` : '本期未选出需要优先评估的组件，完整扫描结果已归档。'}</p>${cards}<footer><p>公告匹配不等于线上可利用；候选版本仍需核实发布状态并完成兼容性回归。</p><p>这里只展示重点组件。完整扫描证据与公告正文保留在原归档中。</p></footer></main></body></html>`;
}

export function runCli() {
  if (process.argv[2] !== '--render') return;
  const [,,, receipt, source, destination] = process.argv;
  const batch = JSON.parse(fs.readFileSync(receipt, 'utf8'));
  fs.writeFileSync(destination, render(batch, source));
  console.log(JSON.stringify({ bytes: fs.statSync(destination).size, report_date: batch.date,
    focus_components: collectFocus(batch, source).focus.map(c => c.name), presentation: 'daily-focus' }));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) runCli();
