import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const dependencies = process.env.MATRIX_NODE_MODULES || '/Users/cuishaoxin/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules';
const { Marked } = await import(pathToFileURL(path.join(dependencies, 'marked/lib/marked.esm.js')));
const escape = value => String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;');
const markdown = new Marked({ gfm: true, breaks: false });
markdown.use({ renderer: {
  html({ text }) { return escape(text); },
  image({ text }) { return `<span>${escape(text || '')}</span>`; },
  link({ href, tokens }) {
    const text = this.parser.parseInline(tokens);
    if (!/^https?:\/\//i.test(href || '') && !/^#[A-Za-z0-9_-]+$/.test(href || '')) return text;
    return `<a href="${escape(href)}" rel="noreferrer noopener">${text}</a>`;
  },
}});

export function render(batch, root) {
  const partial = batch.single_repository_test === true;
  const repositories = partial ? ['matrixone'] : ['matrixone', 'taas', 'matrixflow'];
  const title = partial ? 'MatrixOne 单仓链路验证完整报告' : '三仓依赖安全完整报告';
  if (!/^\d{4}-\d{2}-\d{2}$/.test(batch.date) || (!batch.three_repository_reports_accepted && !(partial && Object.keys(batch.results).length === 1 && batch.results.matrixone))) throw Error('unaccepted_report_batch');
  const sha = /^[0-9a-f]{40}$/;
  let rows = '', sections = '';
  for (const repo of repositories) {
    const result = batch.results[repo];
    if (!result || !sha.test(result.commit) || !result.independent_readback_verified || !result.kb_marker_retrieved) throw Error('report_acceptance_missing:' + repo);
    const c = result.counts;
    rows += `<tr><td><a href="#${repo}">${repo}</a></td><td>${repo === 'matrixflow' ? 'dev' : 'main'} / <code>${result.commit.slice(0, 8)}</code></td><td>${c.input_files}</td><td>${c.affected_component_names}</td><td>${c.unique_advisory_alias_groups}</td></tr>`;
    const employee = fs.readFileSync(path.join(root, repo + '-fullzip-employee.md'), 'utf8');
    const details = fs.readFileSync(path.join(root, repo + '-fullzip-details.md'), 'utf8');
    sections += `<section id="${repo}"><h2>${repo} · ${escape(batch.date)}</h2><p class="meta">${repo === 'matrixflow' ? 'dev' : 'main'} · <code>${result.commit}</code></p><article>${markdown.parse(employee)}</article><details><summary>展开 ${repo} 完整漏洞明细、公告正文与覆盖范围</summary><article class="technical">${markdown.parse(details)}</article></details></section>`;
  }
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>${title} · ${batch.date}</title><style>
:root{color-scheme:light}*{box-sizing:border-box}body{margin:0;background:#f4f6fa;color:#18283a;font:16px/1.75 system-ui,-apple-system,"PingFang SC",sans-serif}main{max-width:1080px;margin:auto;padding:30px 20px 70px}h1{font-size:30px;line-height:1.4}h2{font-size:24px}h3{font-size:19px}p,li{overflow-wrap:anywhere}.meta{color:#52677e;font-size:14px}.notice{padding:16px 20px;background:#fff3dc;border:1px solid #ecd09c;border-radius:10px}nav{display:flex;gap:12px;flex-wrap:wrap;margin:22px 0}a{color:#195bb4}nav a{padding:7px 15px;border:1px solid #bdcce0;border-radius:7px;text-decoration:none;background:white}section{margin:30px 0;background:white;border:1px solid #dce3ed;border-radius:12px;padding:24px;scroll-margin-top:15px}table{border-collapse:collapse;width:100%;font-size:14px}th,td{border:1px solid #dce3ed;text-align:left;padding:9px 12px;vertical-align:top;overflow-wrap:anywhere}th{background:#edf2f8}code{font-size:13px;background:#edf2f8;padding:2px 4px;border-radius:3px}pre{padding:14px;background:#edf2f8;white-space:pre-wrap;overflow-wrap:anywhere;overflow:auto}pre code{padding:0}details{margin-top:24px;border-top:1px solid #dce3ed;padding-top:18px}summary{cursor:pointer;color:#195bb4;font-weight:650}.technical{font-size:14px}.technical h2,.technical h3{margin-top:32px}.overview{overflow:auto}blockquote{border-left:3px solid #ccd7e6;margin-left:0;padding-left:16px}footer{color:#52677e;font-size:13px}@media(max-width:640px){main{padding:18px 12px 45px}h1{font-size:25px}section{padding:16px}table{min-width:540px}article{overflow:auto}}@media print{body{background:white}main{max-width:none}section{break-before:page;border:0}nav{display:none}}
</style></head><body><main><p class="meta">Matrix · 依赖安全检查 · ${batch.date}</p><h1>${title}</h1><div class="notice">${partial ? '这是当天 MatrixOne 单仓云端验收，未发群，三仓每日链路尚未验收。' : ''}请研发优先评估报告中的重点组件，普通同事暂不需要操作。检查基于 MinIO 固定提交 ZIP 中的依赖声明和锁定版本，采用 OSV API 匹配。公告命中不等于线上可利用，升级候选仍需核实发布状态与兼容性。各仓公告组数分别去重，不能直接相加作为全局唯一数。</div><nav><a href="#overview">检查概况</a><a href="#matrixone">MatrixOne</a>${partial ? '' : '<a href="#taas">TaaS</a><a href="#matrixflow">MatrixFlow</a>'}</nav><section id="overview"><h2>检查概况</h2><div class="overview"><table><thead><tr><th>仓库</th><th>分支 / 提交</th><th>清单路径</th><th>命中组件</th><th>公告组</th></tr></thead><tbody>${rows}</tbody></table></div><p class="meta">扫描日期为 ${batch.date}。范围与引用仍有未解析项，未进行运行可达性和升级兼容测试；无同口径历史基线，暂不判断新增或修复。各仓完整明细可在下方展开。</p></section>${sections}<footer>报告日期 ${batch.date} · MinIO 分享副本 · MOI 知识库 matrix_security_daily（80001）保留原始归档。链接有效期以群消息为准。</footer></main></body></html>`;
}

if (process.argv[2] === '--render') {
  const [,, , receipt, source, destination] = process.argv;
  const batch = JSON.parse(fs.readFileSync(receipt, 'utf8'));
  fs.writeFileSync(destination, render(batch, source));
  console.log(JSON.stringify({ output: destination, bytes: fs.statSync(destination).size, report_date: batch.date, repositories: Object.keys(batch.results) }));
}
