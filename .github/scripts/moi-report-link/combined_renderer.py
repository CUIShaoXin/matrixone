"""Compact developer report using only accepted same-batch facts and findings."""
import html,json,re
from pathlib import Path
import subprocess,tempfile

NAMES={'matrixone':'MatrixOne','taas':'TaaS','matrixflow':'MatrixFlow'}
CSS='''*{box-sizing:border-box}body{margin:0;background:#f5f7fa;color:#1d2e40;font:16px/1.7 system-ui,-apple-system,"PingFang SC",sans-serif}main{max-width:1000px;margin:auto;padding:30px 24px}h1{font-size:30px}h2{font-size:25px;margin-top:30px}h3{font-size:21px;margin:0 0 10px;overflow-wrap:anywhere}article{background:white;border:1px solid #dce3ed;border-radius:11px;padding:21px;margin:15px 0}a{color:#265f9f;overflow-wrap:anywhere}.sub,.origin,footer{font-size:13px;color:#65768a}.overview{background:#e9f1fa;border-left:4px solid #3774b9;padding:14px 18px}.overview strong{display:block}.jump{display:flex;flex-wrap:wrap;gap:12px}.jump a{padding:5px 12px;background:white;border:1px solid #cfdaea;border-radius:6px;text-decoration:none}.component-head{display:flex;justify-content:space-between;gap:14px}.component-head>div{display:flex;gap:10px}.index{font-size:12px;color:#8191a4}.version{background:#edf3f9;padding:3px 9px;border-radius:5px;font-size:13px;overflow-wrap:anywhere}dl{margin:0}dl>div{display:grid;grid-template-columns:84px 1fr;gap:10px;margin:9px 0}dt{color:#65768a;font-size:14px}dd{margin:0;font-size:15px;overflow-wrap:anywhere}.action dd{font-weight:600}.location,details{border-top:1px solid #e9edf3;padding-top:10px;margin-top:10px;font-size:13px}summary{cursor:pointer;color:#456789}details p{overflow-wrap:anywhere}footer{border-top:1px solid #dce3ed;padding-top:16px;margin-top:24px}@media(max-width:650px){main{padding:22px 14px}h1{font-size:26px}article{padding:17px}.component-head{display:block}.version{display:inline-block;max-width:100%;margin:8px 0}dl>div{display:block}dt{font-size:12px}}'''
esc=lambda x:html.escape(str(x),quote=True)


def render(batch,files,code):
    # Keep the established focus selection and employee risk/action extraction.
    with tempfile.TemporaryDirectory() as tmp:
        root=Path(tmp)
        (root/'acceptance.json').write_text(json.dumps(batch))
        for (repo,kind),raw in files.items():(root/(repo+'-fullzip-'+kind+('.json' if kind=='osv' else '.md'))).write_bytes(raw)
        script="import {collectFocus} from './render_daily.mjs'; console.log(JSON.stringify(collectFocus(JSON.parse(process.argv[1]),process.argv[2]).focus));"
        result=subprocess.run(['node','--input-type=module','-e',script,json.dumps(batch),tmp],cwd=Path(__file__).parent,capture_output=True,text=True,check=True)
        focus=json.loads(result.stdout)
    components=[]
    for i,c in enumerate(focus,1):
        scan=json.loads(files[(c['repo'],'osv')]);versions=sorted({r['version'] for r in scan['package_version_results'] if r['package']['name']==c['name']})
        # Detail linking validates these values against the original scan records.
        components.append('<article data-component="'+esc(c['name'])+'"><div class="component-head"><div><span class="index">'+f'{i:02d}'+'</span><h3>'+esc(c['label'])+'</h3></div><span class="version">声明 '+esc(' / '.join(versions))+'</span></div><p class="origin">'+esc(c['repo'])+' · '+c['commit'][:8]+'</p><dl><div><dt>风险条件</dt><dd>'+esc(c['risk'])+'</dd></div><div class="action"><dt>检查与处理</dt><dd>'+esc(c['action'])+'</dd></div></dl></article>')
    findings=[]
    for repo,value in code.items():
        if value['commit']!=batch['results'][repo]['commit']:raise ValueError('render_code_commit_mismatch')
        for f in value['retained_findings']:
            locations=[]
            for e in f['evidence']:
                url='https://github.com/matrixorigin/'+repo+'/blob/'+value['commit']+'/'+e['path']+'#L'+str(e['line'])
                locations.append('<a href="'+esc(url)+'">'+esc(e['path']+':'+str(e['line']))+'</a>')
            findings.append('<article class="finding"><p class="origin">'+esc(NAMES[repo])+' · '+value['commit'][:8]+' · 待验证</p><h3>'+esc(f['title'])+'</h3><dl><div><dt>触发条件</dt><dd>'+esc(f['trigger'])+'</dd></div><div><dt>可能影响</dt><dd>'+esc(f['impact'])+'</dd></div><div class="action"><dt>处理建议</dt><dd>'+esc(f['suggested_fix'])+'</dd></div></dl><div class="location">'+' · '.join(locations)+'</div><details><summary>代码依据与验证方法</summary><p>'+esc(f['reasoning'])+'</p><p>'+esc(f['verification'])+'</p></details></article>')
    coverage=' · '.join(NAMES[r]+' '+str(code[r]['selected_files'])+'文件/'+str(code[r]['selected_lines'])+'行' for r in NAMES)
    empty='<article>本轮所审模块未保留证据充分的代码风险；不代表全仓没有漏洞。</article>'
    page='<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><meta http-equiv="Content-Security-Policy" content="default-src \'none\';style-src \'unsafe-inline\';base-uri \'none\';form-action \'none\'"><title>组件＋代码安全日报 · '+batch['date']+'</title><style>'+CSS+'</style></head><body><main><p class="sub">MATRIX · '+batch['date']+'</p><h1>组件＋代码安全日报</h1><p class="sub">MatrixOne · TaaS · MatrixFlow</p><div class="overview"><strong>'+str(len(components))+' 项组件重点 · '+str(len(findings))+' 项代码风险待验证</strong>先定位组件或代码，再核对触发条件和修复方案。</div><nav class="jump"><a href="#components">组件重点</a><a href="#code">代码风险</a></nav><section id="components"><h2>组件重点</h2>'+''.join(components)+'</section><section id="code"><h2>代码风险</h2><p class="sub">Kimi K3 初审和复核；有源码依据的风险线索，均需研发验证。</p>'+(''.join(findings) or empty)+'</section><footer>选定代码范围：'+esc(coverage)+'。未执行应用复现测试。<br>'+esc(' · '.join(NAMES[r]+' '+batch['results'][r]['commit'][:8] for r in NAMES))+'</footer></main></body></html>'
    return page.encode(),len(components),len(findings)
