"""Same-batch component drill-down pages; no scanning or model review."""
import datetime as dt
import hashlib
import html
from html.parser import HTMLParser
import json
import re
import urllib.parse

sha = lambda raw: hashlib.sha256(raw).hexdigest()
esc = lambda value: html.escape(str(value), quote=True)

def require(value, code):
    if not value:
        raise ValueError(code)

def safe_url(value):
    parsed = urllib.parse.urlsplit(value)
    return value if parsed.scheme == 'https' and parsed.netloc and not parsed.username and not parsed.password else None

class CardParser(HTMLParser):
    def __init__(self):
        super().__init__(); self.cards=[]; self.card=None; self.depth=0; self.field=None
    def handle_starttag(self, tag, attrs):
        attrs=dict(attrs)
        if tag=='article' and attrs.get('data-component'):
            require(self.card is None, 'nested_component_card')
            self.card=dict(component=attrs['data-component'],title='',origin='',version='',conditions='',action='');self.depth=1
        elif self.card is not None:
            if tag=='article':self.depth+=1
            if tag=='h3':self.field='title'
            elif tag=='p' and attrs.get('class')=='origin':self.field='origin'
            elif tag=='span' and attrs.get('class')=='version':self.field='version'
            elif tag=='dt':self.field='label';self.card['label']=''
            elif tag=='dd':self.field={'风险条件':'conditions','检查与处理':'action'}.get(self.card.get('label'))
    def handle_endtag(self, tag):
        if self.card is not None:
            if tag=='article':
                self.depth-=1
                if not self.depth:
                    self.cards.append(self.card);self.card=None
            if tag in ('h3','p','span','dt','dd'):self.field=None
    def handle_data(self, data):
        if self.card is not None and self.field:self.card[self.field]=self.card.get(self.field,'')+data

def cards_from(page, commits):
    parser=CardParser();parser.feed(page.decode());require(bool(parser.cards),'component_cards_missing')
    seen=set()
    for card in parser.cards:
        name, short = [v.strip() for v in card['origin'].split('·',1)]
        repo=name.lower();require(repo in commits and commits[repo].startswith(short),'card_commit_mismatch')
        card['repository']=repo;card['commit']=commits[repo]
        require((repo,card['component']) not in seen,'duplicate_component_identity');seen.add((repo,card['component']))
        require(all(card[k] for k in ('title','version','conditions','action')),'component_card_incomplete')
    return parser.cards

def component_data(card, osv, date):
    repo, component, commit=card['repository'],card['component'],card['commit']
    require(osv['commit']==commit and osv['facts']['report_date_shanghai']==date and osv['facts']['repository']=='matrixorigin/'+repo,'detail_source_identity_mismatch')
    rows=[r for r in osv['package_version_results'] if r['package']['name']==component]
    require(rows and len({r['package']['ecosystem'] for r in rows})==1,'component_coordinate_ambiguous')
    require(len({r['version'] for r in rows})==len(rows),'duplicate_component_version')
    shown=card['version'].removeprefix('声明 ').split(' / ')
    require(set(shown)=={r['version'] for r in rows},'card_declared_versions_mismatch')
    ids=sorted({i for r in rows for i in r['vulnerability_ids']})
    advisories=osv['full_advisories'];require(all(i in advisories and advisories[i]['id']==i for i in ids),'component_advisory_body_missing')
    manifest_paths={m['path'] for m in osv['manifest_inventory']}
    for row in rows:
        require(bool(row['sources']),'dependency_location_missing')
        for source in row['sources']:
            require(source['file'] in manifest_paths,'dependency_manifest_not_accepted')
            require(source.get('line') is None or isinstance(source['line'],int) and source['line']>0,'dependency_line_invalid')
    return dict(date=date,repository=repo,commit=commit,component=component,ecosystem=rows[0]['package']['ecosystem'],rows=rows,advisory_ids=ids,advisories={i:advisories[i] for i in ids},conditions=card['conditions'],action=card['action'],title=card['title'])

def link(url, label):
    value=safe_url(url)
    return '<a href="'+esc(value)+'" target="_blank" rel="noopener noreferrer">'+esc(label)+'</a>' if value else esc(label)

def render_detail(data):
    dep=[];versions=[]
    for row in data['rows']:
        versions.append('<li><strong>'+esc(row['version'])+'</strong> · '+str(len(row['vulnerability_ids']))+' 条公告记录</li>')
        for source in row['sources']:
            path=source['file'];number=source.get('line')
            url='https://github.com/matrixorigin/'+data['repository']+'/blob/'+data['commit']+'/'+urllib.parse.quote(path,safe='/')+('#L'+str(number) if number else '')
            dep.append('<tr><td>'+esc(row['version'])+'</td><td>'+link(url,path+(':'+str(number) if number else ''))+'</td><td>'+esc(source['declared'])+'</td></tr>')
    notices=[]
    for aid in data['advisory_ids']:
        advisory=data['advisories'][aid]
        matching=[r['version'] for r in data['rows'] if aid in r['vulnerability_ids']]
        severity=advisory.get('database_specific',{}).get('severity')
        scores=advisory.get('severity',[])
        ranges=[a for a in advisory.get('affected',[]) if a.get('package',{}).get('name')==data['component'] and a.get('package',{}).get('ecosystem')==data['ecosystem']]
        references=[]
        for ref in advisory.get('references',[]):
            if safe_url(ref.get('url','')):references.append('<li>'+link(ref['url'],ref.get('type','参考')+' · '+ref['url'])+'</li>')
        notices.append('<article data-advisory="'+esc(aid)+'"><h3>'+link('https://osv.dev/vulnerability/'+urllib.parse.quote(aid,safe=''),aid)+'</h3><p>'+esc(advisory.get('summary') or '公告未提供摘要，请展开正文')+'</p><p class="meta">匹配声明版本：'+esc(' / '.join(matching))+' · 公告严重性：'+esc(severity or '未提供统一等级')+'</p><p class="meta">别名：'+esc(' · '.join(advisory.get('aliases',[])) or '未提供')+'</p><details><summary>触发条件、影响与维护者处理说明（公告原文）</summary><pre>'+esc(advisory.get('details') or '公告未提供正文；本项条件与影响尚不完整。')+'</pre></details><details><summary>版本范围与评分（原始记录）</summary><pre>'+esc(json.dumps(dict(affected=ranges,severity=scores,published=advisory.get('published'),modified=advisory.get('modified'),withdrawn=advisory.get('withdrawn')),ensure_ascii=False,indent=2))+'</pre><p>范围中的修复版本只作为公告依据；未执行兼容性回归，不能据此认定可直接升级。</p></details><details><summary>公告来源</summary><ul>'+''.join(references)+'</ul></details></article>')
    identity={k:data[k] for k in ('date','repository','commit','component','ecosystem')};identity.update(versions=[r['version'] for r in data['rows']],advisory_ids=data['advisory_ids'])
    raw='<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><title>'+esc(data['title']+' · '+data['repository']+' · '+data['date'])+' 组件详情</title><style>body{margin:0;background:#f5f7fb;color:#213247;font:16px/1.65 system-ui,sans-serif}main{max-width:980px;margin:auto;padding:28px 20px}h1{font-size:32px;margin:8px 0}h2{margin-top:28px;font-size:23px}h3{margin:0 0 8px}a{color:#246ab6;overflow-wrap:anywhere}header,article,.panel{background:white;border:1px solid #dbe3ef;border-radius:12px;padding:22px;margin:16px 0}.meta{color:#63748b;font-size:14px;overflow-wrap:anywhere}.notice{background:#eaf1fa;padding:14px;border-left:3px solid #3976c3}table{width:100%;border-collapse:collapse;font-size:14px}td,th{text-align:left;border-bottom:1px solid #e1e8f1;padding:10px;overflow-wrap:anywhere}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:14px/1.6 ui-monospace,monospace;background:#f5f7fb;padding:14px;border-radius:8px}summary{cursor:pointer;color:#35628b;margin:12px 0}details{border-top:1px solid #e4eaf2}ul{padding-left:22px}@media(max-width:600px){main{padding:14px 10px}header,article,.panel{padding:16px}h1{font-size:27px}td,th{padding:7px 4px}}</style></head><body><main><header><p class="meta">组件详情 · '+esc(data['date'])+'</p><h1>'+esc(data['title'])+'</h1><p>'+esc(data['component'])+'</p><p class="meta">仓库 '+esc(data['repository'])+' · 固定提交 '+esc(data['commit'])+'</p><p class="notice">本页来自当天已验收的依赖清单与 OSV 公告匹配。实际调用、部署版本及漏洞能否触发，仍需研发验证。</p></header><section class="panel"><h2>先检查什么</h2><p><strong>风险条件：</strong>'+esc(data['conditions'])+'</p><p><strong>检查与处理：</strong>'+esc(data['action'])+'</p><p>逐条核对下方公告的必要条件、已存在的防护及影响范围；使用隔离环境复现并回归相关业务路径。</p></section><section class="panel"><h2>声明版本与依赖位置</h2><ul>'+''.join(versions)+'</ul><table><thead><tr><th>版本</th><th>清单位置</th><th>原始声明</th></tr></thead><tbody>'+''.join(dep)+'</tbody></table><p class="meta">锁文件可能记录多个版本；provided 声明不代表部署版本。没有行号的解析结果仅链接到文件。</p></section><section><h2>全部匹配公告 · '+str(len(data['advisory_ids']))+' 条记录</h2><p class="meta">同一漏洞可能由多个数据库分别记录，条数不等于独立漏洞数量。长正文按需展开。</p>'+''.join(notices)+'</section><footer class="meta">只展示本组件的本批结果。未执行运行时可达性分析、依赖安装解析或业务回归。</footer><script type="application/json" id="component-identity">'+json.dumps(identity,ensure_ascii=False).replace('<','\\u003c')+'</script></main></body></html>'
    return raw.encode()

def publish_and_link(job, source, page):
    cards=cards_from(page,source['commits'])
    stamp=job.state.get('component_link_signing_at')
    at=dt.datetime.fromisoformat(stamp) if stamp else dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    require(at+dt.timedelta(days=7)>dt.datetime.now(dt.timezone.utc)+dt.timedelta(hours=1),'detail_revision_links_near_expiry')
    job.state['component_link_signing_at']=at.isoformat();job.journal.save()
    entries=[];text=page.decode();md=[]
    def replace_card(match):
        nonlocal entries
        fragment=match.group(0)
        parser=CardParser();parser.feed(fragment)
        card=next(c for c in cards if c['component']==parser.cards[0]['component'] and c['origin']==parser.cards[0]['origin'])
        data=component_data(card,job.component_osv[card['repository']],source['report_date'])
        raw=render_detail(data)
        identity_digest=sha((data['ecosystem']+'\0'+data['component']).encode())[:16]
        key='reports/'+source['report_date'].replace('-','')+'/component-details/'+data['repository']+'/'+data['commit']+'/'+identity_digest+'/'+sha(raw)[:16]+'/component.html'
        published=job.objects.publish(key,raw,'text/html; charset=utf-8')
        url,expiry=job.objects.presign(key,at=at)
        from cloud_publish import verify_login_free
        check=verify_login_free(url,raw)
        entry=dict(repository=data['repository'],commit=data['commit'],component=data['component'],ecosystem=data['ecosystem'],versions=[r['version'] for r in data['rows']],advisory_ids=data['advisory_ids'],published=published,url=url,expires_at_utc=expiry,login_free_verification=check)
        entries.append(entry)
        md.append('## '+data['repository']+' · '+data['component']+'\n[单组件详情]('+url+')\n声明版本：'+' / '.join(entry['versions'])+'；匹配公告记录 '+str(len(entry['advisory_ids'])))
        # Replace exactly the title content; every other card byte is preserved.
        title=re.search(r'<h3>(.*?)</h3>',fragment,re.S);require(title is not None,'component_title_missing')
        linked='<a class="component-detail-link" href="'+esc(url)+'" target="_blank" rel="noopener noreferrer" title="打开本仓库的组件详情">'+html.escape(card['title'])+'</a>'
        return fragment[:title.start(1)]+linked+fragment[title.end(1):]
    text,count=re.subn(r'<article data-component="[^\"]+">.*?</article>',replace_card,text,flags=re.S)
    require(count==len(cards)==len(entries),'detail_title_link_count_mismatch')
    # Make links discoverable while retaining the accepted typography.
    text=text.replace('</style>','.component-head h3 .component-detail-link{color:inherit;text-decoration:underline;text-decoration-color:#a9bed5;text-underline-offset:5px}.component-head h3 .component-detail-link:hover{color:#246ab6}</style>',1)
    job.store('component-detail-index-private.json',entries)
    job.event('component_details',status='passed',pages=len(entries))
    return text.encode(),entries,'\n\n'.join(md),at

def revise(job, source):
    import os
    from api_port_review import publish_report, render
    from cloud_daily import verify_rag
    fid=os.environ.get('MATRIX_COMBINED_RECEIPT_FILE_ID','');expected=os.environ.get('MATRIX_COMBINED_RECEIPT_SHA256','')
    require(re.fullmatch(r'[0-9a-f-]{36}',fid) and re.fullmatch(r'[0-9a-f]{64}',expected),'combined_receipt_required')
    receipt_raw=job.api.file(fid);require(sha(receipt_raw)==expected,'combined_receipt_hash_mismatch');previous=json.loads(receipt_raw)
    require(previous['schema']=='matrix_api_port_publication_v1' and previous['report_date']==source['report_date'] and previous['commits']==source['commits'] and previous['source_receipt_file_id']==job.state['source_id'] and previous['source_receipt_sha256']==job.state['source_sha256'] and previous['kb_marker_retrieved'],'combined_source_not_accepted')
    oldrun=previous['run_id'];require(re.fullmatch(r'[A-Za-z0-9_-]{1,80}',oldrun),'invalid_prior_run')
    prefix='receipts/'+source['report_date'].replace('-','')+'/api-port-'+oldrun
    cp=json.loads(job.objects.call('GET',prefix+'/checkpoint.json')[2]);require(cp.get('published') and cp['commits']==source['commits'],'prior_checkpoint_not_accepted')
    results={}
    for repo in source['commits']:
        proof=cp['repositories'][repo]['result'];raw=job.objects.call('GET',proof['key'])[2]
        require(len(raw)==proof['bytes'] and sha(raw)==proof['sha256'],'prior_review_result_hash_mismatch');results[repo]=json.loads(raw)
        require(results[repo]['commit']==source['commits'][repo],'prior_review_commit_mismatch')
    original=job.objects.call('GET',previous['published']['key'])[2]
    require(len(original)==previous['published']['bytes'] and sha(original)==previous['published']['sha256'],'prior_combined_page_mismatch')
    original_source=job.objects.call('GET',source['published']['key'])[2]
    rendered,_,oldmarker,_=render(source,original_source,results,oldrun)
    require(rendered==original,'prior_combined_render_mismatch')
    task=job.api.rpc('tasks/get',{'id':cp['audit_task_id']},'component-revision-source-read-'+job.state['run_id'])
    verify_rag(task,[dict(file_id=previous['markdown_artifact']['file_id'],marker=oldmarker)])
    md=job.api.file(previous['markdown_artifact']['file_id']);require(sha(md)==previous['markdown_artifact']['sha256'],'prior_markdown_hash_mismatch')
    marker='MATRIX-COMPONENT-DETAILS-'+source['report_date'].replace('-','')+'-'+job.state['run_id']
    job.state['publication_revision_source']=dict(file_id=fid,sha256=expected,prior_run_id=oldrun);job.journal.save()
    return publish_report(job,source,original_source,results,rendered=(original,md+b'\n\n'+marker.encode(),marker,previous['added_findings']))
