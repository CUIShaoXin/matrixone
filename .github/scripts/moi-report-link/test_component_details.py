import copy
import datetime as dt
import unittest
from unittest.mock import patch
import component_details as m

class DetailTests(unittest.TestCase):
    def fixture(self, repo='matrixone'):
        commit=('a' if repo=='matrixone' else 'b')*40
        card=dict(repository=repo,component='golang.org/x/crypto',commit=commit,title='x/crypto',version='声明 0.51.0',conditions='<script>risk</script>',action='check')
        osv=dict(commit=commit,facts=dict(report_date_shanghai='2026-10-23',repository='matrixorigin/'+repo),manifest_inventory=[dict(path='go.mod')],package_version_results=[dict(package=dict(name=card['component'],ecosystem='Go'),version='0.51.0',sources=[dict(file='go.mod',line=2,declared='0.51.0')],vulnerability_ids=['A','B'])],full_advisories={'A':dict(id='A',summary='A',details='<img src=x onerror=alert(1)>',references=[dict(url='javascript:alert(1)',type='WEB')]),'B':dict(id='B',details='second')})
        return card,osv
    def test_identity_versions_and_complete_advisories(self):
        card,osv=self.fixture();data=m.component_data(card,osv,'2026-10-23');self.assertEqual(data['advisory_ids'],['A','B'])
        del osv['full_advisories']['B']
        with self.assertRaisesRegex(ValueError,'body_missing'):m.component_data(card,osv,'2026-10-23')
        card,osv=self.fixture('taas');osv['commit']='a'*40
        with self.assertRaisesRegex(ValueError,'identity_mismatch'):m.component_data(card,osv,'2026-10-23')
        card,osv=self.fixture();card['version']='声明 0.9.0'
        with self.assertRaisesRegex(ValueError,'versions_mismatch'):m.component_data(card,osv,'2026-10-23')
    def test_untrusted_advisory_is_escaped(self):
        card,osv=self.fixture();raw=m.render_detail(m.component_data(card,osv,'2026-10-23')).decode()
        self.assertIn('&lt;img',raw);self.assertNotIn('<img src=x',raw);self.assertNotIn('href="javascript:',raw);self.assertIn('data-advisory="B"',raw)
    def test_same_name_different_repo_and_verify_before_link(self):
        a,av=self.fixture();b,bv=self.fixture('taas')
        page=('<style></style>'+''.join('<article data-component="golang.org/x/crypto"><span class="version">声明 0.51.0</span><h3>x/crypto</h3><p class="origin">'+c['repository']+' · '+c['commit'][:8]+'</p><dt>风险条件</dt><dd>risk</dd><dt>检查与处理</dt><dd>check</dd></article>' for c in (a,b))).encode()
        class Journal:
            def save(self):pass
        class Objects:
            def publish(self,key,raw,ctype):return dict(key=key,sha256=m.sha(raw),bytes=len(raw))
            def presign(self,key,at):return 'https://example.test/'+key,(at+dt.timedelta(days=7)).isoformat()
        class Job:
            state={};journal=Journal();objects=Objects();component_osv={'matrixone':av,'taas':bv}
            def store(self,*args):pass
            def event(self,*args,**kwargs):pass
        source=dict(report_date='2026-10-23',commits={'matrixone':a['commit'],'taas':b['commit']})
        with patch('cloud_publish.verify_login_free',return_value={'http':200}) as verify:
            raw,entries,md,at=m.publish_and_link(Job(),source,page)
        self.assertEqual(verify.call_count,2);self.assertNotEqual(entries[0]['url'],entries[1]['url']);self.assertEqual(entries[0]['expires_at_utc'],entries[1]['expires_at_utc']);self.assertEqual(raw.count(b'class="component-detail-link"'),2)
        with patch('cloud_publish.verify_login_free',side_effect=ValueError('bad')):
            with self.assertRaisesRegex(ValueError,'bad'):m.publish_and_link(Job(),source,page)

if __name__=='__main__':unittest.main()
