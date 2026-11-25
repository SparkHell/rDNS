"""Exercise the HTTPS portal against a temporary database and local identity provider."""
import plistlib
import socketserver
import email
import base64
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import re
import sqlite3
import ssl
import subprocess
import tempfile
from datetime import datetime
from zoneinfo import ZoneInfo
from concurrent.futures import ThreadPoolExecutor
import threading
import time
from urllib.parse import parse_qs, urlencode, urlsplit

from smoke import BIN, PASSWORD, api, certificate, port, query, rcode


def b64(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip('=')


class Identity(http.server.BaseHTTPRequestHandler):
    def reply(self, value):
        body = json.dumps(value).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        base = self.server.base
        if self.path == '/.well-known/openid-configuration':
            self.reply(dict(issuer=base, authorization_endpoint=base+'/authorize',
                            token_endpoint=base+'/token', jwks_uri=base+'/keys',
                            response_types_supported=['code'], subject_types_supported=['public'],
                            id_token_signing_alg_values_supported=['RS256']))
        elif self.path == '/keys':
            self.reply({'keys': [self.server.jwk]})
        elif self.path == '/profile' and self.headers.get('Authorization') == 'Bearer local-token':
            self.reply({'id': 123, 'login': 'federated', 'email': 'same@example.test'})
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path != '/token':
            return self.send_error(404)
        form = parse_qs(self.rfile.read(int(self.headers['Content-Length'])).decode())
        auth = self.server.grants.pop(form['code'][0])
        assert b64(hashlib.sha256(form['code_verifier'][0].encode()).digest()) == auth['code_challenge'][0]
        assert form['redirect_uri'] == auth['redirect_uri']
        assert self.headers['Authorization'].startswith('Basic ')
        now = int(time.time())
        claims = dict(sub='123', iss=self.server.base, aud='portal', exp=now+120, iat=now,
                      nonce=auth.get('nonce', [''])[0], email='same@example.test',
                      preferred_username='federated')
        claims.update(self.server.overrides)
        payload = '.'.join(b64(json.dumps(obj).encode()) for obj in
                           [{'alg': 'RS256', 'kid': 'test'}, claims])
        signature = subprocess.check_output(['openssl', 'dgst', '-sha256', '-sign', self.server.key],
                                            input=payload.encode())
        if self.server.corrupt:
            signature = bytes(len(signature))
        self.reply(dict(access_token='local-token', token_type='Bearer', expires_in=120,
                        id_token=payload+'.'+b64(signature)))

    def log_message(self, *_):
        pass


class Mailbox(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(b'220 localhost ready\r\n')
        while line := self.rfile.readline():
            verb = line.split()[0].upper()
            if verb == b'DATA':
                self.wfile.write(b'354 send message\r\n')
                raw = b''.join(iter(self.rfile.readline, b'.\r\n'))
                body = email.message_from_bytes(raw).get_payload(decode=True)
                self.server.code = re.search(rb'\b[0-9]{8}\b', body)[0].decode()
            elif verb == b'QUIT':
                self.wfile.write(b'221 bye\r\n')
                return
            self.wfile.write(b'250 OK\r\n')


def run(directory):
    cert, key = certificate(directory, 'localhost')
    idp = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Identity)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    idp.socket = ctx.wrap_socket(idp.socket, server_side=True)
    smtp = socketserver.ThreadingTCPServer(('127.0.0.1', 0), Mailbox)
    smtp.socket = ctx.wrap_socket(smtp.socket, server_side=True)
    threading.Thread(target=smtp.serve_forever, daemon=True).start()
    issuer = idp.base = f'https://localhost:{idp.server_port}'
    idp.grants, idp.key, idp.overrides, idp.corrupt = {}, key, {}, False
    modulus = subprocess.check_output(['openssl','rsa','-in',key,'-noout','-modulus']).decode().strip().split('=')[1]
    idp.jwk = dict(kty='RSA', kid='test', alg='RS256', use='sig', n=b64(bytes.fromhex(modulus)), e='AQAB')
    threading.Thread(target=idp.serve_forever, daemon=True).start()
    admin_port, dns_port = port(), port()
    base, public = f'http://127.0.0.1:{admin_port}', f'https://localhost:{dns_port}'
    config = directory/'settings.toml'
    config.write_text(f'''database = "data.sqlite3"
admin = "127.0.0.1:{admin_port}"
doh = "127.0.0.1:{dns_port}"
allowed_clients = ["127.0.0.0/8"]
certificate = "localhost.crt"
private_key = "localhost.key"
''')
    db = sqlite3.connect(directory/'data.sqlite3')
    db.execute('CREATE TABLE query_log(id INTEGER PRIMARY KEY, at TEXT,client TEXT,domain TEXT,qtype TEXT,outcome TEXT,protocol TEXT)')
    db.execute("INSERT INTO query_log VALUES(1,strftime('%Y-%m-%dT%H:%M:%f+00:00','now'),'127.0.0.1','old.test','A','local','doh')")
    db.commit()
    subprocess.run([BIN,'init-admin',config,'admin'],input=PASSWORD.encode(),check=True,stdout=subprocess.DEVNULL)
    server_log = (directory/'server.log').open('w+')
    def start():
        return subprocess.Popen([BIN,config],env={**os.environ,'TZ':'Asia/Kathmandu','SSL_CERT_FILE':str(cert),'NO_PROXY':'localhost,127.0.0.1','no_proxy':'localhost,127.0.0.1'}, stdout=server_log,stderr=subprocess.STDOUT)
    def admin_login():
        for i in range(100):
            try:
                return api(base,'/login',{'username':'admin','password':PASSWORD})['token']
            except OSError:
                time.sleep(0.1)
        raise AssertionError('admin listener unavailable')
    def call(path, body=None, cookie='', status=200, method=None, via_admin=False):
        con = (http.client.HTTPConnection('127.0.0.1',admin_port,timeout=5) if via_admin
               else http.client.HTTPSConnection('localhost',dns_port,context=ssl.create_default_context(cafile=cert),timeout=5))
        try:
            raw = isinstance(body, bytes)
            con.request(method or ('GET' if body is None else 'POST'),path,
                        body if raw or body is None else json.dumps(body),{'Cookie':cookie,
                        'Content-Type':'application/dns-message' if raw else 'application/json'})
            res=con.getresponse()
            data=res.read()
            if (path == '/portal/api/rdns.mobileconfig' or path.endswith('?mobileconfig=1')) and status == 200:
                assert res.getheader('Content-Type') == 'application/x-apple-aspen-config'
                assert 'rdns.mobileconfig' in res.getheader('Content-Disposition')
                assert res.getheader('Cache-Control') == 'no-store'
            assert res.status==status,(res.status,status,data[:100])
            return (json.loads(data) if res.getheader('Content-Type','').startswith('application/json') else data,
                    res.getheader('Set-Cookie','').split(';')[0],res.getheader('Location'))
        finally:
            con.close()
    def member(name, status=200):
        return call('/portal/api/register',dict(username=name,password='test-password'),status=status)[1]
    def profile(cookie):
        return call('/portal/api/me',cookie=cookie)[0]
    mobile = '/portal/api/rdns.mobileconfig'
    def mobile_profile(cookie, address):
        doc = plistlib.loads(call(mobile, cookie=cookie)[0])
        payload, = doc['PayloadContent']
        assert doc['PayloadType'] == 'Configuration'
        assert payload['PayloadType'] == 'com.apple.dnsSettings.managed'
        assert payload['DNSSettings'] == dict(DNSProtocol='HTTPS', ServerURL=address)
        return doc['PayloadUUID']
    def flow(provider, status=303):
        _,flow_cookie,location=call('/portal/auth/'+provider,status=303)
        auth=parse_qs(urlsplit(location).query)
        assert auth['code_challenge_method']==['S256']
        code=os.urandom(16).hex()
        idp.grants[code]=auth
        assert auth['redirect_uri']==[public+'/portal/callback/'+provider]
        path='/portal/callback/'+provider+'?'+urlencode({'state':auth['state'][0],'code':code})
        call(path.replace('/callback/'+provider, '/callback/wrong-provider'),cookie=flow_cookie,status=401)
        call(path,cookie='wrong=browser',status=401)
        _,session,_=call(path,cookie=flow_cookie,status=status)
        call(path,cookie=flow_cookie,status=401)
        return session

    server=start()
    try:
        token=admin_login()
        def admin(path, body=None, method=None):
            return api(base,'/portal/'+path,body,token,method)
        created=admin('users',{'username':'managed-user','password':'initial-test-password'})['id']
        managed=call('/portal/api/login',dict(username='managed-user',password='initial-test-password'))[1]
        path=profile(managed)['path']
        admin(f'users/{created}',{'username':'managed-renamed','password':'new-test-password'},'PUT')
        call('/portal/api/me',cookie=managed,status=401)
        call('/portal/api/login',dict(username='managed-renamed',password='initial-test-password'),status=401)
        managed=call('/portal/api/login',dict(username='managed-renamed',password='new-test-password'))[1]
        assert profile(managed)['path']==path
        admin(f'users/{created}',method='DELETE')
        call('/portal/api/me',cookie=managed,status=401)
        call(path,query('example.test'),status=404)
        assert all(u['id']!=created for u in admin('users'))
        cfg=admin('settings')
        assert cfg['registration']=='open' and cfg['public']
        api(base,'/rules',dict(kind='local',domain='portal.test',record_type='A',value='192.0.2.27',ttl=60),token)
        a,b=member('alice'),member('bob')
        alice,bob=profile(a),profile(b)
        assert alice['path']!=bob['path'] and re.fullmatch('/dns/[a-zA-Z0-9]{22}',alice['path'])
        call(mobile, status=401)
        original = mobile_profile(a, public + alice['path'])
        assert mobile_profile(b, public + bob['path']) != original
        qr_endpoint='/portal/api/ios-qr'
        call(qr_endpoint,{},status=401)
        assert alice['resolver_url']==public+alice['path']
        assert call('/portal/api/me',cookie=a,via_admin=True)[0]['resolver_url'] is None
        call(qr_endpoint,{},a,status=409,via_admin=True)
        call(mobile,cookie=a,status=409,via_admin=True)
        def download_link(cookie, path):
            data=call(qr_endpoint,{},cookie)[0]
            assert data['image'].startswith('data:image/svg+xml;base64,')
            assert data['url']==public+path+'?mobileconfig=1'
            return path+'?mobileconfig=1'
        before_rotate=download_link(a,alice['path'])
        for _ in range(2):
            descriptor=plistlib.loads(call(before_rotate)[0])
            assert descriptor['PayloadUUID']==original
            assert descriptor['PayloadContent'][0]['DNSSettings']['ServerURL']==public+alice['path']
        assert call(before_rotate,method='HEAD')[0] == b''
        call('/dns-query?mobileconfig=1',status=400)
        wire=query('portal.test')
        check=lambda data: rcode(data)==0 and data.endswith(bytes([192,0,2,27]))
        assert check(call(alice['path']+'?dns='+b64(wire))[0])
        assert check(call(bob['path'],wire)[0])
        assert check(call('/dns-query',wire)[0])
        call('/dns/'+alice['path'][5:].swapcase(),wire,status=404)
        for cookie, other in [(a,bob),(b,alice)]:
            report=call('/portal/api/analytics?user='+str(other['id']),cookie=cookie)[0]
            assert report['total']==1 and report['logs'][0]['user']!=other['id']
        try:
            api(base,'/accounts',token=a.split('=')[1])
            raise AssertionError('portal cookie authorized management')
        except OSError as error:
            assert error.code==401
        assert admin('analytics?entry=historical')['total']==1
        assert admin('analytics?entry=public')['total']==1
        assert admin('analytics?entry=personal')['total']==2
        history=admin('analytics?entry=historical')['logs'][0]
        assert history['response'] is None and history['rcode'] is None
        detail=call('/portal/api/analytics?search=PORTAL&qtype=TYPE1&outcome=local&rcode=0',cookie=a)[0]
        row,=detail['logs']
        expected=datetime.fromisoformat(row['at']).astimezone(ZoneInfo('Asia/Kathmandu'))
        assert row['local_at']==expected.strftime('%Y-%m-%d %H:%M:%S')
        assert detail['server_offset']=='+05:45' and detail['detail_total']==1
        assert row['response']['rcode']=='NOERROR' and row['response']['answers'][0]['data']=='192.0.2.27'
        assert any(bucket['time']==expected.strftime('%Y-%m-%dT%H:00') and bucket['count']==1 for bucket in detail['trend'])
        no_match=call('/portal/api/analytics?search=not-present',cookie=a)[0]
        assert no_match['total']==1 and no_match['detail_total']==0 and not no_match['logs']
        lookup='/portal/api/lookup'
        call(lookup,{'domain':'portal.test','qtype':'A'},status=401)
        call(lookup,{'domain':'portal.test','qtype':'NOT-A-TYPE'},a,status=400)
        for qtype in ('A','1','ANY','TYPE65400'):
            result=call(lookup,{'domain':'portal.test','qtype':qtype,'dnssec_ok':True},a)[0]
            assert result['response']['rcode']=='NOERROR'
            assert bool(result['response']['answers'])==(qtype!='TYPE65400')
            if result['response']['answers']:
                assert result['response']['answers'][0]['data']=='192.0.2.27'
        dns_settings, dns_records = '/portal/api/dns-settings', '/portal/api/dns-records'
        call(dns_settings, status=401)
        default_dns = call(dns_settings,cookie=b)[0]
        assert default_dns['records']==[] and default_dns['preferences']==dict(adguard=False,gfwlist=False)
        call(dns_settings,dict(adguard=True,gfwlist=False),a,method='PUT')
        assert call(dns_settings,cookie=b)[0]==default_dns
        call(dns_settings,dict(adguard=True,gfwlist=False,group='unauthorized'),a,method='PUT',status=422)
        personal_name='private.portal.test'
        personal_rule=dict(domain=' Private.Portal.Test. ',record_type='A',value='192.0.2.110',ttl=30)
        call(dns_records,personal_rule,status=401)
        personal_record=call(dns_records,personal_rule,a)[0]
        assert personal_record['domain']==personal_name and personal_record['ttl']==30
        personal_edit=dns_records+'/'+str(personal_record['id'])
        call(personal_edit,personal_rule,b,method='PUT',status=404)
        call(personal_edit,cookie=b,method='DELETE',status=404)
        call(dns_records,personal_rule,a,status=409)
        call(dns_records,dict(personal_rule,record_type='CNAME',value='target.test'),a,status=409)
        call(dns_records,dict(personal_rule,domain='*.portal.test'),a,status=400)
        call(dns_records,dict(personal_rule,domain='.',value='192.0.2.111'),a,status=400)
        call(dns_records,dict(personal_rule,domain='alias.portal.test',record_type='CNAME',value='Alias.Portal.Test.'),a,status=400)
        call(dns_records,dict(personal_rule,record_type='AAAA'),a,status=400)
        call(dns_records,dict(personal_rule,ttl=0),a,status=400)
        call(dns_records,dict(personal_rule,value='192.0.2.120'),b)
        def resolved(path, name, value, kind=1):
            answer=call(path,query(name,kind))[0]
            assert rcode(answer)==0 and answer.endswith(value)
        resolved(alice['path'],personal_name,bytes([192,0,2,110]))
        resolved(bob['path'],personal_name,bytes([192,0,2,120]))
        call(personal_edit,dict(personal_rule,value='192.0.2.111'),a,method='PUT')
        resolved(alice['path'],personal_name,bytes([192,0,2,111]))
        empty=call(lookup,dict(domain=personal_name,qtype='AAAA'),a)[0]['response']
        assert empty['rcode']=='NOERROR' and not empty['answers']
        for name, kind, value, needle in [
            (personal_name, 'AAAA', '2001:db8::1', '2001:db8::1'),
            ('alias.portal.test', 'CNAME', ' Private.Portal.Test. ', 'private.portal.test.'),
            (personal_name, 'TXT', 'verification token', 'verification token'),
        ]:
            extra=call(dns_records,dict(domain=name,record_type=kind,value=value),a)[0]
            query_type='A' if kind=='CNAME' else kind
            result=call(lookup,dict(domain=name,qtype=query_type),a)[0]['response']
            assert result['rcode']=='NOERROR' and any(needle in item['data'] and item['ttl']==300 for item in result['answers'])
            call(dns_records+'/'+str(extra['id']),cookie=a,method='DELETE')
        call(dns_records,dict(personal_rule,domain='portal.test'),a)
        assert check(call(alice['path'],wire)[0]), 'personal record overrode an administrator local record'
        api(base,'/rules',dict(kind='block',domain=personal_name),token)
        assert rcode(call(alice['path'],query(personal_name))[0])==3, 'personal record bypassed an administrator block'
        api(base,'/rules/'+str(next(r['id'] for r in api(base,'/rules',token=token) if r['domain']==personal_name)),token=token,method='DELETE')
        resolved(alice['path'],personal_name,bytes([192,0,2,111]))
        # Keep a resolver using the old credential during rotation.
        ready=threading.Event()
        def poll_old_address():
            for _ in range(200):
                try:
                    call(alice['path'],wire)
                except AssertionError as e:
                    if e.args[0][0]==404:
                        return
                    raise
                ready.set()
            raise AssertionError('old credential remained usable')
        with ThreadPoolExecutor(max_workers=1) as worker:
            poll=worker.submit(poll_old_address)
            assert ready.wait(3)
            call('/portal/api/rotate',{},a)
            poll.result(timeout=5)
        call(before_rotate,status=404)
        new=profile(a)['path']
        call('/dns-'+alice['path'][5:],wire,status=404)
        legacy = '/dns-' + new[5:]
        call(legacy,wire,status=404)
        call(legacy+'?dns='+b64(wire),status=404)
        assert mobile_profile(a, public + new) == original
        call(alice['path'],wire,status=404)
        assert check(call(new,wire)[0])
        resolved(new,personal_name,bytes([192,0,2,111]))
        assert call('/portal/api/analytics',cookie=a)[0]['total']>=2
        for _ in range(51):
            assert check(call(new,wire)[0])
        more=call('/portal/api/analytics?days=30&page=2',cookie=a)[0]
        assert more['logs'] and more['retention']==7 and more['trend'] and more['domains'][0]['domain']=='portal.test'
        send, verify = '/portal/api/email/send', '/portal/api/email/login'
        address = {'email': 'reader@Example.Test'}
        call(send, address, status=403)
        cfg['email'] = dict(enabled=True, host='localhost', port=smtp.server_address[1],
                            sender='portal@example.test', domains='example.test')
        cfg['registration'] = 'approval'
        admin('settings', cfg, 'PUT')
        call(send, {'email': 'reader@sub.example.test'}, status=403)
        call(send, address)
        call(send, address, status=429)
        call(verify, dict(**address, code='invalid'), status=401)
        _, mail_cookie, _ = call(verify, dict(**address, code=smtp.code))
        assert profile(mail_cookie)['status'] == 'pending'
        call(verify, dict(**address, code=smtp.code), status=401)
        exhausted = {'email': 'attempts@example.test'}
        call(send, exhausted)
        for _ in range(5):
            call(verify, dict(**exhausted, code='invalid'), status=401)
        call(verify, dict(**exhausted, code=smtp.code), status=401)
        revoked = {'email': 'revoked@example.test'}
        call(send, revoked)
        cfg['email']['domains'] = 'other.test'
        admin('settings', cfg, 'PUT')
        call(verify, dict(**revoked, code=smtp.code), status=403)
        cfg['email']['domains'] = 'example.test'
        admin('settings', cfg, 'PUT')
        call(verify, dict(**revoked, code=smtp.code), status=401)
        cfg.update(base=public,registration='approval',public=False)
        admin('settings',cfg,'PUT')
        assert call('/portal/api/me',cookie=a,via_admin=True)[0]['resolver_url']==public+new
        assert call(qr_endpoint,{},a,via_admin=True)[0]['url']==public+new+'?mobileconfig=1'
        mobile_profile(a, public+new)
        call('/dns-query',wire,status=404)
        cfg['base'] = 'https://resolver.example.test:8443'
        admin('settings', cfg, 'PUT')
        mobile_profile(a, cfg['base'] + new)
        cfg['base'] = public
        admin('settings', cfg, 'PUT')
        pending=member('pending')
        call(mobile, cookie=pending, status=403)
        call(dns_settings,cookie=pending,status=403)
        call(dns_records,personal_rule,pending,status=403)
        assert profile(pending)['path'] is None
        admin('users/'+str(profile(pending)['id']),{'action':'activate'})
        assert check(call(profile(pending)['path'],wire)[0])
        admin('users/'+str(bob['id']),{'action':'disable'})
        call('/portal/api/me',cookie=b,status=401)
        call(mobile,cookie=b,status=401)
        call(bob['path'],wire,status=404)
        cfg['registration']='closed'
        admin('settings',cfg,'PUT')
        member('rejected',403)
        call('/portal/api/login',dict(username='alice',password='test-password'))
        cfg['providers']=[dict(id='one',label='OIDC',kind='oidc',issuer=issuer,client_id='portal',secret='demo-secret'),
                          dict(id='two',label='OAuth',kind='oauth',client_id='portal',secret='demo-secret',authorization=issuer+'/authorize',
                               token=issuer+'/token',profile=issuer+'/profile',user_id='id')]
        cfg['registration']='open'
        admin('settings',cfg,'PUT')
        assert all(p['secret']=='' for p in admin('settings')['providers'])
        cfg['password_login']=False
        cfg['providers'][0]['enabled']=False
        admin('settings',cfg,'PUT')
        opts=call('/portal/api/options')[0]
        assert not opts['password_login'] and opts['email'] and [p['id'] for p in opts['providers']]==['two']
        member('password-off',403)
        call('/portal/api/login',dict(username='alice',password='test-password'),status=403)
        call('/portal/auth/one',status=404)
        assert profile(flow('two'))['id']
        cfg['password_login']=True
        cfg['providers'][0]['enabled']=True
        admin('settings',cfg,'PUT')
        first=profile(flow('one'))
        second=profile(flow('two'))
        assert first['id']!=second['id'] and first['name']==second['name']
        for claim,value in [('aud','wrong'),('iss',issuer+'/wrong'),('nonce','wrong')]:
            idp.overrides={claim:value}
            flow('one',502)
        idp.overrides={};idp.corrupt=True
        flow('one',502)
        idp.corrupt=False
        cfg['registration']='closed'
        admin('settings',cfg,'PUT')
        assert profile(flow('one'))['id']==first['id']
        idp.overrides={'sub':'new-id'}
        flow('one',403)
        cfg['registration']='approval'
        admin('settings',cfg,'PUT')
        assert profile(flow('one'))['status']=='pending'
        cfg['registration']='closed'
        idp.overrides={}
        admin('settings',cfg,'PUT')
        policy=api(base,'/features',token=token)['settings']
        policy['access'].update(mode='whitelist',cidrs=['192.0.2.0/24'])
        api(base,'/features',policy,token,'PUT')
        assert rcode(call(new,wire)[0])==5
        assert call(lookup,{'domain':'portal.test','qtype':'A'},a)[0]['response']['rcode']=='REFUSED'
        server.terminate();server.wait(timeout=10)
        server=start();token=admin_login()
        assert profile(a)['path']==new and admin('settings')['registration']=='closed'
        assert call(dns_settings,cookie=a)[0]['preferences']==dict(adguard=True,gfwlist=False)
        assert rcode(call(new,query(personal_name))[0])==5
        policy['access']['cidrs']=['127.0.0.0/8']
        api(base,'/features',policy,token,'PUT')
        resolved(new,personal_name,bytes([192,0,2,111]))
        call('/dns-query',wire,status=404)
        assert all(new not in str(row) for row in api(base,'/audit',token=token))
        if os.environ.get('RDNS_PORTAL_UI'):
            cfg['registration']='open'
            admin('settings',cfg,'PUT')
            subprocess.run(['node',str(Path(__file__).with_name('portal-ui.mjs')),public,base],env={**os.environ,'RDNS_TEST_ADMIN_TOKEN':token,'RDNS_TEST_ADMIN_PASSWORD':PASSWORD},check=True,timeout=60)
        server_log.flush()
        for credential in (alice['path'],bob['path'],new):
            assert credential[5:] not in (directory/'server.log').read_text()
        print('PASS: portal policies, OAuth/OIDC validation, isolation, DoH ownership and restart')
    finally:
        server.terminate();server.wait(timeout=10)
        smtp.shutdown();smtp.server_close()
        idp.shutdown();idp.server_close();db.close();server_log.close()


if __name__=='__main__':
    with tempfile.TemporaryDirectory(prefix='rdns-portal-') as temp:
        run(Path(temp))
