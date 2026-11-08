"""Boot an isolated matching Keycloak; verify SPI registration and a real login redirect.
No production credentials, volumes, accounts or Steam login are used.
"""
import argparse
import http.cookiejar
import http.client
import json
from pathlib import Path
import secrets
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request


def docker(*args):
    return subprocess.check_output(['docker', *args], text=True).strip()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--version', default='26.8.1')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    jars = list((root / 'target').glob('keycloak-steam-provider-*.jar'))
    if len(jars) != 1:
        raise RuntimeError('Run mvn clean verify first; expected exactly one provider JAR')
    name = 'ggh-steam-ci-' + secrets.token_hex(5)
    password = secrets.token_urlsafe(32)
    try:
        docker('run', '-d', '--name', name, '--publish', '127.0.0.1::8080',
               '--mount', f'type=bind,source={jars[0]},target=/opt/keycloak/providers/steam.jar,readonly',
               '--env', 'KC_BOOTSTRAP_ADMIN_USERNAME=ci-admin',
               '--env', 'KC_BOOTSTRAP_ADMIN_PASSWORD=' + password,
               '--env', 'KC_HOSTNAME=https://login.example.test',
               'quay.io/keycloak/keycloak:' + args.version, 'start-dev')
        port = docker('port', name, '8080/tcp').splitlines()[0].rsplit(':', 1)[1]
        base = 'http://127.0.0.1:' + port
        # Keep auth traffic local, independent of workstation proxy settings.
        cookies = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                    urllib.request.HTTPCookieProcessor(cookies))

        def call(path, data=None, token=None, method=None, form=False):
            # TLS is modeled by KC_HOSTNAME; this test transport is loopback-only HTTP.
            # Browser cookies marked Secure must travel over that local test transport.
            for cookie in cookies:
                cookie.secure = False
            headers = {}
            if token:
                headers['Authorization'] = 'Bearer ' + token
            if data is not None:
                headers['Content-Type'] = 'application/x-www-form-urlencoded' if form else 'application/json'
                data = (urllib.parse.urlencode(data) if form else json.dumps(data)).encode()
            req = urllib.request.Request(base + path, data, headers, method=method)
            with opener.open(req, timeout=15) as r:
                body = r.read()
                return json.loads(body) if body else None

        deadline = time.monotonic() + 150
        while True:
            try:
                call('/realms/master/.well-known/openid-configuration')
                break
            except (urllib.error.URLError, TimeoutError, OSError, http.client.HTTPException):
                if docker('inspect', '--format', '{{.State.Running}}', name) != 'true':
                    raise RuntimeError('Test Keycloak stopped during startup')
                if time.monotonic() > deadline:
                    raise RuntimeError('Test Keycloak did not start')
                time.sleep(2)
        token = call('/realms/master/protocol/openid-connect/token',
            dict(grant_type='password', client_id='admin-cli', username='ci-admin', password=password), form=True)['access_token']
        info = call('/admin/serverinfo', token=token)
        assert any(p['id'] == 'ggh-steam-openid2' for p in info['identityProviders'])
        call('/admin/realms', dict(realm='steam-ci', enabled=True), token)
        prefix = '/admin/realms/steam-ci'
        profile = call(prefix + '/users/profile', token=token)
        profile['attributes'].append(dict(name='steam_id', displayName='Steam ID', multivalued=False,
            permissions=dict(view=['admin', 'user'], edit=['admin'])))
        call(prefix + '/users/profile', profile, token, method='PUT')
        call(prefix + '/identity-provider/instances', dict(alias='steam-test',
            providerId='ggh-steam-openid2', enabled=True, trustEmail=False, config={}), token)
        types = call(prefix + '/identity-provider/instances/steam-test/mapper-types', token=token)
        assert 'ggh-steam-profile-attribute' in types
        properties = types['ggh-steam-profile-attribute']['properties']
        assert any(p['name'] == 'userAttribute' and p['type'] == 'UserProfileAttributeList' for p in properties)
        call(prefix + '/identity-provider/instances/steam-test/mappers', dict(name='steam-id',
            identityProviderAlias='steam-test', identityProviderMapper='ggh-steam-profile-attribute',
            config=dict(jsonField='steam_id', userAttribute='steam_id', syncMode='FORCE')), token)
        call(prefix + '/clients', dict(clientId='smoke-client', protocol='openid-connect', enabled=True,
            publicClient=True, standardFlowEnabled=True, redirectUris=['https://client.example.test/callback']), token)
        query = urllib.parse.urlencode(dict(client_id='smoke-client', response_type='code',
            scope='openid', redirect_uri='https://client.example.test/callback', kc_idp_hint='steam-test'))
        path = '/realms/steam-ci/protocol/openid-connect/auth?' + query
        for _ in range(6):
            try:
                call(path)
                raise AssertionError('Expected a redirect to Steam')
            except urllib.error.HTTPError as e:
                assert e.code in (302, 303), e.code
                location = urllib.parse.urlsplit(e.headers['Location'])
                if location.netloc in ('login.example.test', urllib.parse.urlsplit(base).netloc):
                    # Follow only this isolated realm's internal broker hops locally.
                    assert location.path.startswith('/realms/steam-ci/')
                    path = location.path + ('?' + location.query if location.query else '')
                    continue
                assert location.scheme == 'https' and location.netloc == 'steamcommunity.com', 'Unexpected redirect host: ' + location.netloc
                params = urllib.parse.parse_qs(location.query)
                assert params['openid.realm'] == ['https://login.example.test/']
                assert params['openid.mode'] == ['checkid_setup']
                assert params['openid.return_to'][0].startswith('https://login.example.test/realms/steam-ci/broker/steam-test/endpoint?state=')
                break
        else:
            raise AssertionError('Too many local redirects')
        # Exercise the Jakarta callback and Keycloak auth-session validation without
        # inventing a Steam signature or requiring a real Steam account.
        return_url = urllib.parse.urlsplit(params['openid.return_to'][0])
        cancel_path = return_url.path + '?' + return_url.query + '&openid.mode=cancel'
        try:
            with opener.open(base + cancel_path, timeout=15) as response:
                assert response.status == 200
        except urllib.error.HTTPError as e:
            assert e.code in (302, 303), 'Cancellation callback failed: ' + str(e.code)
        print('PASS: Keycloak ' + args.version + ': provider, selectable mapper, profile schema, Steam login redirect and cancellation callback')
    except Exception:
        try:
            print(docker('logs', '--tail', '50', name).replace(password, '[redacted]'))
        except subprocess.CalledProcessError:
            pass
        raise
    finally:
        subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == '__main__':
    main()
