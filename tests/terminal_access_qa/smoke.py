"""One bounded in-process ASGI composition smoke. Never production or GUI acceptance."""
from pathlib import Path
import argparse
import asyncio
from datetime import timedelta
import hashlib
import importlib.abc
import importlib.metadata
import json
import os
import socket
import sys
import threading
import time
from unittest.mock import patch
import uuid

AUTH = Path(__file__).resolve().parents[2]
ROOT = AUTH.parent
sys.path.insert(0, str(AUTH))


class BlockPrivateModules(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname in ('app.main', 'app.config'):
            raise RuntimeError('Private runtime imports are forbidden in Auth-only QA')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


async def smoke(output):
    import httpx
    from backend import build
    from app import terminal_access
    from app.security import token_hash, utc_now
    from app.store import iso
    fixture = build(output / 'fixture', ROOT / '.local-operations')
    results = []
    headers = {'X-Muxi-Server-Key': fixture.settings.terminal_sso_server_key}
    base = '/api/internal/minecraft/terminal-context/'
    bind_path = '/api/launcher/minecraft/terminal-context/bind'
    uid = fixture.accounts[0].uid

    def check(condition, name):
        if not condition:
            raise AssertionError(name)
        results.append(name)

    def correlation(session=None):
        return {'uid': uid, 'requestId': str(uuid.uuid4()), 'gameSession': session or str(uuid.uuid4())}

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=fixture.app), base_url='https://account.muxigame.com',
                                 follow_redirects=False, trust_env=False) as client:
        async def request(route, body, expected, name, authority=None):
            response = await client.post(base + route, json=body, headers=headers if authority is None else authority)
            check(response.status_code == expected, name)
            if expected == 200:
                value = response.json()
                check(value['uid'] == uid and value['gameSession'] == body['gameSession']
                      and ('requestId' not in body or value['requestId'] == body['requestId'])
                      and response.headers.get('cache-control') == 'no-store'
                      and 'set-cookie' not in response.headers
                      and not {'token', 'access_token', 'refresh_token', 'proof', 'ticket'} & value.keys(), name + ': correlation/no credential response')
            return response

        async def bind(body, expected, name, token=None):
            response = await client.post(bind_path, json={k: body[k] for k in ('requestId', 'gameSession')},
                                         headers={'Authorization': 'Bearer ' + (token or fixture.access[0])})
            check(response.status_code == expected, name)
            return response

        body = correlation()
        await bind(body, 401, 'bind requires a real CREATE')
        await request('create', body, 200, 'CREATE through actual router')
        await request('claim', body, 401, 'CLAIM requires prior bind')
        await bind(body, 401, 'other account rejected', fixture.access[1])
        await bind(body, 401, 'wrong launcher client rejected', fixture.wrong_client_access)
        await request('create', correlation(), 401, 'identity authority cannot act as terminal authority',
                      {'X-Muxi-Server-Key': fixture.settings.minecraft_profile_key})
        await bind(body, 200, 'real Store-issued54 token binds')
        await bind(body, 401, 'bind is consumed once')
        await request('claim', body, 200, 'CLAIM authorizes only bound correlation')
        await request('claim', body, 401, 'CLAIM is consumed once')
        session = {k: body[k] for k in ('uid', 'gameSession')}
        status = await request('status', session, 200, 'status of real claimed session')
        check(status.json()['authenticated'] is True, 'actual Store records active source')
        await request('revoke', session, 200, 'revoke active context')
        renewed = correlation(body['gameSession'])
        await request('create', renewed, 200, 'revoke keeps same live session rebindable')
        await bind(renewed, 200, 'fresh request binds after revoke')
        await request('claim', renewed, 200, 'fresh request claims after revoke')
        await request('disconnect', session, 200, 'disconnect retires session')
        await request('create', correlation(body['gameSession']), 401, 'disconnect tombstone denies late CREATE')

        expiring = correlation()
        await request('create', expiring, 200, 'expiry setup uses actual CREATE')
        # Only the fixture issuer clock advances; no global system time or production DB edit.
        with patch.object(terminal_access, 'utc_now', return_value=utc_now() + timedelta(seconds=31)):
            await bind(expiring, 401, '30 second challenge expires before bind')

        revoked = correlation()
        await request('create', revoked, 200, 'source revocation setup CREATE')
        await bind(revoked, 200, 'source revocation setup bind')
        with fixture.store.connect() as db:
            db.execute('UPDATE access_tokens SET revoked_at=? WHERE token_hash=?',
                       (iso(utc_now()), token_hash(fixture.access[0])))
        await request('claim', revoked, 401, 'revoked real source cannot CLAIM')
        check('app.main' not in sys.modules and 'app.config' not in sys.modules, 'no runtime main/config imports')
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    output = args.output.absolute()
    private = (ROOT / '.local-operations').resolve(strict=True)
    if output.exists() or output != output.resolve() or private not in output.parents:
        raise ValueError('Use a fresh output inside workspace .local-operations')
    output.mkdir()
    lock_paths = [Path(__file__), Path(__file__).with_name('backend.py'),
                  *[AUTH / 'app' / name for name in ('__init__.py', 'store.py', 'security.py', 'external_identity.py',
                    'terminal_access.py', 'terminal_access_api.py', 'terminal_server_auth.py')]]
    sources = {p.relative_to(ROOT).as_posix(): sha(p) for p in lock_paths}
    lock = {'sources': sources, 'python': sys.executable,
            'dependencies': {name: importlib.metadata.version(name) for name in ('fastapi', 'httpx', 'argon2-cffi', 'PyJWT')},
            'command': [sys.executable, '-B', str(Path(__file__)), '--output', str(output)],
            'budgetSeconds': 30, 'transport': 'in-process httpx.ASGITransport; no TLS/socket',
            'fixtureDB': 'fixture/fixture-auth.db; new isolated Store only'}
    (output / 'source-lock.json').write_text(json.dumps(lock, indent=2) + '\n', encoding='utf-8')
    sys.meta_path.insert(0, BlockPrivateModules())

    def deny(*args, **kwargs):
        raise RuntimeError('Network/listener forbidden in Tier A')

    start = time.monotonic()
    def timeout():
        (output / 'result.json').write_text(json.dumps({'passed': False, 'errorType': 'BudgetExceeded', 'seconds': 30}) + '\n', encoding='utf-8')
        os._exit(124)
    deadline = threading.Timer(30, timeout)
    deadline.daemon = True
    deadline.start()
    # Windows' asyncio loop creates its own wakeup socket pair. Initialize it before
    # denying application bind/connect; this is not a fixture listener or HTTP transport.
    loop = asyncio.new_event_loop()
    try:
        with patch.object(socket.socket, 'connect', deny), patch.object(socket.socket, 'connect_ex', deny), \
                patch.object(socket.socket, 'bind', deny), patch.object(socket, 'create_connection', deny):
            results = loop.run_until_complete(smoke(output))
        if any(sha(ROOT / name) != digest for name, digest in sources.items()):
            raise RuntimeError('Source drift during smoke')
        report = {'passed': True, 'assertions': len(results), 'scenarios': results, 'seconds': time.monotonic() - start,
                  'network': False, 'listener': False, 'actualTLS': False, 'MC': False, 'GUI': False,
                  'realPlayerAccount': False, 'production': False, 'runtimeConfigRead': False,
                  'TierB_C': 'not implemented or verified', 'sourceLockSha256': sha(output / 'source-lock.json')}
    except Exception as error:
        # Do not dump HTTP request objects, tokens, DB rows or exception locals.
        report = {'passed': False, 'errorType': type(error).__name__, 'seconds': time.monotonic() - start}
    finally:
        deadline.cancel()
        loop.close()
    (output / 'result.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({k: report[k] for k in ('passed', 'seconds')}, separators=(',', ':')))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
