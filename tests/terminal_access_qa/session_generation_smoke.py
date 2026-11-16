"""Only new scenario: actual server-generated session IDs isolate delayed issuer cleanup."""
from pathlib import Path
import argparse
import asyncio
import hashlib
import json
import os
import socket
import sys
import threading
import time
from unittest.mock import patch

from smoke import AUTH, ROOT, BlockPrivateModules, sha


async def scenario(output, keys):
    import httpx
    from backend import build
    fixture=build(output / 'fixture', ROOT / '.local-operations')
    if fixture.accounts[0].uid != keys['uid'] or keys['oldSession'] == keys['newSession']:
        raise ValueError('Expected distinct actual server session generations and fixture UID')
    headers={'X-Muxi-Server-Key':fixture.settings.terminal_sso_server_key}
    base='/api/internal/minecraft/terminal-context/'
    old={'uid':keys['uid'],'requestId':keys['oldRequest'],'gameSession':keys['oldSession']}
    new={'uid':keys['uid'],'requestId':keys['newRequest'],'gameSession':keys['newSession']}
    checks=[]
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=fixture.app),base_url='https://account.muxigame.com',trust_env=False) as client:
        async def route(name, body, expected, reason):
            response=await client.post(base+name,json=body,headers=headers)
            if response.status_code != expected:raise AssertionError(reason)
            checks.append(reason);return response
        async def bind(body):
            response=await client.post('/api/launcher/minecraft/terminal-context/bind',json={k:body[k] for k in ('requestId','gameSession')},headers={'Authorization':'Bearer '+fixture.access[0]})
            if response.status_code != 200:raise AssertionError('actual bind')
        await route('create',old,200,'old actual server correlation creates')
        await bind(old);await route('claim',old,200,'old session claims with real isolated credential')
        # The old cleanup was delayed while the accepted server CREATE chose a new id.
        await route('create',new,200,'new actual server correlation creates before old cleanup')
        await bind(new)
        old_session={k:old[k] for k in ('uid','gameSession')}
        await route('revoke',old_session,200,'late old revoke accepted against old key only')
        await route('disconnect',old_session,200,'late old disconnect tombstones old key only')
        await route('claim',new,200,'new pending request survives both old cleanups')
        status=await route('status',{k:new[k] for k in ('uid','gameSession')},200,'new active session remains readable')
        if not status.json()['authenticated']:raise AssertionError('new context must stay authenticated')
        checks.append('new active source remains authenticated')
        await route('create',old,401,'old tombstone does not permit late old CREATE')
    return checks


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--server-keys',type=Path,required=True)
    args=parser.parse_args();output=args.output.absolute();private=(ROOT/'.local-operations').resolve(strict=True)
    if output.exists() or output!=output.resolve() or private not in output.parents:raise ValueError('Fresh private output required')
    keys_path=args.server_keys.resolve(strict=True)
    if ROOT not in keys_path.parents:raise ValueError('Server correlation input must stay in workspace')
    keys=json.loads(keys_path.read_text(encoding='utf-8'));output.mkdir()
    paths=[Path(__file__),Path(__file__).with_name('backend.py'),Path(__file__).with_name('smoke.py')]+[AUTH/'app'/n for n in ('__init__.py','store.py','security.py','external_identity.py','terminal_access.py','terminal_access_api.py','terminal_server_auth.py')]
    lock={'sources':{p.relative_to(ROOT).as_posix():sha(p) for p in paths},'python':sys.executable,'serverCorrelationSha256':sha(keys_path),'budgetSeconds':15,'scenario':'new session generation versus delayed old revoke/disconnect only'}
    (output/'source-lock.json').write_text(json.dumps(lock,indent=2)+'\n',encoding='utf-8')
    sys.meta_path.insert(0,BlockPrivateModules())
    def deny(*args,**kwargs):raise RuntimeError('No application socket/network in issuer ordering smoke')
    def timeout():
        (output/'result.json').write_text('{"passed":false,"errorType":"BudgetExceeded"}\n',encoding='utf-8');os._exit(124)
    deadline=threading.Timer(15,timeout);deadline.daemon=True;deadline.start();loop=asyncio.new_event_loop();start=time.monotonic()
    try:
        with patch.object(socket.socket,'connect',deny),patch.object(socket.socket,'connect_ex',deny),patch.object(socket.socket,'bind',deny),patch.object(socket,'create_connection',deny):
            checks=loop.run_until_complete(scenario(output,keys))
        if any(sha(ROOT/n)!=digest for n,digest in lock['sources'].items()):raise RuntimeError('Source drift')
        report={'passed':True,'checks':checks,'seconds':time.monotonic()-start,'sourceLockSha256':sha(output/'source-lock.json'),'actualProductServerCorrelationInput':True,'inProcessASGIOnly':True,'network':False,'TLS':False,'MC':False,'GUI':False,'realAccount':False}
    except Exception as error:report={'passed':False,'errorType':type(error).__name__,'seconds':time.monotonic()-start}
    finally:deadline.cancel();loop.close()
    (output/'result.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps({'passed':report['passed'],'seconds':report['seconds']}))
    return 0 if report['passed'] else 1

if __name__=='__main__':raise SystemExit(main())
