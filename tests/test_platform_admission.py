"""Extract only the pure HTTP admission helper; do not import auth configuration/secrets."""
import ast,json,os,unittest
from pathlib import Path
from unittest.mock import patch
from urllib.request import Request
from urllib.parse import urlsplit
from fastapi import HTTPException

source=Path(__file__).resolve().parents[1]/'app/main.py'
tree=ast.parse(source.read_text(encoding='utf-8'))
node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='check_game_admission')
scope={'os':os,'json':json,'HTTPException':HTTPException,'ServiceRequest':Request,'service_urlsplit':urlsplit}
exec(compile(ast.Module(body=[node],type_ignores=[]),str(source),'exec'),scope)
check=scope['check_game_admission']

class Reply:
 def __init__(self,payload): self.payload=payload
 def __enter__(self): return self
 def __exit__(self,*args): pass
 def read(self,limit): return json.dumps(self.payload).encode()

class Tests(unittest.TestCase):
 def setUp(self):
  self.env=patch.dict(os.environ,{'MUXI_GAME_ADMISSION_ENABLED':'1','MUXI_GAME_PLATFORM_URL':'http://127.0.0.1','MUXI_GAME_PLATFORM_KEY':'synthetic-credential-00000000000000'})
  self.env.start()
 def tearDown(self): self.env.stop()
 def test_disabled_never_calls_service(self):
  with patch.dict(os.environ,{'MUXI_GAME_ADMISSION_ENABLED':'0'}),patch('urllib.request.build_opener') as opener:
   check(10000);opener.assert_not_called()
 def test_allowed(self):
  with patch('urllib.request.build_opener') as opener:
   opener.return_value.open.return_value=Reply({'uid':10000,'allowed':True});check(10000)
 def test_banned_only_game(self):
  with patch('urllib.request.build_opener') as opener:
   opener.return_value.open.return_value=Reply({'uid':10000,'allowed':False})
   with self.assertRaises(HTTPException) as raised: check(10000)
   self.assertEqual(403,raised.exception.status_code)
 def test_failure_and_wrong_uid_fail_closed(self):
  for payload in [None,{'uid':10001,'allowed':True}]:
   with patch('urllib.request.build_opener') as opener:
    if payload is None: opener.return_value.open.side_effect=OSError('synthetic outage')
    else: opener.return_value.open.return_value=Reply(payload)
    with self.assertRaises(HTTPException) as raised: check(10000)
    self.assertEqual(503,raised.exception.status_code)
 def test_gate_precedes_ticket_consume(self):
  consume=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='minecraft_join_consume')
  calls=[n.func.id if isinstance(n.func,ast.Name) else n.func.attr for n in ast.walk(consume) if isinstance(n,ast.Call) and isinstance(n.func,(ast.Name,ast.Attribute))]
  self.assertLess(calls.index('check_game_admission'),calls.index('consume'))

if __name__=='__main__': unittest.main(verbosity=2)
