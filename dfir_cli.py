#!/usr/bin/env python3
from pathlib import Path
import hashlib, json
BASE=Path(__file__).resolve().parent

def h(p,a):
 x=hashlib.new(a)
 with p.open('rb') as f:
  for c in iter(lambda:f.read(1048576),b''):x.update(c)
 return x.hexdigest()
while True:
 print('\nDFIR INVESTIGATION LAB\n[1] Hash evidence file\n[2] Show saved cases\n[3] Exit')
 c=input('Choice: ').strip()
 if c=='1':
  p=Path(input('Evidence path: ').strip())
  if p.is_file(): print('MD5:',h(p,'md5'),'\nSHA256:',h(p,'sha256'))
  else: print('File not found')
 elif c=='2':
  data=json.loads((BASE/'data/cases_db.json').read_text()); cases=data.get('cases',data)
  for x in cases: print('-',x['id'],':',x['title'])
 elif c=='3': break
