#!/usr/bin/env python3
from pathlib import Path
import hashlib, json, sys
root=Path(__file__).resolve().parent
prov=json.loads((root/'PROVENANCE.json').read_text(encoding='utf-8'))
failed=False
for row in prov['files']:
    p=root/row['path']; b=p.read_bytes()
    sha=hashlib.sha256(b).hexdigest()
    git=hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()
    ok=(len(b)==row['bytes'] and sha==row['sha256'] and git==row['git_blob_sha1'])
    print(('OK  ' if ok else 'BAD ')+row['path'])
    print('    bytes:',len(b),'expected',row['bytes'])
    print('    sha256:',sha)
    print('    git-blob-sha1:',git)
    failed |= not ok
raise SystemExit(1 if failed else 0)
