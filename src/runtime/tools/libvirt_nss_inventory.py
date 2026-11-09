"""Targeted readonly NSS queries; diagnostic results never authorize account creation.

Synthetic tests inject lookup results. Only --query-host enables real NSS calls.
No enumeration, account command, shadow access, or service management is used.
The caller must impose a finite process timeout because NSS can block.
"""
import argparse
import json
from pathlib import Path
import re
import sys

if __name__=='__main__':sys.path.insert(0,str(Path(__file__).resolve().parents[1]))

from dnlab_runtime.manifest import Conflict,fingerprint
from dnlab_runtime.libvirt_account_identity import host_query,checked_lookup



def collect(name,uid,gid,*,query):
    if (not isinstance(name,str) or not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}',name) or name=='root'
            or any(type(v) is not int or not 0<v<2**31 for v in (uid,gid))):
        raise Conflict('dedicated candidate name and numeric IDs required')
    controls=[('passwd','root'),('passwd',0),('group','root'),('group',0)]
    candidates=[('passwd',name),('passwd',uid),('group',name),('group',gid)]
    def snapshot():
        rows=[]
        for database,key in controls+candidates:
            result=checked_lookup(database,key,query)
            rows.append(dict(database=database,key=key,result=result))
        for row in rows[:4]:
            expected=dict(name='root',gid=0)
            if row['database']=='passwd':expected['uid']=0
            if row['result']!=expected:raise Conflict('NSS root control query differs')
        return rows
    first=snapshot();second=snapshot()
    if first!=second:raise Conflict('NSS results changed between observations')
    return dict(status='collected',qualified=False,candidate=dict(name=name,uid=uid,gid=gid),
        observation_sha256=fingerprint(first),observed=first,
        candidate_reported_absent=all(row['result'] is None for row in first[4:]),
        limitations=['No account enumeration, commands, shadow or service management',
            'Negative NSS results do not prove availability of every configured provider',
            'No atomic reservation, original resource ownership or provisioning window',
            'Fresh original preflight and explicit provisioning authorization still required'])


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--query-host',action='store_true')
    parser.add_argument('--name',default='dnlab-libvirt')
    parser.add_argument('--uid',type=int,default=1001);parser.add_argument('--gid',type=int,default=1002)
    args=parser.parse_args()
    if not args.query_host:parser.error('real NSS queries require --query-host')
    print(json.dumps(collect(args.name,args.uid,args.gid,query=host_query),sort_keys=True))


if __name__=='__main__':main()
