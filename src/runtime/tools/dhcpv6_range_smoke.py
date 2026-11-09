#!/usr/bin/env python3
"""Pinned dnsmasq diagnosis or bounded DHCPv4/v6 handshake and RA gate.

The direct isolated veth qualifies generated config, not full service integration
or RFC compliance. No installed plugin or existing lab is modified.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import uuid

IMAGE = 'sha256:de63a0cd8f1083ecab8d81ffcc3446227271b9677ad8dd2e08547704b57850da'
PLUGIN = Path('/opt/dnlab-vrf-plugin/dnlab_vrf_plugin.py')
PLUGIN_STATE = Path('/var/lib/dnlab-vrf-plugin/state.json')
PROBE = r'''
import json,socket,struct,time,sys
def option(code,data):return struct.pack('!HH',code,len(data))+data
def options(data):
 out=[]
 while data:
  if len(data)<4:raise ValueError('truncated option header')
  code,n=struct.unpack('!HH',data[:4]);value=data[4:4+n]
  if len(value)!=n:raise ValueError('truncated option value')
  item={'code':code,'hex':value.hex()}
  if code==3:item['iaid']=value[:4].hex();item['options']=options(value[12:])
  if code==5:
   item['address']=socket.inet_ntop(socket.AF_INET6,value[:16])
   item['preferred_lifetime'],item['valid_lifetime']=struct.unpack('!II',value[16:24])
  if code==13:item['status']=int.from_bytes(value[:2],'big');item['message']=value[2:].decode(errors='replace')
  out.append(item);data=data[4+n:]
 return out
idx=socket.if_nametoindex('client0')
sock=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM);sock.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,b'client0\0')
sock.bind(('::',546));sock.settimeout(.5)
sock.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_MULTICAST_IF,idx)
duid=bytes.fromhex('000400000000000000000000000000000011');iaid=bytes.fromhex('12345678')
xid=bytes.fromhex('d1a601');req=b'\x01'+xid+option(1,duid)+option(3,iaid+bytes(8))+option(8,bytes(2))+option(6,struct.pack('!HH',23,24))
ra=socket.socket(socket.AF_INET6,socket.SOCK_RAW,socket.IPPROTO_ICMPV6)
ra.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,b'client0\0')
ra.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_MULTICAST_HOPS,255)
ra.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_RECVHOPLIMIT,1)
result={'sent_solicit':0,'responses':[],'router_solicitation_sent':False}
ra.sendto(bytes([133,0,0,0])+bytes(4),('ff02::2',0,0,idx));result['router_solicitation_sent']=True
deadline=time.monotonic()+8;next_send=0
while time.monotonic()<deadline:
 if time.monotonic()>=next_send:
  sock.sendto(req,('ff02::1:2',547,0,idx));result['sent_solicit']+=1;next_send=time.monotonic()+2
 try:
  data,peer=sock.recvfrom(65535)
  if len(data)<4 or data[1:4]!=xid or data[0]!=2 or peer[1]!=547:continue
  result['responses'].append({'type':data[0],'peer':peer,'hex':data.hex(),'options':options(data[4:])})
 except socket.timeout:pass
if len(sys.argv)>1 and sys.argv[1]=='verify':
 def only(opts,code):
  values=[x for x in opts if x['code']==code]
  assert len(values)==1,(code,values)
  return values[0]
 def qualify(message,serverid=None):
  opts=message['options'];assert only(opts,1)['hex']==duid.hex()
  sid=only(opts,2)['hex'];assert serverid is None or sid==serverid
  ia=only(opts,3);assert ia['iaid']==iaid.hex()
  address=only(ia['options'],5)
  assert address['address']=='2001:db8:1::11' and 0<address['preferred_lifetime']<=address['valid_lifetime']
  for scope in (opts,ia['options']):
   assert all(x.get('status',0)==0 for x in scope),(scope,'negative status')
  return sid,address
 assert result['responses'],'no ADVERTISE'
 sid,offer=qualify(result['responses'][0])
 request_xid=bytes.fromhex('d1a602')
 hint=socket.inet_pton(socket.AF_INET6,offer['address'])+bytes(8)
 request=b'\x03'+request_xid+option(1,duid)+option(2,bytes.fromhex(sid))+option(3,iaid+bytes(8)+option(5,hint))+option(8,bytes(2))+option(6,struct.pack('!HH',23,24))
 result['sent_request']=0;result['reply']=None
 deadline=time.monotonic()+6;next_send=0
 while time.monotonic()<deadline and result['reply'] is None:
  if time.monotonic()>=next_send:
   sock.sendto(request,('ff02::1:2',547,0,idx));result['sent_request']+=1;next_send=time.monotonic()+2
  try:
   data,peer=sock.recvfrom(65535)
   if len(data)<4 or data[0]!=7 or data[1:4]!=request_xid or peer[1]!=547:continue
   reply={'type':data[0],'peer':peer,'hex':data.hex(),'options':options(data[4:])}
   qualify(reply,sid);result['reply']=reply
  except socket.timeout:pass
 assert result['reply'] is not None,'no qualified REPLY'
 ra.settimeout(.1);result['router_advertisements']=[]
 while True:
  try:packet,ancillary,flags,peer=ra.recvmsg(65535,1024)
  except socket.timeout:break
  if len(packet)<16 or packet[0]!=134:continue
  hoplimits=[struct.unpack('i',v)[0] for level,kind,v in ancillary if level==socket.IPPROTO_IPV6 and kind==socket.IPV6_HOPLIMIT]
  record={'peer':peer,'hoplimits':hoplimits,'flags':packet[5],'router_lifetime':int.from_bytes(packet[6:8],'big'),'prefixes':[]}
  offset=16
  while offset<len(packet):
   kind,units=packet[offset:offset+2];assert units and offset+units*8<=len(packet),'invalid RA option length'
   value=packet[offset:offset+units*8]
   if kind==3:
    assert units==4
    record['prefixes'].append({'length':value[2],'flags':value[3],'valid_lifetime':int.from_bytes(value[4:8],'big'),
     'preferred_lifetime':int.from_bytes(value[8:12],'big'),'prefix':socket.inet_ntop(socket.AF_INET6,value[16:32])})
   offset+=units*8
  result['router_advertisements'].append(record)
 assert result['router_advertisements'],'no RA observed'
 for record in result['router_advertisements']:
  assert record['hoplimits']==[255] and record['flags']&0xc0==0xc0 and record['router_lifetime']==1800,record
  prefixes=record['prefixes'];assert len(prefixes)==1,prefixes
  prefix=prefixes[0]
  assert prefix['prefix']=='2001:db8:1::' and prefix['length']==64 and prefix['flags']&0x80,prefix
  assert 0<prefix['preferred_lifetime']<=prefix['valid_lifetime'],prefix
print(json.dumps(result))
'''

from dhcpv4_probe import standalone_program
PROBE4 = standalone_program()

# Diagnose the original UDP-only reception independently of the AF_PACKET gate.
DIAGNOSE4 = r'''
import json,socket,struct,time,select,subprocess
from pathlib import Path
def snapshot():
 out={'files':{},'commands':{}}
 for name in ('snmp','netstat','dev','udp'):
  out['files']['/proc/net/'+name]=Path('/proc/net/'+name).read_text()
 for interface in ('all','default','client0'):
  for option in ('rp_filter','accept_local','log_martians'):
   path='/proc/sys/net/ipv4/conf/'+interface+'/'+option
   out['files'][path]=Path(path).read_text()
 for label,args in [('addresses',['ip','-j','addr']),('routes',['ip','-j','route','show','table','all']),
  ('route_to_server',['ip','route','get','172.20.0.1']),('route_to_broadcast',['ip','route','get','255.255.255.255']),
  ('firewall',['iptables-save'])]:
  p=subprocess.run(args,text=True,capture_output=True,timeout=3)
  out['commands'][label]={'returncode':p.returncode,'stdout':p.stdout,'stderr':p.stderr}
 return out
mac=bytes.fromhex('020000000011');xid=0xd1a60401
udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);udp.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1)
udp.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,b'client0\0');udp.bind(('0.0.0.0',68));udp.setblocking(False)
raw=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x0800));raw.bind(('client0',0));raw.setblocking(False)
header=struct.pack('!BBBBIHH4s4s4s4s16s64s128s',1,1,6,0,xid,0,0x8000,bytes(4),bytes(4),bytes(4),bytes(4),mac+bytes(10),bytes(64),bytes(128))+bytes.fromhex('63825363')
packet=header+bytes.fromhex('350101370303060fff')
out={'before':snapshot(),'sent_discover':0,'af_packet_offers':[],'udp_datagrams':[],'other_incoming_ipv4':[]}
deadline=time.monotonic()+8;next_send=0
while time.monotonic()<deadline:
 if time.monotonic()>=next_send:
  udp.sendto(packet,('255.255.255.255',67));out['sent_discover']+=1;next_send=time.monotonic()+2
 ready,_,_=select.select([udp,raw],[],[],.2)
 for sock in ready:
  data,peer=sock.recvfrom(65535)
  if sock is udp:
   out['udp_datagrams'].append({'peer':peer,'hex':data.hex()});continue
  if peer[2]==socket.PACKET_OUTGOING:continue
  if len(data)<42 or data[12:14]!=bytes.fromhex('0800'):continue
  ihl=(data[14]&15)*4;start=14+ihl
  record={'peer':list(peer[:4])+[peer[4].hex()],'source':socket.inet_ntoa(data[26:30]),'destination':socket.inet_ntoa(data[30:34]),'hex':data.hex()}
  if data[23]!=17 or len(data)<start+8:
   out['other_incoming_ipv4'].append(record);continue
  src,dst,length,checksum=struct.unpack('!HHHH',data[start:start+8]);payload=data[start+8:start+length]
  record.update(source_port=src,destination_port=dst)
  if src!=67 or dst!=68 or len(payload)<240 or payload[4:8]!=struct.pack('!I',xid) or payload[28:34]!=mac:
   out['other_incoming_ipv4'].append(record);continue
  opts={};i=240
  while i<len(payload):
   code=payload[i];i+=1
   if code==255:break
   if code==0:continue
   assert i<len(payload);n=payload[i];i+=1;assert i+n<=len(payload)
   opts[code]=payload[i:i+n];i+=n
  record['options']={str(k):v.hex() for k,v in opts.items()}
  record['offered']=socket.inet_ntoa(payload[16:20])
  record['server']=socket.inet_ntoa(opts[54]);record['router']=socket.inet_ntoa(opts[3]);record['dns']=socket.inet_ntoa(opts[6])
  assert opts[53]==b'\x02' and record['offered']=='172.20.0.11' and record['router']=='172.20.0.1' and record['dns']=='172.20.0.53',record
  out['af_packet_offers'].append(record)
out['after']=snapshot()
print(json.dumps(out))
'''


def rendered():
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'multinode'))
    from dnlab_multinode.models.topology import (DistributedTopology, InfraHost,
        JumphostConfig, JumphostNet, MgmtConfig, VDNode)
    from dnlab_multinode.services.jumphost import render_dhcp_config
    topo = DistributedTopology(name='diagnostic', master=InfraHost('master','127.0.0.1','root','fixture',True),
        workers={}, underlay_iface='lo', jumphost=JumphostConfig(image=IMAGE),
        jumphost_net=JumphostNet('fixture','fixture','198.18.1.0/24','198.18.1.1'),
        nodes={'vd':VDNode('vd','linux','fixture',mgmt_ipv4='172.20.0.11',mgmt_ipv6='2001:db8:1::11',
            mgmt_mac='02:00:00:00:00:11',mgmt_duid='00:04:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:11')},
        links=[],mgmt=MgmtConfig('fixture','fixture','172.20.0.0/24','172.20.0.1',
            ipv6_subnet='2001:db8:1::/64',ipv6_gw='2001:db8:1::fe',dhcp=True))
    return render_dhcp_config(topo,'172.20.0.53')


def run(output,verify=False,ipv4_diagnostic=False):
    root=Path(output);root.mkdir(mode=0o700)
    plugin_before=hashlib.sha256(PLUGIN.read_bytes()).hexdigest()
    state_before=json.loads(PLUGIN_STATE.read_text())
    report={'scope':'bounded DHCPv4/v6 handshake and RA gate' if verify else 'DHCPv6 SOLICIT/ADVERTISE and RA comparison only',
        'rfc_compliance_concluded':False,'image':IMAGE,'mode':'verify' if verify else 'diagnose',
        'cases':{},'status':'running'}
    if ipv4_diagnostic:
        report.update(scope='single addressless DHCPv4 AF_PACKET/UDP reception diagnosis',mode='ipv4-diagnostic')
    def save(name,value):
        path=root/name
        with path.open('w') as stream:
            stream.write(json.dumps(value,indent=2)+'\n');stream.flush();os.fsync(stream.fileno())
        fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
    def cmd(argv,check=True,**kwargs):
        result=subprocess.run(argv,text=True,capture_output=True,timeout=20,**kwargs)
        if check and result.returncode:raise RuntimeError(f'{argv!r}: rc={result.returncode}: {result.stderr}')
        return result
    current=rendered()
    report['renderer_config_sha256']=hashlib.sha256(current.encode()).hexdigest()
    original=current.replace('dhcp-range=set:mgmt,2001:db8:1::,','dhcp-range=tag:mgmt,::,')
    controls={'rendered':current} if verify or ipv4_diagnostic else {'original':original,
        'set-tag-only':original.replace('dhcp-range=tag:mgmt,::,','dhcp-range=set:mgmt,::,'),
        'explicit-prefix-control':original.replace('dhcp-range=tag:mgmt,::,','dhcp-range=set:mgmt,2001:db8:1::,')}
    try:
        for case,content in controls.items():
            directory=root/case;directory.mkdir(mode=0o755)
            cfg=directory/'dnsmasq.conf';cfg.write_text(content);cfg.chmod(0o644)
            token=uuid.uuid4().hex[:12];name='drsp-d6-'+token;ns=name+'-c'
            intent={'name':name,'namespace':ns,'nonce':token,'image':IMAGE,
                'config_sha256':hashlib.sha256(content.encode()).hexdigest()}
            save(case+'/intent.json',intent)
            cid=None;nsid=None;server_ns=None;processes=[];files=[];created=False
            def inspect():
                data=json.loads(cmd(['docker','inspect',name]).stdout)[0]
                if data['Id']!=cid or data['Config']['Labels'].get('dnlab.diag.nonce')!=token or data['Image']!=IMAGE:
                    raise RuntimeError('container birth differs')
                return data
            def client(*args,**kwargs):
                st=os.stat('/var/run/netns/'+ns)
                if (st.st_dev,st.st_ino)!=nsid:raise RuntimeError('client namespace identity differs')
                return cmd(['ip','netns','exec',ns,*args],**kwargs)
            def server(*args,**kwargs):
                data=inspect();pid=data['State']['Pid'];st=os.stat(f'/proc/{pid}/ns/net')
                if (st.st_dev,st.st_ino)!=server_ns:raise RuntimeError('server namespace identity differs')
                return cmd(['nsenter','-t',str(pid),'-n','--',*args],**kwargs)
            result={'config':content}
            try:
                cmd(['ip','netns','add',ns]);created=True
                st=os.stat('/var/run/netns/'+ns);nsid=(st.st_dev,st.st_ino)
                # Record nonce intent before create and Docker ID before bootstrap.
                cmd(['docker','create','--name',name,'--label','dnlab.diag.nonce='+token,
                    '--network','none','--cap-add','NET_ADMIN','--mount',f'type=bind,src={cfg},dst=/fixture.conf,readonly',
                    '--entrypoint','python3',IMAGE,'-c','import time;time.sleep(600)'])
                raw=json.loads(cmd(['docker','inspect',name]).stdout)[0];cid=raw['Id'];inspect()
                save(case+'/birth.json',{'container_id':cid,'intent':intent})
                cmd(['docker','start',cid]);data=inspect();pid=data['State']['Pid']
                st=os.stat(f'/proc/{pid}/ns/net');server_ns=(st.st_dev,st.st_ino)
                client('ip','link','add','client0','type','veth','peer','name','eth1','netns',str(pid))
                client('ip','link','set','client0','address','02:00:00:00:00:11')
                client('ip','link','set','client0','alias','drsp-dhcpv6:'+token)
                server('ip','link','set','eth1','alias','drsp-dhcpv6:'+token)
                for command in [('ip','link','set','lo','up'),('ip','link','set','client0','up')]:client(*command)
                server('ip','link','set','lo','up');server('ip','addr','add','172.20.0.1/24','dev','eth1')
                server('ip','-6','addr','add','2001:db8:1::fe/64','dev','eth1');server('ip','link','set','eth1','up')
                for _ in range(50):
                    a=json.loads(server('ip','-j','-6','addr','show','dev','eth1').stdout)
                    b=json.loads(client('ip','-j','-6','addr','show','dev','client0').stdout)
                    if all(any(x['scope']=='link' and not x.get('tentative',False) for x in side[0]['addr_info']) for side in (a,b)):break
                    time.sleep(.1)
                else:raise RuntimeError('link-local readiness timed out')
                save(case+'/endpoints.json',{'server':a,'client':b})
                pcaplog=(directory/'capture.log').open('w');files.append(pcaplog)
                capture=subprocess.Popen(['ip','netns','exec',ns,'tcpdump','-U','-i','client0','-w',str(directory/'wire.pcap'),
                    'icmp6 or udp port 546 or udp port 547 or udp port 67 or udp port 68'],stdout=pcaplog,stderr=pcaplog);processes.append(capture)
                for _ in range(50):
                    if capture.poll() is not None:raise RuntimeError('capture exited')
                    if 'listening on client0' in (directory/'capture.log').read_text():break
                    time.sleep(.1)
                else:raise RuntimeError('capture readiness timed out')
                dnslog=(directory/'dnsmasq.log').open('w');files.append(dnslog)
                daemon=subprocess.Popen(['docker','exec',cid,'dnsmasq','--keep-in-foreground','--log-dhcp',
                    '--log-facility=-','--conf-file=/fixture.conf'],stdout=dnslog,stderr=dnslog);processes.append(daemon)
                for _ in range(50):
                    if daemon.poll() is not None:raise RuntimeError('dnsmasq exited: '+(directory/'dnsmasq.log').read_text())
                    if ':0223' in cmd(['docker','exec',cid,'cat','/proc/net/udp6']).stdout:break
                    time.sleep(.1)
                else:raise RuntimeError('DHCPv6 socket readiness timed out')
                time.sleep(.3)
                if ipv4_diagnostic:
                    save(case+'/server-before.json',json.loads(server('ip','-j','addr').stdout))
                probe=client(sys.executable,'-c',DIAGNOSE4 if ipv4_diagnostic else PROBE,*(['verify'] if verify else []),check=False)
                save(case+'/probe-command.json',{'returncode':probe.returncode,'stdout':probe.stdout,'stderr':probe.stderr})
                if probe.returncode:raise RuntimeError('DHCPv6 probe failed: '+probe.stderr)
                result['probe']=json.loads(probe.stdout)
                if ipv4_diagnostic:
                    save(case+'/server-after.json',json.loads(server('ip','-j','addr').stdout))
                if verify:
                    server_link=json.loads(server('ip','-j','link','show','dev','eth1').stdout)[0]
                    save(case+'/ipv4-server-port.json',server_link)
                    ipv4=client(sys.executable,'-c',PROBE4,server_link['address'],check=False)
                    save(case+'/ipv4-command.json',{'returncode':ipv4.returncode,'stdout':ipv4.stdout,'stderr':ipv4.stderr})
                    if ipv4.returncode:raise RuntimeError('DHCPv4 probe failed: '+ipv4.stderr)
                    result['ipv4']=json.loads(ipv4.stdout)
                result['version']=cmd(['docker','exec',cid,'dnsmasq','--version']).stdout
                result['binary_sha256']=cmd(['docker','exec',cid,'sha256sum','/usr/sbin/dnsmasq']).stdout.strip()
                result['status']='observed'
            finally:
                errors=[]
                # Signals target only local diagnostic children. Namespace removal follows verified container exit.
                for proc in reversed(processes):
                    if proc.poll() is None:proc.send_signal(signal.SIGINT)
                for proc in processes:
                    try:proc.wait(timeout=4)
                    except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=4)
                for handle in files:handle.close()
                if cid:
                    try:
                        inspect();cmd(['docker','kill',cid],check=False)
                        cmd(['docker','wait',cid]);inspect();cmd(['docker','rm',cid])
                        missing=cmd(['docker','inspect',cid],check=False)
                        save(case+'/absence.json',{'returncode':missing.returncode,'stdout':missing.stdout,'stderr':missing.stderr})
                        if (missing.returncode!=1 or json.loads(missing.stdout)!=[] or
                                missing.stderr.strip().lower()!='error: no such object: '+cid):
                            raise RuntimeError('container absence not verified')
                    except Exception as error:errors.append(str(error))
                if created:
                    try:
                        client('ip','link','show');cmd(['ip','netns','delete',ns])
                        if Path('/var/run/netns',ns).exists():raise RuntimeError('namespace still present')
                    except Exception as error:errors.append(str(error))
                result['cleanup_verified']=not errors
                if errors:result['cleanup_errors']=errors
                report['cases'][case]=result;save('report.json',report)
                if errors:raise RuntimeError('fixture cleanup incomplete: '+repr(errors))
            decoded=cmd(['tcpdump','-nn','-vv','-r',str(directory/'wire.pcap')]).stdout
            (directory/'wire.txt').write_text(decoded)
            result['ra_packets']=decoded.count('router advertisement')
            result['solicit_packets']=decoded.count('dhcp6 solicit')
            result['advertise_packets']=decoded.count('dhcp6 advertise')
        report['status']='passed' if verify else 'diagnosed'
    except BaseException as error:
        report['status']='failed';report['error']=str(error);raise
    finally:
        report['plugin_source_unchanged']=hashlib.sha256(PLUGIN.read_bytes()).hexdigest()==plugin_before
        report['plugin_state_unchanged']=json.loads(PLUGIN_STATE.read_text())==state_before
        if not report['plugin_source_unchanged'] or not report['plugin_state_unchanged']:
            report['status']='failed';report['baseline_error']='installed plugin source or state differs'
        save('report.json',report)
        print(json.dumps({'report':str(root/'report.json'),'status':report['status']}))


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output',required=True)
    modes=parser.add_mutually_exclusive_group()
    modes.add_argument('--verify',action='store_true');modes.add_argument('--ipv4-diagnostic',action='store_true')
    args=parser.parse_args()
    run(args.output,verify=args.verify,ipv4_diagnostic=args.ipv4_diagnostic)
