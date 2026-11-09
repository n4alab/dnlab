"""Validate packet acknowledgments and progress against the original profile."""
import re
import ipaddress


def dns_profile(profile,request):
    fields={'mode','interface','client_mac','server_mac','server_ip','server_ipv6','server_link_local',
            'addresses','resolvers','records','token'}
    identity=request['identity'];attachment=request['attachment']
    addresses={'4':identity['ipv4']}
    if identity['ipv6']:addresses['6']=identity['ipv6']
    if (set(profile)!=fields or profile['mode']!='dns-client' or profile['interface']!='probe0'
            or profile['client_mac']!=identity['mac'] or profile['addresses']!=addresses
            or not re.fullmatch('[0-9a-f]{2}(?::[0-9a-f]{2}){5}',profile['server_mac'])
            or int(profile['server_mac'][:2],16)&1 or profile['server_mac'] in (identity['mac'],'00:00:00:00:00:00')
            or profile['server_ip']!=str(ipaddress.ip_interface(attachment['ipv4']).ip)
            or not re.fullmatch('[0-9a-f]{64}',profile['token']) or not isinstance(profile['resolvers'],dict)
            or set(profile['resolvers']) not in ({'4'},{'4','6'})
            or not isinstance(profile['records'],list) or not 1<=len(profile['records'])<=2):
        raise ValueError('DNS client profile differs from original probe')
    resolver=ipaddress.IPv4Address(profile['resolvers']['4'])
    if resolver.is_multicast or resolver.is_unspecified or resolver.is_loopback or resolver.is_link_local:
        raise ValueError('qualified lab DNS resolver required')
    if '6' in addresses:
        if (profile['server_ipv6']!=str(ipaddress.ip_interface(attachment['ipv6']).ip)
                or not ipaddress.IPv6Address(profile['server_link_local']).is_link_local):
            raise ValueError('original IPv6 management router required')
    elif profile['server_ipv6'] is not None or profile['server_link_local'] is not None:
        raise ValueError('unexpected IPv6 DNS router')
    if '6' in profile['resolvers'] and ('6' not in addresses or profile['resolvers']['6']!=profile['server_ipv6']):
        raise ValueError('IPv6 DNS must use original advertised jumphost address')
    seen=set()
    for record in profile['records']:
        if (not isinstance(record,dict) or set(record)!={'name','address'} or not isinstance(record['name'],str)
                or not record['name'].isascii() or len(record['name'].rstrip('.'))>253
                or any(not 1<=len(label)<=63 for label in record['name'].rstrip('.').split('.'))):
            raise ValueError('bounded original DNS records required')
        ipaddress.ip_address(record['address']);key=(record['name'].rstrip('.').lower(),record['address'])
        if key in seen:raise ValueError('duplicate DNS client expectation')
        seen.add(key)


def dns_expected(profile):
    return {'dns.ipv'+family+'.'+transport+'.'+str(index):dict(record,
        type='A' if ipaddress.ip_address(record['address']).version==4 else 'AAAA',family='ipv'+family,
        transport=transport,server=profile['resolvers'][family],client=profile['addresses'][family],
        router_mac=profile['server_mac'],tcp_closed=transport=='tcp')
        for family in sorted(profile['resolvers']) for index,record in enumerate(profile['records']) for transport in ('udp','tcp')}


def dns_progress(profile,stage,row):
    expected=dns_expected(profile).get(stage)
    if (expected is None or not isinstance(row,dict) or set(row)!=set(expected)|{'sent','checksum_status'}
            or any(row.get(k)!=v for k,v in expected.items()) or row['tcp_closed'] is not expected['tcp_closed']
            or type(row['sent']) is not int or not 1<=row['sent']<=32):
        raise ValueError('DNS client receipt differs from original expectation')
    checksums=row['checksum_status']
    allowed={'kernel-offload-pending','kernel-validated','verified'}
    if expected['family']=='ipv4' and expected['transport']=='udp':allowed.add('absent')
    if (not isinstance(checksums,list) or not checksums or any(not isinstance(value,str) for value in checksums)
            or checksums!=sorted(set(checksums)) or set(checksums)-allowed):
        raise ValueError('qualified DNS client checksum evidence required')


def routing_profile(profile,request):
    fields={'mode','interface','client_mac','server_mac','server_ip','server_ipv6','server_link_local',
            'addresses','peer_addresses','peer_segment','token','side','port'}
    row=request['identity'];attachment=request['attachment'];cfg=request['management_intent']
    if (set(profile)!=fields or profile['mode']!='routed-pair' or profile['interface']!='probe0'
            or profile['client_mac']!=row['mac'] or not re.fullmatch('[0-9a-f]{2}(?::[0-9a-f]{2}){5}',profile['server_mac'])
            or int(profile['server_mac'][:2],16)&1 or profile['server_mac']==row['mac']
            or profile['server_ip']!=str(ipaddress.ip_interface(attachment['ipv4']).ip)
            or not isinstance(profile['peer_segment'],str) or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,62}',profile['peer_segment'])
            or profile['peer_segment']==request['segment'] or not re.fullmatch('[0-9a-f]{64}',profile['token'])
            or type(profile['side']) is not int or profile['side'] not in (0,1)
            or type(profile['port']) is not int or not 49152<=profile['port']<=65535
            or not isinstance(profile['addresses'],dict) or set(profile['addresses']) not in ({'4'},{'4','6'})
            or not isinstance(profile['peer_addresses'],dict) or profile['addresses'].keys()!=profile['peer_addresses'].keys()):
        raise ValueError('routing profile differs from original probe identities')
    for family,field in (('4','ipv4'),('6','ipv6')):
        if family not in profile['addresses']:continue
        peer=ipaddress.ip_address(profile['peer_addresses'][family])
        if (profile['addresses'][family]!=row[field] or peer.version!=int(family) or peer.is_multicast
                or peer.is_unspecified or peer.is_link_local or peer.is_loopback
                or peer in ipaddress.ip_network(cfg[field+'_subnet'])):
            raise ValueError('routing peer must be on a distinct original management subnet')
    if '6' in profile['addresses']:
        if (profile['server_ipv6']!=str(ipaddress.ip_interface(attachment['ipv6']).ip)
                or not ipaddress.IPv6Address(profile['server_link_local']).is_link_local):
            raise ValueError('original IPv6 router identity required')
    elif profile['server_ipv6'] is not None or profile['server_link_local'] is not None:
        raise ValueError('unexpected IPv6 routing identity')


def routing_progress(profile,stage,row):
    family=stage.removeprefix('routing.ipv')
    if (not isinstance(row,dict) or stage!='routing.ipv'+family or family not in profile['addresses']
            or set(row)!={'source','target','router_mac','hops','peer_acknowledged','sent'}
            or row['source']!=profile['peer_addresses'][family] or row['target']!=profile['addresses'][family]
            or row['router_mac']!=profile['server_mac'] or type(row['hops']) is not int or row['hops']!=63
            or row['peer_acknowledged'] is not True or type(row['sent']) is not int or not 1<=row['sent']<=30):
        raise ValueError('routing receipt differs from original peer and router')


def expected_progress(profile,result):
    if profile.get('mode')=='dns-client':return result['answers']
    if profile.get('mode')=='routed-pair':
        return {'routing.ipv'+key:row for key,row in result['families'].items()}
    expected={'ipv4.'+name:result['ipv4'][name] for name in ('offer','ack')}
    if result['ipv6']:expected.update({'ipv6.'+name:result['ipv6'][name] for name in ('advertise','reply','ra')})
    return expected


def validate_progress(profile,stage,row):
    if profile.get('mode')=='dns-client':return dns_progress(profile,stage,row)
    if profile.get('mode')=='routed-pair':return routing_progress(profile,stage,row)
    if not isinstance(row,dict):raise ValueError('packet progress object required')
    if stage in ('ipv4.offer','ipv4.ack'):
        expected={'offered':profile['client_ip'],'server':profile['server_ip'],'router':profile['server_ip'],
            'dns':profile['dns_ip'],'type':2 if stage=='ipv4.offer' else 5}
        if (any(row.get(k)!=v for k,v in expected.items()) or type(row.get('sent')) is not int or row['sent']<1
                or row.get('udp_checksum_status') not in ('kernel-offload-pending','kernel-validated','absent','verified')):
            raise ValueError('DHCPv4 receipt differs from original profile')
        return
    six=profile['ipv6']
    if not six:raise ValueError('unexpected IPv6 progress')
    if stage in ('ipv6.advertise','ipv6.reply'):
        expected={'type':2 if stage=='ipv6.advertise' else 7,'iaid':six['iaid'],'address':six['address'],'dns':six['dns']}
        if (any(row.get(k)!=v for k,v in expected.items()) or not re.fullmatch('(?:[0-9a-f]{2}){2,128}',row.get('server_id',''))
                or any(type(row.get(k)) is not int for k in ('preferred_lifetime','valid_lifetime','t1','t2','sent'))
                or not 0<row['preferred_lifetime']<=row['valid_lifetime'] or row['sent']<1
                or row['t1'] and row['t2'] and row['t1']>row['t2']):
            raise ValueError('DHCPv6 receipt differs from original profile')
        return
    if stage!='ipv6.ra':raise ValueError('unknown packet progress stage')
    prefixes=row.get('prefixes',[])
    if (row.get('router_lifetime')!=1800 or type(row.get('flags')) is not int or row['flags']&0xc0!=0xc0
            or not isinstance(prefixes,list) or len(prefixes)!=1):raise ValueError('original RA receipt required')
    prefix=prefixes[0]
    if (not isinstance(prefix,dict) or prefix.get('prefix')!=six['prefix'] or type(prefix.get('flags')) is not int or not prefix['flags']&0x80
            or any(type(prefix.get(k)) is not int for k in ('preferred_lifetime','valid_lifetime'))
            or not 0<prefix['preferred_lifetime']<=prefix['valid_lifetime']):raise ValueError('RA prefix receipt differs')


def validate(profile,result):
    if profile.get('mode')=='dns-client':
        if (not isinstance(result,dict) or set(result)!={'level','answers'} or result['level']!='dns-client-packets'
                or not isinstance(result['answers'],dict) or result['answers'].keys()!=dns_expected(profile).keys()):
            raise ValueError('complete original DNS client receipt required')
        for stage,row in result['answers'].items():dns_progress(profile,stage,row)
        return
    if profile.get('mode')=='routed-pair':
        if (not isinstance(result,dict) or set(result)!={'level','families'} or result['level']!='routed-pair'
                or not isinstance(result['families'],dict) or result['families'].keys()!=profile['addresses'].keys()):
            raise ValueError('complete original routed pair receipt required')
        for stage,row in expected_progress(profile,result).items():routing_progress(profile,stage,row)
        return
    if not isinstance(result,dict) or set(result)!={'level','ipv4','ipv6'} or result['level']!='dhcp-packets':
        raise ValueError('complete DHCP packet receipt required')
    four=result['ipv4']
    if not isinstance(four,dict) or four.get('reception')!='AF_PACKET' or four.get('client_addressless') is not True:
        raise ValueError('addressless DHCPv4 receipt required')
    for name in ('offer','ack'):validate_progress(profile,'ipv4.'+name,four.get(name))
    six=profile['ipv6'];proof=result['ipv6']
    if six is None:
        if proof is not None:raise ValueError('unexpected DHCPv6 receipt')
        return
    if not isinstance(proof,dict) or proof.get('reception')!='AF_PACKET':raise ValueError('DHCPv6 packet receipt required')
    for name in ('advertise','reply','ra'):validate_progress(profile,'ipv6.'+name,proof.get(name))
    if proof['advertise']['server_id']!=proof['reply']['server_id']:raise ValueError('DHCPv6 server changed')
