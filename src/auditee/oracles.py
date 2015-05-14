import re
from xml.dom import minidom
import urllib2
from base64 import b64decode,b64encode


kernelId = 'aki-503e7402'
snapshotID_main = 'snap-cdd399f8'
snapshotID_sig = 'snap-00083b35'
imageID_main = 'ami-5e39040c'
imageID_sig = 'ami-88724fda'

oracle_modulus = [200,206,3,195,115,240,245,171,146,48,87,244,28,184,6,253,36,28,201,42,163,10,2,113,165,195,180,162,209,12,74,118,133,170,236,185,52,20,121,92,140,131,66,32,133,233,147,209,176,76,156,79,14,189,86,65,16,214,6,182,132,159,144,194,243,15,126,236,236,52,69,102,75,34,254,167,110,251,254,186,193,182,162,25,75,218,240,221,148,145,140,112,238,138,104,46,240,194,192,173,65,83,7,25,223,102,197,161,126,43,44,125,129,68,133,41,10,223,94,252,143,147,118,123,251,178,7,216,167,212,165,187,115,58,232,254,76,106,55,131,73,194,36,74,188,226,104,201,128,194,175,120,198,119,237,71,205,214,56,119,36,77,28,22,215,61,13,144,145,6,120,46,19,217,155,118,237,245,78,136,233,106,108,223,209,115,95,223,10,147,171,215,4,151,214,200,9,27,49,180,23,136,54,194,168,147,33,15,204,237,68,163,149,152,125,212,9,243,81,145,20,249,125,44,28,19,155,244,194,237,76,52,200,219,227,24,54,15,88,170,36,184,109,122,187,224,77,188,126,212,143,93,30,143,133,58,99,169,222,225,26,29,223,22,27,247,92,225,253,124,185,77,118,117,0,83,169,28,217,22,200,68,109,17,198,88,203,163,33,3,184,236,43,170,51,225,147,255,78,41,154,197,8,171,81,253,134,151,107,68,23,66,7,81,150,5,110,184,138,22,137,46,209,152,39,227,125,106,161,131,240,41,82,65,223,129,172,90,26,189,158,240,66,244,253,246,167,66,170,209,20,162,210,245,110,193,172,24,188,18,23,207,10,83,84,250,96,149,144,126,237,45,194,154,163,145,235,30,41,235,211,162,201,215,4,58,102,133,60,43,166,143,81,187,7,72,140,76,120,146,248,54,106,170,25,126,241,161,106,103,108,108,123,10,88,180,208,219,53,34,106,206,96,55,108,24,238,126,194,107,88,32,77,180,29,73,193,13,123,99,229,219,197,175,244,70,8,110,113,130,126,8,109,74,216,203,61,26,146,195,228,240,25,150,173,47,123,108,94,106,114,13,212,195,246,24,42,138,245,122,63,112,93,201,174,104,30,14,112,18,214,80,139,58,224,215,185,12,69,203,206,112,58,231,171,117,159,214,73,173,44,155]

oracle = {'name':'tlsnotarygroup1',
                'main': 
                {"IP":"52.74.29.34",
                "port":"10011",
                'DI':'https://ec2.ap-southeast-1.amazonaws.com/?AWSAccessKeyId=AKIAIHF5FKKL7SKLLJNQ&Action=DescribeInstances&Expires=2018-01-01&InstanceId=i-e2f28d2f&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&Signature=u6rcenB%2Feng0c%2FMknOEJu7nbb8s0qHd84AJmF1pLTCc%3D',
                'DV':'https://ec2.ap-southeast-1.amazonaws.com/?AWSAccessKeyId=AKIAIHF5FKKL7SKLLJNQ&Action=DescribeVolumes&Expires=2018-01-01&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&VolumeId=vol-70423d7e&Signature=22tBu9aEToc1he01%2BN%2BBn8S6ESPt2ZAOOuCDdCrr7kc%3D',
                'GCO':'https://ec2.ap-southeast-1.amazonaws.com/?AWSAccessKeyId=AKIAIHF5FKKL7SKLLJNQ&Action=GetConsoleOutput&Expires=2018-01-01&InstanceId=i-e2f28d2f&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&Signature=lvCv2bPNLaEcqPv%2FoGef3lN2ni83A%2B5sMBEpnPcb740%3D',
                'GU':'https://iam.amazonaws.com/?AWSAccessKeyId=AKIAIHF5FKKL7SKLLJNQ&Action=GetUser&Expires=2018-01-01&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2010-05-08&Signature=rKqb5XyhcRMCPhIXsUv0ETkcjOBvLr5xskUWpbyGyB8%3D',
                'DIA':'https://ec2.ap-southeast-1.amazonaws.com/?AWSAccessKeyId=AKIAIHF5FKKL7SKLLJNQ&Action=DescribeInstanceAttribute&Attribute=userData&Expires=2018-01-01&InstanceId=i-e2f28d2f&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&Signature=ntW%2F89MAan9PebvA%2B3%2F4P8qwHWwJ%2B1v0VqoItBAIqAE%3D',
                'instanceId': 'i-e2f28d2f'
        },
        'sig': {
                "modulus":[200,206,3,195,115,240,245,171,146,48,87,244,28,184,6,253,36,28,201,42,163,10,2,113,165,195,180,162,209,12,74,118,133,170,236,185,52,20,121,92,140,131,66,32,133,233,147,209,176,76,156,79,14,189,86,65,16,214,6,182,132,159,144,194,243,15,126,236,236,52,69,102,75,34,254,167,110,251,254,186,193,182,162,25,75,218,240,221,148,145,140,112,238,138,104,46,240,194,192,173,65,83,7,25,223,102,197,161,126,43,44,125,129,68,133,41,10,223,94,252,143,147,118,123,251,178,7,216,167,212,165,187,115,58,232,254,76,106,55,131,73,194,36,74,188,226,104,201,128,194,175,120,198,119,237,71,205,214,56,119,36,77,28,22,215,61,13,144,145,6,120,46,19,217,155,118,237,245,78,136,233,106,108,223,209,115,95,223,10,147,171,215,4,151,214,200,9,27,49,180,23,136,54,194,168,147,33,15,204,237,68,163,149,152,125,212,9,243,81,145,20,249,125,44,28,19,155,244,194,237,76,52,200,219,227,24,54,15,88,170,36,184,109,122,187,224,77,188,126,212,143,93,30,143,133,58,99,169,222,225,26,29,223,22,27,247,92,225,253,124,185,77,118,117,0,83,169,28,217,22,200,68,109,17,198,88,203,163,33,3,184,236,43,170,51,225,147,255,78,41,154,197,8,171,81,253,134,151,107,68,23,66,7,81,150,5,110,184,138,22,137,46,209,152,39,227,125,106,161,131,240,41,82,65,223,129,172,90,26,189,158,240,66,244,253,246,167,66,170,209,20,162,210,245,110,193,172,24,188,18,23,207,10,83,84,250,96,149,144,126,237,45,194,154,163,145,235,30,41,235,211,162,201,215,4,58,102,133,60,43,166,143,81,187,7,72,140,76,120,146,248,54,106,170,25,126,241,161,106,103,108,108,123,10,88,180,208,219,53,34,106,206,96,55,108,24,238,126,194,107,88,32,77,180,29,73,193,13,123,99,229,219,197,175,244,70,8,110,113,130,126,8,109,74,216,203,61,26,146,195,228,240,25,150,173,47,123,108,94,106,114,13,212,195,246,24,42,138,245,122,63,112,93,201,174,104,30,14,112,18,214,80,139,58,224,215,185,12,69,203,206,112,58,231,171,117,159,214,73,173,44,155],
                'DI':'https://ec2.ap-southeast-1.amazonaws.com/?AWSAccessKeyId=AKIAI2LSGPAGQTAR6UPQ&Action=DescribeInstances&Expires=2018-01-01&InstanceId=i-eaee9127&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&Signature=dVywKE9V8YSticfknIpUh3OY0zuN%2BOpsozLN%2F44u%2FHk%3D',
                'DV':'https://ec2.ap-southeast-1.amazonaws.com/?AWSAccessKeyId=AKIAI2LSGPAGQTAR6UPQ&Action=DescribeVolumes&Expires=2018-01-01&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&VolumeId=vol-82bfc08c&Signature=Jqu7ykkGqCmvuSvJgD7odC8%2F6onaijr%2BsVGg8nEOES4%3D',
                'GCO':'https://ec2.ap-southeast-1.amazonaws.com/?AWSAccessKeyId=AKIAI2LSGPAGQTAR6UPQ&Action=GetConsoleOutput&Expires=2018-01-01&InstanceId=i-eaee9127&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&Signature=15CXO6WVRzww8VvZ5noXRqI5HpjIaDXUYdzR0j1AOaI%3D',
                'GU':'https://iam.amazonaws.com/?AWSAccessKeyId=AKIAI2LSGPAGQTAR6UPQ&Action=GetUser&Expires=2018-01-01&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2010-05-08&Signature=qtHAlM8MedH7NRlJazfqYdlVJFaXEbiU9CenC%2FWc1CQ%3D',
                'DIA':'https://ec2.ap-southeast-1.amazonaws.com/?AWSAccessKeyId=AKIAI2LSGPAGQTAR6UPQ&Action=DescribeInstanceAttribute&Attribute=userData&Expires=2018-01-01&InstanceId=i-eaee9127&SignatureMethod=HmacSHA256&SignatureVersion=2&Version=2014-10-01&Signature=Leqk1fx7X1AQkErydEljdwZoEV9LmxMm9EC8mwodCIs%3D',
                'instanceId': 'i-eaee9127',
                'IP': '52.74.155.127'
        }
        } 


def get_xhr(url):
    xml = urllib2.urlopen(url).read()
    return minidom.parseString(xml)

def getChildNodes(x):
    return [a for a in x[0].childNodes if not a.nodeName=='#text']

#assuming both events happened on the same day, get the time
#difference between them in seconds
#the time string looks like "2015-04-15T19:00:59.000Z"
def getSecondsDelta (later, sooner):
    assert (len(later) == 24)
    if (later[:11] != sooner[:11]):
	return 999999; #not on the same day
    laterTime = later[11:19].split(':')
    soonerTime = sooner[11:19].split(':')
    laterSecs = int(laterTime[0])*3600+int(laterTime[1])*60+int(laterTime[2])
    soonerSecs = int(soonerTime[0])*3600+int(soonerTime[1])*60+int(soonerTime[2])
    return laterSecs - soonerSecs


def modulus_from_pubkey(pem_pubkey):
	b64_str = ''
	lines = pem_pubkey.split('\n')
	#omit header and footer lines
	for i in range(1,len(lines)-1):
	    b64_str += lines[i]
	der = b64decode(b64_str)
	#last 5 bytes are 2 DER bytes and 3 bytes exponent, our pubkey is the preceding 512 bytes
	pubkey = der[len(der)-517:len(der)-5]
	return pubkey

def checkDescribeInstances(xmlDoc, instanceId, IP, type):
    try:
	if type == 'main':
	    imageID = imageID_main
	    snapshotID = snapshotID_main
	elif type == 'sig':
	    imageID = imageID_sig
	    snapshotID = snapshotID_sig
	else: 
	    raise Exception('unknown oracle type')
	
	rs = xmlDoc.getElementsByTagName('reservationSet')
	assert rs.length == 1    
	rs_items = getChildNodes(rs)
	assert len(rs_items) == 1
	ownerId = rs_items[0].getElementsByTagName('ownerId')[0].firstChild.data
	isets = rs_items[0].getElementsByTagName('instancesSet')
	assert isets.length == 1
	instances = getChildNodes(isets)
	assert len(instances) == 1
	parent = instances[0]
	assert parent.getElementsByTagName('instanceId')[0].firstChild.data == instanceId
	assert parent.getElementsByTagName('imageId')[0].firstChild.data == imageID
	assert parent.getElementsByTagName('instanceState')[0].getElementsByTagName('name')[0].firstChild.data == 'running'
	launchTime = parent.getElementsByTagName('launchTime')[0].firstChild.data
	assert parent.getElementsByTagName('kernelId')[0].firstChild.data == kernelId
	assert parent.getElementsByTagName('ipAddress')[0].firstChild.data == IP
	assert parent.getElementsByTagName('rootDeviceType')[0].firstChild.data == 'ebs'
	assert parent.getElementsByTagName('rootDeviceName')[0].firstChild.data == '/dev/xvda'
	devices = parent.getElementsByTagName('blockDeviceMapping')[0].getElementsByTagName('item')
	assert devices.length == 1
	assert devices[0].getElementsByTagName('deviceName')[0].firstChild.data == '/dev/xvda'
	assert devices[0].getElementsByTagName('ebs')[0].getElementsByTagName('status')[0].firstChild.data == 'attached'
	volAttachTime = devices[0].getElementsByTagName('ebs')[0].getElementsByTagName('attachTime')[0].firstChild.data
	volumeId = devices[0].getElementsByTagName('ebs')[0].getElementsByTagName('volumeId')[0].firstChild.data
	#get seconds from "2015-04-15T19:00:59.000Z"
	assert getSecondsDelta(volAttachTime, launchTime) <= 3
	
    except:
	return False
	
    return {'ownerId':ownerId, 'volumeId':volumeId, 'volAttachTime':volAttachTime, 'launchTime':launchTime};

def checkDescribeVolumes(xmlDoc, instanceId, volumeId, volAttachTime, type):
    try:
	if type == 'main':
	    imageID = imageID_main
	    snapshotID = snapshotID_main
	elif type == 'sig':
	    imageID = imageID_sig
	    snapshotID = snapshotID_sig
	else: 
	    raise Exception('unknown oracle type')
	
	v = xmlDoc.getElementsByTagName('volumeSet')
	volumes = getChildNodes(v)
	assert len(volumes) == 1
	volume = volumes[0]
	assert volume.getElementsByTagName('volumeId')[0].firstChild.data == volumeId
	assert volume.getElementsByTagName('snapshotId')[0].firstChild.data == snapshotID
	assert volume.getElementsByTagName('status')[0].firstChild.data == 'in-use'
	volCreateTime = volume.getElementsByTagName('createTime')[0].firstChild.data
	attVolumes = volume.getElementsByTagName('attachmentSet')[0].getElementsByTagName('item')
	assert attVolumes.length == 1
	attVolume = attVolumes[0];
	assert attVolume.getElementsByTagName('volumeId')[0].firstChild.data == volumeId
	assert attVolume.getElementsByTagName('instanceId')[0].firstChild.data == instanceId
	assert attVolume.getElementsByTagName('device')[0].firstChild.data == '/dev/xvda'
	assert attVolume.getElementsByTagName('status')[0].firstChild.data == 'attached'
	attTime = attVolume.getElementsByTagName('attachTime')[0].firstChild.data
	assert volAttachTime == attTime
	#Crucial: volume was created from snapshot and attached at the same instant
	#this guarantees that there was no time window to modify it
	assert getSecondsDelta(attTime, volCreateTime) == 0	
    except:
	return False
    
    return True


def checkGetConsoleOutput(xmlDoc, instanceId, launchTime, type, main_pubkey):
    #try:
    assert xmlDoc.getElementsByTagName('instanceId')[0].firstChild.data == instanceId
    timestamp = xmlDoc.getElementsByTagName('timestamp')[0].firstChild.data
    #prevent funny business: last consoleLog entry no later than 4 minutes after instance starts
    assert getSecondsDelta(timestamp, launchTime) <= 240
    b64data = xmlDoc.getElementsByTagName('output')[0].firstChild.data
    logstr = b64decode(b64data)
    #no other string starting with xvd except for xvda
    assert not re.match(r'/xvd[^a]/g',logstr)
    mainmark = 'TLSNotary main server pubkey which is embedded into the signing server:'
    sigmark = 'TLSNotary siging server pubkey:'
    sigimportedmark = 'TLSNotary imported main server pubkey:'
    pkstartmark = '-----BEGIN PUBLIC KEY-----'
    pkendmark = '-----END PUBLIC KEY-----'
    
    if type == 'main':
	mark_start = logstr.index(mainmark)
	assert mark_start != -1
	pubkey_start = mark_start + logstr[mark_start:].index(pkstartmark)
	pubkey_end = pubkey_start+ logstr[pubkey_start:].index(pkendmark) + len(pkendmark)
	pubkey = logstr[pubkey_start:pubkey_end]
	assert len(pubkey) > 0
	return pubkey
    
    elif type == 'sig':
	mark_start = logstr.index(sigmark);
	assert mark_start != -1
	pubkey_start = mark_start + logstr[mark_start:].index(pkstartmark)
	pubkey_end = pubkey_start+ logstr[pubkey_start:].index(pkendmark) + len(pkendmark)
	mypubkey = logstr[pubkey_start:pubkey_end]
	assert len(mypubkey) > 0
	    
	mark_start = logstr.index(sigimportedmark)
	assert mark_start != -1
	pubkey_start = mark_start + logstr[mark_start:].index(pkstartmark)
	pubkey_end = pubkey_start+ logstr[pubkey_start:].index(pkendmark) + len(pkendmark)
	hispubkey = logstr[pubkey_start:pubkey_end]
	assert main_pubkey == hispubkey
	return mypubkey
    else:
	return False
	
    #except:
	#return False
    
    return True

# "userData" allows to pass an arbitrary script to the instance at launch. It MUST be empty.
# This is a sanity check because the instance is stripped of the code which parses userData.	
def checkDescribeInstanceAttribute(xmlDoc, instanceId):
    try:
	assert xmlDoc.getElementsByTagName('instanceId')[0].firstChild.data == instanceId
	assert not xmlDoc.getElementsByTagName('userData')[0].firstChild
    except:
	return False
    return True

def checkGetUser(xmlDoc, ownerId):
    #try:
    assert xmlDoc.getElementsByTagName('UserId')[0].firstChild.data == ownerId
    assert xmlDoc.getElementsByTagName('Arn')[0].firstChild.data[-(len(ownerId) + len(':root')):] == ownerId+':root'
    #except:
	#return False
    return True

def check_oracle(o, typ, main_pubkey):
    xmlDoc = get_xhr(o['DI'])
    CDIresult = checkDescribeInstances(xmlDoc, o['instanceId'], o['IP'], typ)
    if not CDIresult:
	raise Exception('checkDescribeInstances')	
    xmlDoc = get_xhr(o['DV'])
    CDVresult = checkDescribeVolumes(xmlDoc, o['instanceId'], CDIresult['volumeId'], CDIresult['volAttachTime'], typ)
    if not CDVresult:
	raise Exception('checkDescribeVolumes')
    
    xmlDoc = get_xhr(o['GU'])
    
    CGUresult = checkGetUser(xmlDoc, CDIresult['ownerId'])
    if not CGUresult:
	raise Exception('checkGetUser')	        

    xmlDoc = get_xhr(o['GCO'])
    GCOresult = checkGetConsoleOutput(xmlDoc, o['instanceId'], CDIresult['launchTime'], typ,  main_pubkey['pubkey'])
    if not GCOresult:
	raise Exception('checkGetConsoleOutput')	        
    else:
	yes = True
	if typ == 'main':
	    main_pubkey['pubkey'] = GCOresult
	elif typ == 'sig':
	    sigmod_binary = bytearray('').join(map(chr,o['modulus']))
	    if modulus_from_pubkey(GCOresult) != sigmod_binary:
		raise Exception("modulus from pubkey")
	    
    xmlDoc = get_xhr(o['DIA'])
    DIAresult = checkDescribeInstanceAttribute(xmlDoc, o['instanceId'])
    if not DIAresult:
	raise Exception('checkDescribeInstanceAttribute')	        
					
    mark = 'AWSAccessKeyId=';
    ids = [];
    #"AWSAccessKeyId" should be the same to prove that the queries are made on behalf of AWS user "root".
    #The attacker can be a user with limited privileges for whom the API would report only partial information.
    for url in [o['DI'], o['DV'], o['GU'], o['GCO'], o['DIA']]:
	start = url.index(mark)+len(mark);
	ids.append(url[start:start + url[start:].index('&')])
    assert len(set(ids)) == 1
    print('oracle verification successfully finished')


