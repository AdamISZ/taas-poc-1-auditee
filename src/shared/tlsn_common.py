from __future__ import print_function
from ConfigParser import SafeConfigParser
from SocketServer import ThreadingMixIn
from struct import pack
import os, binascii, itertools, re, random
import threading, BaseHTTPServer
import select, time, socket
from subprocess import check_output
#General utility objects used by both auditor and auditee.

config = SafeConfigParser()
config_location = os.path.join(os.path.dirname(os.path.realpath(__file__)),'tlsnotary.ini')

#required_options = {'Notary':['notary_server','notary_port']}
required_options = {}
reliable_sites = {}        


def verify_signature(msg, signature, modulus):
    '''RSA verification is sig^e mod n, drop the padding and get the last 32 bytes
    Args: msg as sha256 digest, signature as bytearray, modulus as (big) int
    '''
    sig = ba2int(signature)
    exponent = 65537
    result = pow(sig,exponent,modulus)
    padded_hash = bi2ba(result,fixed=512) #4096 bit key
    unpadded_hash = padded_hash[512-32:]
    if msg==unpadded_hash:
	return True
    else:
	return False

def load_program_config():    

    loadedFiles = config.read([config_location])
    #detailed sanity checking :
    #did the file exist?
    if len(loadedFiles) != 1:
        raise Exception("Could not find config file: "+config_location)
    #check for sections
    for s in required_options:
        if s not in config.sections():
            raise Exception("Config file does not contain the required section: "+s)
    #then check for specific options
    for k,v in required_options.iteritems():
        for o in v:
            if o not in config.options(k):
                raise Exception("Config file does not contain the required option: "+o)


def import_reliable_sites(d):
    '''Read in the site names and ssl ports from the config file,
    and then read in the corresponding pubkeys in browser hex format from
    the file pubkeys.txt in directory d. Then combine this data into the reliable_sites global dict'''
    sites = [x.strip() for x in config.get('SSL','reliable_sites').split(',')]
    ports = [int(x.strip()) for x in config.get('SSL','reliable_sites_ssl_ports').split(',')]
    assert len(sites) == len(ports), "Error, tlsnotary.ini file contains a mismatch between reliable sites and ports"    
    #import hardcoded pubkeys
    with open(os.path.join(d,'pubkeys.txt'),'rb') as f: plines = f.readlines()
    raw_pubkeys= []
    pubkeys = []
    while len(plines):
        next_raw_pubkey = list(itertools.takewhile(lambda x: x.startswith('#') != True,plines))
        k = len(next_raw_pubkey)
        plines = plines[k+1:]
        if k > 0 : raw_pubkeys.append(''.join(next_raw_pubkey))
    for rp in raw_pubkeys: 
        pubkeys.append(re.sub(r'\s+','',rp))
    for i,site in enumerate(sites):
        reliable_sites[site] = [ports[i]]
        reliable_sites[site].append(pubkeys[i])

def check_complete_records(d):
    '''Given a response d from a server,
    we want to know if its contents represents
    a complete set of records, however many.'''
    l = ba2int(d[3:5])
    if len(d)< l+5: return False
    elif len(d)==l+5: return True
    else: return check_complete_records(d[l+5:])

def create_sock(server,prt):
    returned_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    returned_sock.settimeout(int(config.get("General","tcp_socket_timeout"))) 
    returned_sock.connect((server, prt))    
    return returned_sock
    
def recv_socket(sckt,is_handshake=False):
    last_time_data_was_seen_from_server = 0
    data_from_server_seen = False
    databuffer=''
    while True:
        rlist, wlist, xlist = select.select((sckt,), (), (sckt,), 1)
        if len(rlist) == len(xlist) == 0: #timeout
            #TODO dont rely on a fixed timeout 
            delta = int(time.time()) - last_time_data_was_seen_from_server
            if not data_from_server_seen: continue
            if  delta < int(config.get("General","server_response_timeout")): continue
            return databuffer #we timed out on the socket read 
        if len(xlist) > 0:
            print ('Socket exceptional condition. Terminating connection')
            return ''
        if len(rlist) == 0:
            print ('Python internal socket error: rlist should not be empty. Please investigate. Terminating connection')
            return ''
        for rsckt in rlist:
            data = rsckt.recv(1024*32)
            if not data:
                if not databuffer:
                    raise Exception ("Server closed the socket and sent no data")
                else:
                    return databuffer
            data_from_server_seen = True  
            databuffer += data
            if is_handshake: 
                if check_complete_records(databuffer): return databuffer #else, just continue loop
            last_time_data_was_seen_from_server = int(time.time())
    
def bi2ba(bigint,fixed=None):
    m_bytes = []
    while bigint != 0:
        b = bigint%256
        m_bytes.insert( 0, b )
        bigint //= 256
    if fixed:
        padding = fixed - len(m_bytes)
        if padding > 0: m_bytes = [0]*padding + m_bytes
    return bytearray(m_bytes)


def xor(a,b):
    return bytearray([ord(a) ^ ord(b) for a,b in zip(a,b)])

def bigint_to_list(bigint):
    m_bytes = []
    while bigint != 0:
        b = bigint%256
        m_bytes.insert( 0, b )
        bigint //= 256
    return m_bytes

#convert bytearray into int
def ba2int(byte_array):
    return int(str(byte_array).encode('hex'), 16)
    
    
def gunzip_http(http_data):
    import gzip
    import StringIO
    http_header = http_data[:http_data.find('\r\n\r\n')+len('\r\n\r\n')]
    #\s* below means any amount of whitespaces
    if re.search(r'content-encoding:\s*deflate', http_header, re.IGNORECASE):
        #TODO manually resend the request with compression disabled
        raise Exception('Please set gzip_disabled = 1 in tlsnotary.ini and rerun the audit')
    if not re.search(r'content-encoding:\s*gzip', http_header, re.IGNORECASE):
        return http_data #nothing to gunzip
    http_body = http_data[len(http_header):]
    ungzipped = http_header
    gzipped = StringIO.StringIO(http_body)
    f = gzip.GzipFile(fileobj=gzipped, mode="rb")
    ungzipped += f.read()    
    return ungzipped
    
       
def dechunk_http(http_data):
    '''Dechunk only if http_data is chunked otherwise return http_data unmodified'''
    http_header = http_data[:http_data.find('\r\n\r\n')+len('\r\n\r\n')]
    #\s* below means any amount of whitespaces
    if not re.search(r'transfer-encoding:\s*chunked', http_header, re.IGNORECASE):
        return http_data #nothing to dechunk
    http_body = http_data[len(http_header):]
    
    dechunked = http_header
    cur_offset = 0
    chunk_len = -1 #initialize with a non-zero value
    while True:  
        new_offset = http_body[cur_offset:].find('\r\n')
        if new_offset==-1:  #pre-caution against endless looping
            #pinterest.com is known to not send the last 0 chunk when HTTP gzip is disabled
            return dechunked
        chunk_len_hex  = http_body[cur_offset:cur_offset+new_offset]
        chunk_len = int(chunk_len_hex, 16)
        if chunk_len ==0: break #for properly-formed html we should break here
        cur_offset += new_offset+len('\r\n')   
        dechunked += http_body[cur_offset:cur_offset+chunk_len]
        cur_offset += chunk_len+len('\r\n')    
    return dechunked
