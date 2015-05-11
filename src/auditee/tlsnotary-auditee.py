#!/usr/bin/env python
from __future__ import print_function

from base64 import b64decode, b64encode
from hashlib import md5, sha1, sha256
from os.path import join
from subprocess import Popen, check_output
import binascii, hmac, os, platform,  tarfile
import Queue, random, re, shutil, signal, sys, time
import SimpleHTTPServer, socket, threading, zipfile
import string
try: import wingdbstub
except: pass

#file system setup.
data_dir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.dirname(data_dir))
install_dir = os.path.dirname(os.path.dirname(data_dir))
sessions_dir = join(data_dir, 'sessions')
time_str = time.strftime('%d-%b-%Y-%H-%M-%S', time.gmtime())
current_session_dir = join(sessions_dir, time_str)
os.makedirs(current_session_dir)

#Globals
audit_no = 0 #we may be auditing multiple URLs. This var keeps track of how many
#successful audits there were so far and is used to index html files audited.
#Default values from the config file. Will be overridden after configfile is parsed
global_tlsver = bytearray('\x03\x02')
global_use_gzip = True
global_use_slowaes = False
global_use_paillier = False
random_uid = ''
oracle_modulus = [200,206,3,195,115,240,245,171,146,48,87,244,28,184,6,253,36,28,201,42,163,10,2,113,165,195,180,162,209,12,74,118,133,170,236,185,52,20,121,92,140,131,66,32,133,233,147,209,176,76,156,79,14,189,86,65,16,214,6,182,132,159,144,194,243,15,126,236,236,52,69,102,75,34,254,167,110,251,254,186,193,182,162,25,75,218,240,221,148,145,140,112,238,138,104,46,240,194,192,173,65,83,7,25,223,102,197,161,126,43,44,125,129,68,133,41,10,223,94,252,143,147,118,123,251,178,7,216,167,212,165,187,115,58,232,254,76,106,55,131,73,194,36,74,188,226,104,201,128,194,175,120,198,119,237,71,205,214,56,119,36,77,28,22,215,61,13,144,145,6,120,46,19,217,155,118,237,245,78,136,233,106,108,223,209,115,95,223,10,147,171,215,4,151,214,200,9,27,49,180,23,136,54,194,168,147,33,15,204,237,68,163,149,152,125,212,9,243,81,145,20,249,125,44,28,19,155,244,194,237,76,52,200,219,227,24,54,15,88,170,36,184,109,122,187,224,77,188,126,212,143,93,30,143,133,58,99,169,222,225,26,29,223,22,27,247,92,225,253,124,185,77,118,117,0,83,169,28,217,22,200,68,109,17,198,88,203,163,33,3,184,236,43,170,51,225,147,255,78,41,154,197,8,171,81,253,134,151,107,68,23,66,7,81,150,5,110,184,138,22,137,46,209,152,39,227,125,106,161,131,240,41,82,65,223,129,172,90,26,189,158,240,66,244,253,246,167,66,170,209,20,162,210,245,110,193,172,24,188,18,23,207,10,83,84,250,96,149,144,126,237,45,194,154,163,145,235,30,41,235,211,162,201,215,4,58,102,133,60,43,166,143,81,187,7,72,140,76,120,146,248,54,106,170,25,126,241,161,106,103,108,108,123,10,88,180,208,219,53,34,106,206,96,55,108,24,238,126,194,107,88,32,77,180,29,73,193,13,123,99,229,219,197,175,244,70,8,110,113,130,126,8,109,74,216,203,61,26,146,195,228,240,25,150,173,47,123,108,94,106,114,13,212,195,246,24,42,138,245,122,63,112,93,201,174,104,30,14,112,18,214,80,139,58,224,215,185,12,69,203,206,112,58,231,171,117,159,214,73,173,44,155]


def check_oracle():
    print ('Oracle should be checked via AWS queries; not yet implemented')
    
def probe_server_modulus(server):
    probe_session = shared.TLSNClientSession(server, tlsver=global_tlsver)
    print ('ssl port is: ', probe_session.ssl_port)
    tls_sock = shared.create_sock(probe_session.server_name,probe_session.ssl_port)
    probe_session.start_handshake(tls_sock)
    server_mod, server_exp = probe_session.extract_mod_and_exp()
    tls_sock.close()
    return shared.bi2ba(server_mod)


def start_audit(server_name, headers, server_modulus):
    global global_tlsver
    global global_use_gzip
    global global_use_slowaes
    tlsn_session = shared.TLSNClientSession(server_name, tlsver=global_tlsver)
    tlsn_session.server_modulus = shared.ba2int(server_modulus)
    tlsn_session.server_mod_length = shared.bi2ba(len(server_modulus))        
    print ('Preparing encrypted pre-master secret')
    prepare_pms(tlsn_session)

    for i in range(10):
        try:
            print ('Performing handshake with server')
            tls_sock = shared.create_sock(tlsn_session.server_name,tlsn_session.ssl_port)
            tlsn_session.start_handshake(tls_sock)
            retval = negotiate_crippled_secrets(tlsn_session, tls_sock)
            if not retval == 'success': 
                raise shared.TLSNSSLError('Failed to negotiate secrets: '+retval)                         
            #TODO: cert checking; how to do it for browserless mode?
            #========================================================
            #before sending any data to server compare this connection's cert to the
            #one which FF already validated earlier
            #if sha256(tlsn_session.server_certificate.asn1cert).hexdigest() != certhash:
            #    raise Exception('Certificate mismatch')   
            #========================================================
            print ('Getting data from server')  
            response = make_tlsn_request(headers,tlsn_session,tls_sock)
            #prefix response with number of to-be-ignored records, 
            #note: more than 256 unexpected records will cause a failure of audit. Just as well!
            response = shared.bi2ba(tlsn_session.unexpected_server_app_data_count,fixed=1) + response
            break
        except shared.TLSNSSLError:
            shared.ssl_dump(tlsn_session)
            raise 
        except Exception as e:
            print ('Exception caught while getting data from server, retrying...', e)
            if i == 9:
                raise Exception('Audit failed')
            continue

    global audit_no
    audit_no += 1 #we want to increase only after server responded with data
    sf = str(audit_no)

    commit_hash, pms2, signature = commit_session(tlsn_session, response,sf)
    with open(join(current_session_dir,'sigfile'+sf),'wb') as f:
        f.write(signature)
    with open(join(current_session_dir,'commit_hash_pms2_servermod'+sf),'wb') as f:
        f.write(commit_hash+pms2+shared.bi2ba(tlsn_session.server_modulus))
    
    msg = sha256(commit_hash+pms2+shared.bi2ba(tlsn_session.server_modulus)).digest()
    oracle_int_modulus = shared.ba2int(bytearray('').join(map(chr,oracle_modulus)))
    print ('oracle int mod: ', oracle_int_modulus)
    if not shared.verify_signature(msg, signature, shared.ba2int(bytearray('').join(map(chr,oracle_modulus)))):
        raise Exception("Audit FAILED, notary signature invalid.")
    
    print ('Verified OK')
    audit_data = 'tlsnotary audit file\n\n'
    audit_data += '\x00\x01' #2 version bytes
    audit_data += shared.bi2ba(tlsn_session.chosen_cipher_suite,fixed=2) # 2 bytes
    audit_data += tlsn_session.client_random + tlsn_session.server_random # 64 bytes
    audit_data += tlsn_session.pms1 + pms2 #48 bytes
    audit_data += tlsn_session.server_mod_length #2 bytes
    audit_data += shared.bi2ba(tlsn_session.server_modulus) #256 bytes usually
    audit_data += shared.bi2ba(tlsn_session.server_exponent, fixed=8) #8 bytes
    audit_data += shared.bi2ba(len(tlsn_session.server_name),fixed=2)
    audit_data += tlsn_session.server_name #variable; around 10 bytes
    audit_data += tlsn_session.tlsver #2 bytes
    audit_data += tlsn_session.initial_tlsver #2 bytes
    audit_data += shared.bi2ba(len(response),fixed=8) #8 bytes
    audit_data += response #note that it includes unexpected pre-request app data, 10s of kB
    IV = tlsn_session.IV_after_finished if tlsn_session.chosen_cipher_suite in [47,53] \
                else shared.rc4_state_to_bytearray(tlsn_session.IV_after_finished)
    audit_data += shared.bi2ba(len(IV),fixed=2) #2 bytes
    audit_data += IV #16 bytes or 258 bytes for RC4.
    audit_data += signature #512 bytes RSA PKCS 1 v1.5 padding
    audit_data += commit_hash #32 bytes sha256 hash
    with open(join(install_dir,"public.pem"),"rb") as f:
        audit_data += f.read()
    
    with open(join(current_session_dir,sf+".audit"),"wb") as f:
        f.write(audit_data)
        
    print ("\n\n AUDIT SUCCEEDED. \n ",
    "You can pass the file(s) " , join(current_session_dir, "1.audit (and 2.audit etc. if they exist)"),
    " to an auditor for verification.")

    rv = decrypt_html(pms2, tlsn_session, sf)
    html_paths = b64encode(rv[1])
    return True

#Because there is a 1 in ? chance that the encrypted PMS will contain zero bytes in its
#padding, we first try the encrypted PMS with a reliable site and see if it gets rejected.
def prepare_pms(tlsn_session):
    n = shared.bi2ba(tlsn_session.server_modulus)
    rs_choice = random.choice(shared.reliable_sites.keys())
    for i in range(10): #keep trying until reliable site check succeeds
        try:
            pms_session = shared.TLSNClientSession(rs_choice,shared.reliable_sites[rs_choice][0], ccs=53, tlsver=global_tlsver)
            if not pms_session: 
                raise Exception("Client session construction failed in prepare_pms")
            tls_sock = shared.create_sock(pms_session.server_name,pms_session.ssl_port)
            pms_session.start_handshake(tls_sock)
            reply = send_and_recv('rcr_rsr_rsname_n',
                                  pms_session.client_random+pms_session.server_random+rs_choice[:5]+n)
            if reply[0] != 'success': 
                raise Exception ('Failed to receive a reply for rcr_rsr_rsname_n:')
            if not reply[1]=='rrsapms_rhmac_rsapms':
                raise Exception ('bad reply. Expected rrsapms_rhmac_rsapms:')
            reply_data = reply[2]
            rrsapms2 = reply_data[:256]
            pms_session.p_auditor = reply_data[256:304]
            rsapms2 = reply_data[304:]
            response = pms_session.complete_handshake(tls_sock,rrsapms2)
            tls_sock.close()
            if not response:
                print ("PMS trial failed")
                continue
            #judge success/fail based on whether a properly encoded 
            #Change Cipher Spec record is returned by the server (we could
            #also check the server finished, but it isn't necessary)
            if not response.count(shared.TLSRecord(shared.chcis,f='\x01', tlsver=global_tlsver).serialized):
                print ("PMS trial failed, retrying. (",binascii.hexlify(response),")")
                continue
            tlsn_session.auditee_secret = pms_session.auditee_secret
            tlsn_session.auditee_padding_secret = pms_session.auditee_padding_secret		
            tlsn_session.enc_second_half_pms = shared.ba2int(rsapms2)			
            tlsn_session.set_enc_first_half_pms()
            tlsn_session.set_encrypted_pms()
            return
        except shared.TLSNSSLError:
            shared.ssl_dump(pms_session,fn='preparepms_ssldump')
            shared.ssl_dump(tlsn_session)
            raise
        #except Exception,e:
        #    print ('Exception caught in prepare_pms, retrying...', e)
        #    continue
    raise Exception ('Could not prepare PMS with ', rs_choice, ' after 10 tries. Please '+\
                     'double check that you are using a valid public key modulus for this site; '+\
                     'it may have expired.')

def send_and_recv (cmd, dat,timeout=5):
    headers = {'Request':cmd,"Data":b64encode(dat),"UID":random_uid}
    url = 'http://'+shared.config.get("Notary","server_name")+":"+shared.config.get("Notary","server_port")
    r = requests.head(url,headers=headers)
    r_response_headers = r.headers #case insensitive dict
    received_cmd, received_dat = (r_response_headers['response'],r_response_headers['data'])
    return ('success', received_cmd, b64decode(received_dat))
    
#reconstruct correct http headers
#for passing to TLSNotary custom ssl session
#TODO not yet implemented in browserless mode; should
#add standard headers, esp. gzip according to prefs
def parse_headers(headers):
    header_lines = headers.split('\r\n') #no new line issues; it was constructed like that
    server = header_lines[1].split(':')[1].strip()
    if not global_use_gzip:
        modified_headers = '\r\n'.join([x for x in header_lines if 'gzip' not in x])
    else:
        modified_headers = '\r\n'.join(header_lines)
    return (server,modified_headers)


def negotiate_crippled_secrets(tlsn_session, tls_sock):
    '''Negotiate with auditor in order to create valid session keys
    (except server mac is garbage as auditor withholds it)'''
    assert tlsn_session.handshake_hash_md5
    assert tlsn_session.handshake_hash_sha
    tlsn_session.set_auditee_secret()
    cs_cr_sr_hmacms_verifymd5sha = chr(tlsn_session.chosen_cipher_suite) + tlsn_session.client_random + \
        tlsn_session.server_random + tlsn_session.p_auditee[:24] +  tlsn_session.handshake_hash_md5 + \
        tlsn_session.handshake_hash_sha
    reply = send_and_recv('cs_cr_sr_hmacms_verifymd5sha',cs_cr_sr_hmacms_verifymd5sha)
    if reply[0] != 'success': 
        raise Exception ('Failed to receive a reply for cs_cr_sr_hmacms_verifymd5sha:')
    if not reply[1]=='hmacms_hmacek_hmacverify':
        raise Exception ('bad reply. Expected hmacms_hmacek_hmacverify but got', reply[1])
    reply_data = reply[2]
    expanded_key_len = shared.tlsn_cipher_suites[tlsn_session.chosen_cipher_suite][-1]
    if len(reply_data) != 24+expanded_key_len+12:
        raise Exception('unexpected reply length in negotiate_crippled_secrets')
    hmacms = reply_data[:24]    
    hmacek = reply_data[24:24 + expanded_key_len]
    hmacverify = reply_data[24 + expanded_key_len:24 + expanded_key_len+12] 
    tlsn_session.set_master_secret_half(half=2,provided_p_value = hmacms)
    tlsn_session.p_master_secret_auditor = hmacek
    tlsn_session.do_key_expansion()
    tlsn_session.send_client_finished(tls_sock,provided_p_value=hmacverify)
    sha_digest2,md5_digest2 = tlsn_session.set_handshake_hashes(server=True)
    reply = send_and_recv('verify_md5sha2',md5_digest2+sha_digest2)
    if reply[0] != 'success':
        raise Exception("Failed to receive a reply for verify_md5sha2")
    if not reply[1]=='verify_hmac2':
        raise Exception("bad reply. Expected verify_hmac2:")
    if not tlsn_session.check_server_ccs_finished(provided_p_value = reply[2]):
        raise Exception ("Could not finish handshake with server successfully. Audit aborted")
    return 'success'    

def make_tlsn_request(headers,tlsn_session,tls_sock):
    '''Send TLS request including http headers and receive server response.'''
    try:
        tlsn_session.build_request(tls_sock,headers)
        response = shared.recv_socket(tls_sock) #not handshake flag means we wait on timeout
        if not response: 
            raise Exception ("Received no response to request, cannot continue audit.")
        tlsn_session.store_server_app_data_records(response)
    except shared.TLSNSSLError:
        shared.ssl_dump(tlsn_session)
        raise
    
    tls_sock.close()
    #we return the full record set, not only the response to our request
    return tlsn_session.unexpected_server_app_data_raw + response

def commit_session(tlsn_session,response,sf):
    '''Commit the encrypted server response and other data to auditor'''
    commit_dir = join(current_session_dir, 'commit')
    if not os.path.exists(commit_dir): os.makedirs(commit_dir)
    #Serialization of RC4 'IV' requires concatenating the box,x,y elements of the RC4 state tuple
    IV = shared.rc4_state_to_bytearray(tlsn_session.IV_after_finished) \
        if tlsn_session.chosen_cipher_suite in [4,5] else tlsn_session.IV_after_finished
    stuff_to_be_committed  = {'response':response,'IV':IV,
                              'cs':str(tlsn_session.chosen_cipher_suite),
                              'pms_ee':tlsn_session.pms1,'domain':tlsn_session.server_name,
                              'certificate.der':tlsn_session.server_certificate.asn1cert, 
                              'origtlsver':tlsn_session.initial_tlsver, 'tlsver':tlsn_session.tlsver}
    for k,v in stuff_to_be_committed.iteritems():
        with open(join(commit_dir,k+sf),'wb') as f: f.write(v)    
    commit_hash = sha256(response).digest()
    reply = send_and_recv('commit_hash',commit_hash)
    #TODO: changed response from webserver
    if reply[0] != 'success': 
        raise Exception ('Failed to receive a reply') 
    if not reply[1]=='pms2':
        raise Exception ('bad reply. Expected pms2')    
    return (commit_hash, reply[2][:24], reply[2][24:])


def decrypt_html(pms2, tlsn_session,sf):
    '''Receive correct server mac key and then decrypt server response (html),
    (includes authentication of response). Submit resulting html for browser
    for display (optionally render by stripping http headers).'''
    try:
        tlsn_session.auditor_secret = pms2[:tlsn_session.n_auditor_entropy]
        tlsn_session.set_auditor_secret()
        tlsn_session.set_master_secret_half() #without arguments sets the whole MS
        tlsn_session.do_key_expansion() #also resets encryption connection state
    except shared.TLSNSSLError:
        shared.ssl_dump(tlsn_session)
        raise
        #either using slowAES or a RC4 ciphersuite
    try:
        plaintext,bad_mac = tlsn_session.process_server_app_data_records()
    except shared.TLSNSSLError:
        shared.ssl_dump(tlsn_session)
        raise
    if bad_mac:
        raise Exception("ERROR! Audit not valid! Plaintext is not authenticated.")
    return decrypt_html_stage2(plaintext, tlsn_session, sf)


def decrypt_html_stage2(plaintext, tlsn_session, sf):
    plaintext = shared.dechunk_http(plaintext)
    if global_use_gzip:    
        plaintext = shared.gunzip_http(plaintext)
    #write a session dump for checking even in case of success
    with open(join(current_session_dir,'session_dump'+sf),'wb') as f: f.write(tlsn_session.dump())
    commit_dir = join(current_session_dir, 'commit')
    html_path = join(commit_dir,'html-'+sf)
    with open(html_path,'wb') as f: f.write('\xef\xbb\xbf'+plaintext) #see "Byte order mark"
    if not int(shared.config.get("General","prevent_render")):
        html_path = join(commit_dir,'forbrowser-'+sf+'.html')
        with open(html_path,'wb') as f:
            f.write('\r\n\r\n'.join(plaintext.split('\r\n\r\n')[1:]))
    return ('success',html_path)

#unpack and check validity of Python modules
def first_run_check(modname,modhash):
    if not modhash: return
    mod_dir = join(data_dir, 'python', modname)
    if not os.path.exists(mod_dir):
        print ('Extracting '+modname + '.tar.gz...')
        with open(join(data_dir, 'python', modname+'.tar.gz'), 'rb') as f: tarfile_data = f.read()
        if md5(tarfile_data).hexdigest() !=  modhash:
            raise Exception ('Wrong hash')
        os.chdir(join(data_dir, 'python'))
        tar = tarfile.open(join(data_dir, 'python', modname+'.tar.gz'), 'r:gz')
        tar.extractall()
        tar.close()

if __name__ == "__main__":
    if ('test' in sys.argv): testing = True
    if ('randomtest' in sys.argv): 
        testing = True
        randomtest = True
    if ('mode=addon' in sys.argv): 
        mode='addon'
    else:
        mode='normal'
    #for md5 hash, see https://pypi.python.org/pypi/<module name>/<module version>
    modules_to_load = {'rsa-3.1.4':'b6b1c80e1931d4eba8538fd5d4de1355',\
                       'pyasn1-0.1.7':'2cbd80fcd4c7b1c82180d3d76fee18c8',\
                       'slowaes':'','requests-2.3.0':'7449ffdc8ec9ac37bbcd286003c80f00'}
    for x,h in modules_to_load.iteritems():
        first_run_check(x,h)
        sys.path.append(join(data_dir, 'python', x))

    import rsa
    import pyasn1
    import requests
    from pyasn1.type import univ
    from pyasn1.codec.der import encoder, decoder
    from slowaes import AESModeOfOperation        
    import shared
    shared.load_program_config()
    shared.import_reliable_sites(join(install_dir,'src','shared'))
    random_uid = ''.join(random.choice(string.ascii_lowercase+string.digits) for x in range(10))
    #override default config values
    if int(shared.config.get("General","tls_11")) == 0: 		
        global_tlsver = bytearray('\x03\x01')
    if int(shared.config.get("General","decrypt_with_slowaes")) == 1:
        global_use_slowaes = True
    if int(shared.config.get("General","gzip_disabled")) == 1:
        global_use_gzip = False
    if int(shared.config.get("General","use_paillier_scheme")) == 1:
        global_use_paillier = True    
    
    check_oracle()
    host = sys.argv[1].split('/')[0]
    url = '/'.join(sys.argv[1].split('/')[1:])
    server_mod = probe_server_modulus(host)
    #TODO obv needs to be configurable, best to have whole http request read in from a file
    headers = "GET" + " /" + url + " HTTP/1.1" + "\r\n" + "Host: " + host + "\r\n\r\n"
    if start_audit(host, headers, server_mod):
        print ('successfully finished')
    else:
        print ('failed to complete notarization')