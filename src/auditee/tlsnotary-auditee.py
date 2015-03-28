#!/usr/bin/env python
from __future__ import print_function

from base64 import b64decode, b64encode
from hashlib import md5, sha1, sha256
from os.path import join
from subprocess import Popen, check_output
import binascii, hmac, os, platform,  tarfile
import Queue, random, re, shutil, signal, sys, time
import SimpleHTTPServer, socket, threading, zipfile
import httplib
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

#OS detection
m_platform = platform.system()
if m_platform == 'Windows': OS = 'mswin'
elif m_platform == 'Linux': OS = 'linux'
elif m_platform == 'Darwin': OS = 'macos'

#Globals
recv_queue = Queue.Queue() #all messages from the auditor are placed here by receiving_thread
ack_queue = Queue.Queue() #ack numbers are placed here
b_peer_connected = False #toggled to True when p2p connection is establishe
auditor_nick = '' #we learn auditor's nick as soon as we get a ao_hello signed by the auditor
my_nick = '' #our nick is randomly generated on connection
my_prv_key = my_pub_key = auditor_pub_key = None
firefox_pid = selftest_pid = 0
audit_no = 0 #we may be auditing multiple URLs. This var keeps track of how many
#successful audits there were so far and is used to index html files audited.
suspended_session = None #while FF validates the certificate
#Default values from the config file. Will be overridden after configfile is parsed
global_tlsver = bytearray('\x03\x02')
global_use_gzip = True
global_use_slowaes = False
global_use_paillier = False
hcts = None #an http connection to notary

def verify_data(data_to_be_verified, signature):
    return check_output(['openssl','dgst','-ecdsa-with-SHA1',
                        '-verify','public.pem','-signature',signature, data_to_be_verified])

#Receive AES cleartext and send ciphertext to browser
class HandlerClass_aes(SimpleHTTPServer.SimpleHTTPRequestHandler):
    #Using HTTP/1.0 instead of HTTP/1.1 is crucial, otherwise the minihttpd just keep hanging
    #https://mail.python.org/pipermail/python-list/2013-April/645128.html
    protocol_version = "HTTP/1.0"      

    def do_HEAD(self):
        print ('aes_http received ' + self.path[:80] + ' request',end='\r\n')
        # example HEAD string "/command?parameter=124value1&para2=123value2"
        # we need to adhere to CORS and add extra Access-Control-* headers in server replies

        if self.path.startswith('/ready_to_decrypt'):
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Expose-Headers", "status, response, ciphertext, key, iv")
            self.send_header("response", "ready_to_decrypt")
            self.send_header("status", "success")
            #wait for sth to appear in the queue
            ciphertext, key, iv = aes_ciphertext_queue.get()
            self.send_header("ciphertext", b64encode(ciphertext))
            self.send_header("key", b64encode(key))
            self.send_header("iv", b64encode(iv))
            global b_awaiting_cleartext
            b_awaiting_cleartext = True            
            self.end_headers()
            return

        if self.path.startswith('/cleartext'):
            if not b_awaiting_cleartext:
                print ('OUT OF ORDER:' + self.path)
                raise Exception ('received a cleartext request out of order')
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Expose-Headers", "status, response")
            self.send_header("response", "cleartext")
            self.send_header("status", "success")
            cleartext = b64decode(self.path[len('/cleartext?b64cleartext='):])
            aes_cleartext_queue.put(cleartext)
            b_awaiting_cleartext = False            
            self.end_headers()
            return

    #overriding BaseHTTPServer.py's method to cap the output
    def log_message(self, fmt, *args):
        sys.stderr.write("%s - - [%s] %s\n" %
                         (self.client_address[0],
                          self.log_date_time_string(),
                          (fmt%args)[:80]))        


#Receive HTTP HEAD requests from FF addon
class HandleBrowserRequestsClass(SimpleHTTPServer.SimpleHTTPRequestHandler):
    #HTTP/1.0 instead of HTTP/1.1 is crucial, otherwise the http server just keep hanging
    #https://mail.python.org/pipermail/python-list/2013-April/645128.html
    protocol_version = 'HTTP/1.0'

    def respond(self, headers):
        # we need to adhere to CORS and add extra Access-Control-* headers in server replies                
        keys = [k for k in headers]
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Expose-Headers', ','.join(keys))
        for key in headers:
            self.send_header(key, headers[key])
        self.end_headers()        

    def get_certificate(self, args):
        if not args.startswith('b64headers='):
            self.respond({'response':'get_certificate', 'status':'wrong HEAD parameter'})
            return                    
        b64headers = args[len('b64headers='):]
        headers = b64decode(b64headers)
        server_name, modified_headers = parse_headers(headers)        
        print('Probing server to get its certificate')
        try:
            probe_session = shared.TLSNClientSession(server_name, tlsver=global_tlsver)
            probe_sock = shared.create_sock(probe_session.server_name,probe_session.ssl_port)
            probe_session.start_handshake(probe_sock)
        except shared.TLSNSSLError:
            shared.ssl_dump(probe_session)
            raise
        
        probe_sock.close()
        certBase64 = b64encode(probe_session.server_certificate.asn1cert)
        certhash = sha256(probe_session.server_certificate.asn1cert).hexdigest()
        self.respond({'response':'get_certificate', 'status':'success','certBase64':certBase64})
        return [server_name, modified_headers, certhash]


    def start_audit(self, args):
        global global_tlsver
        global global_use_gzip
        global global_use_slowaes
        global suspended_session

        arg1, arg2 = args.split('&')
        if  not arg1.startswith('server_modulus=') or not arg2.startswith('ciphersuite='):
            self.respond({'response':'start_audit', 'status':'wrong HEAD parameter'})
            return        
        server_modulus_hex = arg1[len('server_modulus='):]
        #modulus is lowercase hexdigest
        server_modulus = bytearray(server_modulus_hex.decode("hex"))
        cs = arg2[len('ciphersuite='):] #used for testing, empty otherwise
        server_name, modified_headers, certhash = suspended_session

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
                #before sending any data to server compare this connection's cert to the
                #one which FF already validated earlier
                if sha256(tlsn_session.server_certificate.asn1cert).hexdigest() != certhash:
                    raise Exception('Certificate mismatch')   
                print ('Getting data from server')  
                response = make_tlsn_request(modified_headers,tlsn_session,tls_sock)
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
        print ('Got signature: ', binascii.hexlify(signature))
        with open(join(current_session_dir,'sigfile'+sf),'wb') as f:
            f.write(signature)
        with open(join(current_session_dir,'commit_hash_pms2_servermod'+sf),'wb') as f:
            f.write(commit_hash+pms2+shared.bi2ba(tlsn_session.server_modulus))
        print ('Verifying against notary server pubkey...')
        if 'Verified OK' not in  verify_data(join(current_session_dir,'commit_hash_pms2_servermod'+sf),
                           join(current_session_dir,'sigfile'+sf)):
            raise Exception("Audit FAILED, notary signature invalid.")
        print ('Verified OK')
        #another option would be a fixed binary format for a *.audit file: 
        #cs|cr|sr|pms1|pms2|n|e|domain|tlsver|origtlsver|response|signature|notary_pubkey
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
                    else ''.join(map(chr,tlsn_session.IV_after_finished[0]))+\
                    chr(tlsn_session.IV_after_finished[1])+chr(tlsn_session.IV_after_finished[2])
        audit_data += shared.bi2ba(len(IV),fixed=2) #2 bytes
        audit_data += IV #16 bytes or 258 bytes for RC4.
        audit_data += signature #2 + 2 + 32 + 2 + 33 bytes usually; r,s lengths encoded
        audit_data += commit_hash #32 bytes sha256 hash
        with open(join(install_dir,"public.pem"),"rb") as f:
            audit_data += f.read()
        
        with open(join(current_session_dir,sf+".audit"),"wb") as f:
            f.write(audit_data)
            
        print ("\n\n AUDIT SUCCEEDED. \n ",
        "You can pass the file(s) " , join(current_session_dir, "1.audit (and 2.audit etc. if they exist)"),
        " to an auditor for verification.")

        rv = decrypt_html(pms2, tlsn_session, sf)
        if rv[0] == 'decrypt':
            ciphertexts = rv[1]
            ciphertext, key, iv = ciphertexts[0]
            b64blob = b64encode(iv)+';'+b64encode(key)+';'+b64encode(ciphertext)
            suspended_session = [tlsn_session, ciphertexts, [], 0, sf]
            self.respond({'response':'start_audit', 'status':'success', 
                          'next_action':'decrypt', 'argument':b64blob})
            return
        #else no browser decryption necessary
        html_paths = b64encode(rv[1])
        self.respond({'response':'start_audit', 'status':'success', 'next_action':'audit_finished', 'argument':html_paths})        

    def process_cleartext(self, args):
        global suspended_session
        tlsn_session, ciphertexts, plaintexts, index, sf = suspended_session
        raw_cleartext = b64decode(args[len('b64cleartext='):])
        #crypto-js removes pkcs7 padding. There is still an extra byte which we remove it manually
        plaintexts.append(raw_cleartext[:-1])
        if (index+1) < len(ciphertexts):
            index = index + 1
            ciphertext, key, iv = ciphertexts[index]
            b64blob = b64encode(iv)+';'+b64encode(key)+';'+b64encode(ciphertext)
            suspended_session = [tlsn_session, ciphertexts, plaintexts, index, sf]
            self.respond({'response':'cleartext', 'next_action':'decrypt', 
                          'argument':b64blob, 'status':'success'})
            return
        #else this was the last decrypted ciphertext
        plaintext = tlsn_session.mac_check_plaintexts(plaintexts)
        rv = decrypt_html_stage2(plaintext, tlsn_session, sf)
        self.respond({'response':'cleartext', 'status':'success', 'next_action':'audit_finished', 'argument':b64encode(rv[1])})        

    def do_HEAD(self):
        request = self.path
        print ('browser sent ' + request[:80] + '... request',end='\r\n')
        # example HEAD string "/command?parameter=124value1&para2=123value2"
        if request.startswith('/get_certificate'):
            global suspended_session
            suspended_session  = self.get_certificate(request.split('?', 1)[1])
        elif request.startswith('/start_audit'):
            self.start_audit(request.split('?', 1)[1])
        elif request.startswith('/cleartext'):
            self.process_cleartext(request.split('?', 1)[1])   
        else:
            self.respond({'response':'unknown command'})

    #overriding BaseHTTPRequestHandler's method to cap the output
    def log_message(self, fmt, *args):
        sys.stderr.write("%s - - [%s] %s\n" %
                         (self.client_address[0],
                          self.log_date_time_string(),
                          (fmt%args)[:80]))

#Because there is a 1 in ? chance that the encrypted PMS will contain zero bytes in its
#padding, we first try the encrypted PMS with a reliable site and see if it gets rejected.
#TODO the probability seems to have increased too much w.r.t. random padding, investigate
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
            if not reply[1].startswith('rrsapms_rhmac_rsapms'):
                raise Exception ('bad reply. Expected rrsapms_rhmac_rsapms:')
            reply_data = reply[1][len('rrsapms_rhmac_rsapms:'):]
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

def send_and_recv (hdr, dat,timeout=5):
    rqstring = '/'+hdr+':'+b64encode(dat)
    hcts.request("HEAD", rqstring)
    response = hcts.getresponse() 
    received_hdr, received_dat = (response.getheader('response'),response.getheader('data'))
    if 'busy' in received_hdr:
        raise Exception("Notary server is busy, quitting. Try again later.")
    return ('success', received_hdr+b64decode(received_dat))
    
#reconstruct correct http headers
#for passing to TLSNotary custom ssl session
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
    if not reply[1].startswith('hmacms_hmacek_hmacverify:'):
        raise Exception ('bad reply. Expected hmacms_hmacek_hmacverify but got', reply[1])
    reply_data = reply[1][len('hmacms_hmacek_hmacverify:'):]
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
    if not reply[1].startswith('verify_hmac2:'):
        raise Exception("bad reply. Expected verify_hmac2:")
    if not tlsn_session.check_server_ccs_finished(provided_p_value = reply[1][len('verify_hmac2:'):]):
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
    if not reply[1].startswith('pms2:'):
        raise Exception ('bad reply. Expected pms2')    
    return (commit_hash, reply[1][len('pms2:'):len('pms2:')+24], reply[1][len('pms2:')+24:])


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
    if global_use_slowaes or not tlsn_session.chosen_cipher_suite in [47,53]:
        #either using slowAES or a RC4 ciphersuite
        try:
            plaintext,bad_mac = tlsn_session.process_server_app_data_records()
        except shared.TLSNSSLError:
            shared.ssl_dump(tlsn_session)
            raise
        if bad_mac:
            raise Exception("ERROR! Audit not valid! Plaintext is not authenticated.")
        return decrypt_html_stage2(plaintext, tlsn_session, sf)
    else: #AES ciphersuite and not using slowaes
        try:
            ciphertexts = tlsn_session.get_ciphertexts()
        except:
            shared.ssl_dump(tlsn_session)
            raise
        return ('decrypt', ciphertexts)


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

#Make a local copy of firefox, find the binary, install the new profile
#and start up firefox with that profile.
def start_firefox(FF_to_backend_port, firefox_install_path):
    #find the binary *before* copying; acts as sanity check
    ffbinloc = {'linux':['firefox'],'mswin':['firefox.exe'],'macos':['Contents','MacOS','firefox']}
    assert os.path.isfile(join(*([firefox_install_path]+ffbinloc[OS]))),\
           "Firefox executable not found - invalid Firefox application directory."

    local_ff_copy = join(data_dir,'Firefox.app') if OS=='macos' else join(data_dir,'firefoxcopy')  

    #check if FF-addon/tlsnotary@tlsnotary files were modified. If so, get a fresh 
    #firefoxcopy and FF-profile. This is useful for developers, otherwise
    #we forget to do it manually and end up chasing wild geese
    filehashes = []
    for root, dirs, files in os.walk(join(data_dir, 'FF-addon', 'tlsnotary@tlsnotary')):
        for onefile in files:
            with open(join(root, onefile), 'rb') as f: filehashes.append(md5(f.read()).hexdigest())
    #sort hashes and get the final hash
    filehashes.sort()
    final_hash = md5(''.join(filehashes)).hexdigest()
    hash_path = join(data_dir, 'ffaddon.md5')
    if not os.path.exists(hash_path):
        with open(hash_path, 'wb') as f: f.write(final_hash)
    else:
        with open(hash_path, 'rb') as f: saved_hash = f.read()
        if saved_hash != final_hash:
            print("FF-addon directory changed since last invocation. Creating a new Firefox profile directory...")
            try:
                shutil.rmtree(join(data_dir, 'FF-profile'))
            except:
                pass
            with open(hash_path, 'wb') as f: f.write(final_hash)            

    firefox_exepath = join(*([firefox_install_path]+ffbinloc[OS]))

    logs_dir = join(data_dir, 'logs')
    if not os.path.isdir(logs_dir): os.makedirs(logs_dir)
    with open(join(logs_dir, 'firefox.stdout'), 'w') as f: pass
    with open(join(logs_dir, 'firefox.stderr'), 'w') as f: pass
    ffprof_dir = join(data_dir, 'FF-profile')
    if not os.path.exists(ffprof_dir): os.makedirs(ffprof_dir)
    shutil.copyfile(join(data_dir,'prefs.js'),join(ffprof_dir,'prefs.js'))
    shutil.copyfile(join(data_dir,'localstore.rdf'),join(ffprof_dir,'localstore.rdf'))
    shutil.copyfile(join(data_dir,'extensions.json'),join(ffprof_dir,'extensions.json'))

    extension_path = join(ffprof_dir, 'extensions', 'tlsnotary@tlsnotary')
    if not os.path.exists(extension_path):
        shutil.copytree(join(data_dir, 'FF-addon', 'tlsnotary@tlsnotary'),extension_path)

    #Disable addon compatibility check on startup (note: disabled for MacOS)
    if OS != 'macos':
        try:
            application_ini_data = None
            with open(join(firefox_install_path, 'application.ini'), 'r') as f: application_ini_data = f.read()
            version_pos = application_ini_data.find('Version=')+len('Version=')
            #version string can be 34.0 or 34.0.5
            version_raw = application_ini_data[version_pos:version_pos+8]
            version = ''.join(char for char in version_raw if char in '1234567890.')
    
            with open(join(ffprof_dir, 'prefs.js'), 'a') as f:
                f.write('user_pref("extensions.lastAppVersion", "' + version + '"); ')
        except:
            print ('Failed to disable add-on compatibility check')

    os.putenv('FF_to_backend_port', str(FF_to_backend_port))
    os.putenv('FF_first_window', 'true')   #prevents addon confusion when websites open multiple FF windows
    if not global_use_slowaes:
        os.putenv('TLSNOTARY_USING_BROWSER_AES_DECRYPTION', 'true')

    print ('Starting a new instance of Firefox with tlsnotary profile',end='\r\n')
    try: ff_proc = Popen([firefox_exepath,'-no-remote', '-profile', ffprof_dir],
                         stdout=open(join(logs_dir, 'firefox.stdout'),'w'), 
                         stderr=open(join(logs_dir, 'firefox.stderr'), 'w'))
    except Exception,e: return ('Error starting Firefox: %s' %e,)
    return ('success', ff_proc)

#HTTP server to talk with Firefox addon
def http_server(parentthread): 
    print ('Starting http server to communicate with Firefox addon')
    try:
        httpd = shared.StoppableHttpServer(('127.0.0.1', 0), HandleBrowserRequestsClass)
    except Exception, e:
        parentthread.retval = ('failure',)
        return
    #Caller checks thread.retval for httpd status
    parentthread.retval = ('success', httpd.server_port)
    print ('Serving HTTP on port ', str(httpd.server_port), end='\r\n')
    httpd.serve_forever()


#use miniHTTP server to receive commands from Firefox addon and respond to them
def aes_decryption_thread(parentthread):    
    print ('Starting AES decryption server')
    try:
        aes_httpd = shared.StoppableHttpServer(('127.0.0.1', 0), HandlerClass_aes)
    except Exception, e:
        parentthread.retval = ('failure',)
        return
    #Caller checks thread.retval for httpd status
    parentthread.retval = ('success',  aes_httpd.server_port)
    print ('Receiving decrypted AES on port ', str(aes_httpd.server_port), end='\r\n')
    aes_httpd.serve_forever()

#cleanup
def quit_clean(sig=0, frame=0):
    if firefox_pid != 0:
        try: os.kill(firefox_pid, signal.SIGTERM)
        except: pass #firefox not runnng
    if selftest_pid != 0:
        try: os.kill(selftest_pid, signal.SIGTERM)
        except: pass #selftest not runnng    
    exit(1)

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
    global hcts
    hcts = httplib.HTTPConnection(shared.config.get("Notary","server_name")\
                                  +":"+shared.config.get("Notary","server_port"))
    #override default config values
    if int(shared.config.get("General","tls_11")) == 0: 		
        global_tlsver = bytearray('\x03\x01')
    if int(shared.config.get("General","decrypt_with_slowaes")) == 1:
        global_use_slowaes = True
    if int(shared.config.get("General","gzip_disabled")) == 1:
        global_use_gzip = False
    if int(shared.config.get("General","use_paillier_scheme")) == 1:
        global_use_paillier = True    


    firefox_install_path = None
    if len(sys.argv) > 1: firefox_install_path = sys.argv[1]
    if firefox_install_path in ('test', 'randomtest'): firefox_install_path = None

    if mode == 'normal':
        if not firefox_install_path:
            if OS=='linux':
                if not os.path.exists('/usr/lib/firefox'):
                    raise Exception ("Could not set firefox install path")
                firefox_install_path = '/usr/lib/firefox'
            elif OS=='mswin':
                bFound = False
                prog64 = os.getenv('ProgramW6432')
                prog32 = os.getenv('ProgramFiles(x86)')
                progxp = os.getenv('ProgramFiles')			
                if prog64:
                    if os.path.exists(join(prog64,'Mozilla Firefox')):
                        firefox_install_path = join(prog64,'Mozilla Firefox')
                        bFound = True
                if not bFound and prog32:
                    if os.path.exists(join(prog32,'Mozilla Firefox')):
                        firefox_install_path = join(prog32,'Mozilla Firefox')
                        bFound = True
                if not bFound and progxp:
                    if os.path.exists(join(progxp,'Mozilla Firefox')):
                        firefox_install_path = join(progxp,'Mozilla Firefox')
                        bFound = True
                if not bFound:
                    raise Exception('Could not set firefox install path')
            elif OS=='macos':
                if not os.path.exists(join("/","Applications","Firefox.app")):
                    raise Exception('''Could not set firefox install path. 
                    Please make sure Firefox is in your Applications folder''')
                firefox_install_path = join("/","Applications","Firefox.app")
            else:
                raise Exception("Unrecognised operating system.")           
        print ("Firefox install path is: ",firefox_install_path)
        if not os.path.exists(firefox_install_path): 
            raise Exception ("Could not find Firefox installation")

    thread = shared.ThreadWithRetval(target= http_server)
    thread.daemon = True
    thread.start()
    #wait for minihttpd thread to indicate its status and FF_to_backend_port  
    b_was_started = False
    for i in range(10):
        time.sleep(1)        
        if thread.retval == '': continue
        #else
        if thread.retval[0] != 'success': 
            raise Exception (
                'Failed to start minihttpd server. Please investigate')
        #else
        b_was_started = True
        break
    if b_was_started == False:
        raise Exception ('minihttpd failed to start in 10 secs. Please investigate')
    FF_to_backend_port = thread.retval[1]

    if mode == 'addon':
        with open (join(data_dir, 'ports'), 'w') as f:
            f.write(str(FF_to_backend_port))
    elif mode == 'normal':
        ff_retval = start_firefox(FF_to_backend_port, firefox_install_path)
        if ff_retval[0] != 'success': 
            raise Exception (
                'Error while starting Firefox: '+ ff_retval[0])
        ff_proc = ff_retval[1]
        firefox_pid = ff_proc.pid 

    signal.signal(signal.SIGTERM, quit_clean)

    try:
        while True:
            time.sleep(1)
            if mode == 'normal':
                if ff_proc.poll() != None: quit_clean() #FF was closed
    except KeyboardInterrupt: quit_clean()            