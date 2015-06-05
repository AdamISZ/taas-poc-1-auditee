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

global_tlsver = bytearray('\x03\x02')
global_use_gzip = True
global_use_slowaes = False
global_use_paillier = False
hcts = None #an http connection to notary
oracle_modulus = [200,206,3,195,115,240,245,171,146,48,87,244,28,184,6,253,36,28,201,42,163,10,2,113,165,195,180,162,209,12,74,118,133,170,236,185,52,20,121,92,140,131,66,32,133,233,147,209,176,76,156,79,14,189,86,65,16,214,6,182,132,159,144,194,243,15,126,236,236,52,69,102,75,34,254,167,110,251,254,186,193,182,162,25,75,218,240,221,148,145,140,112,238,138,104,46,240,194,192,173,65,83,7,25,223,102,197,161,126,43,44,125,129,68,133,41,10,223,94,252,143,147,118,123,251,178,7,216,167,212,165,187,115,58,232,254,76,106,55,131,73,194,36,74,188,226,104,201,128,194,175,120,198,119,237,71,205,214,56,119,36,77,28,22,215,61,13,144,145,6,120,46,19,217,155,118,237,245,78,136,233,106,108,223,209,115,95,223,10,147,171,215,4,151,214,200,9,27,49,180,23,136,54,194,168,147,33,15,204,237,68,163,149,152,125,212,9,243,81,145,20,249,125,44,28,19,155,244,194,237,76,52,200,219,227,24,54,15,88,170,36,184,109,122,187,224,77,188,126,212,143,93,30,143,133,58,99,169,222,225,26,29,223,22,27,247,92,225,253,124,185,77,118,117,0,83,169,28,217,22,200,68,109,17,198,88,203,163,33,3,184,236,43,170,51,225,147,255,78,41,154,197,8,171,81,253,134,151,107,68,23,66,7,81,150,5,110,184,138,22,137,46,209,152,39,227,125,106,161,131,240,41,82,65,223,129,172,90,26,189,158,240,66,244,253,246,167,66,170,209,20,162,210,245,110,193,172,24,188,18,23,207,10,83,84,250,96,149,144,126,237,45,194,154,163,145,235,30,41,235,211,162,201,215,4,58,102,133,60,43,166,143,81,187,7,72,140,76,120,146,248,54,106,170,25,126,241,161,106,103,108,108,123,10,88,180,208,219,53,34,106,206,96,55,108,24,238,126,194,107,88,32,77,180,29,73,193,13,123,99,229,219,197,175,244,70,8,110,113,130,126,8,109,74,216,203,61,26,146,195,228,240,25,150,173,47,123,108,94,106,114,13,212,195,246,24,42,138,245,122,63,112,93,201,174,104,30,14,112,18,214,80,139,58,224,215,185,12,69,203,206,112,58,231,171,117,159,214,73,173,44,155]
oracle_ba_modulus = None
oracle_int_modulus = None

def extract_audit_data(audit_filename):
    audit_data = {}
    with open(audit_filename,'rb') as f:
        header = f.read(29)
        if header != 'tlsnotary notarization file\n\n':
            raise Exception("Invalid file format")
        version = f.read(2)
        if version != '\x00\x01':
            raise Exception("Incompatible file version")
        audit_data['cipher_suite'] = shared.ba2int(f.read(2))
        audit_data['client_random'] = f.read(32)
        audit_data['server_random'] = f.read(32)
        audit_data['pms1'] = f.read(24)
        audit_data['pms2'] = f.read(24)
        audit_data['certs_len'] = shared.ba2int(f.read(3))
        audit_data['certs'] = f.read(audit_data['certs_len'])
        audit_data['tlsver'] = f.read(2)
        audit_data['initial_tlsver'] = f.read(2)
        response_len = shared.ba2int(f.read(8))
        audit_data['response'] = f.read(response_len)
        IV_len = shared.ba2int(f.read(2))
        if IV_len not in [258,16]:
            print ("IV length was: ", IV_len)
            raise Exception("Wrong IV format in audit file")
        audit_data['IV'] = f.read(IV_len)
        audit_data['oracle_modulus_len'] = f.read(2) #TODO can check this
        audit_data['signature'] = f.read(len(oracle_ba_modulus))
        audit_data['commit_hash'] = f.read(32)
        audit_data['oracle_modulus'] = f.read()
        if audit_data['oracle_modulus'] != oracle_ba_modulus:
            print ("file mod was: ", binascii.hexlify(audit_data['oracle_modulus']))
            print ("actual was: ", binascii.hexlify(oracle_ba_modulus))
            raise Exception("Unrecognized oracle")
    return audit_data

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
    audit_filename = sys.argv[1]
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
    oracle_ba_modulus = bytearray('').join(map(chr,oracle_modulus))
    oracle_int_modulus = shared.ba2int(oracle_ba_modulus)     

    shared.load_program_config()
    
    if int(shared.config.get("General","gzip_disabled")) == 1:
        global_use_gzip = False   
    
    audit_data = extract_audit_data(audit_filename)
    #1. Verify notary pubkey - done in extract_audit_data
    print ('Notary pubkey OK')
    #2. Verify signature
    dummy_session = shared.TLSNClientSession()
    first_cert_len = shared.ba2int(audit_data['certs'][:3])
    server_mod, server_exp = dummy_session.extract_mod_and_exp(certDER=audit_data['certs'][3:3+first_cert_len])
    data_to_be_verified = audit_data['commit_hash'] + audit_data['pms2'] + shared.bi2ba(server_mod)
    data_to_be_verified = sha256(data_to_be_verified).digest()
    if not shared.verify_signature(data_to_be_verified, audit_data['signature'],
                                   oracle_int_modulus):
        print ('Audit FAILED. Signature is not verified.')
        exit()        
    print ('Notary signature OK')
    #3. Verify commitment hash.
    if not sha256(audit_data['response']).digest() == audit_data['commit_hash']:
        print ('Audit FAILED. Commitment hash does not match encrypted server response.')
        exit()
    print ('Commitment hash OK')
    #4 Decrypt html and check for mac errors.
    audit_session = shared.TLSNClientSession(ccs=audit_data['cipher_suite'],tlsver=audit_data['initial_tlsver'])
    audit_session.unexpected_server_app_data_count = shared.ba2int(audit_data['response'][0])
    audit_session.tlsver = audit_data['tlsver']
    audit_session.client_random = audit_data['client_random']
    audit_session.server_random = audit_data['server_random']
    audit_session.pms1 = audit_data['pms1']
    audit_session.pms2 = audit_data['pms2']
    audit_session.p_auditee = shared.tls_10_prf('master secret'+audit_session.client_random+audit_session.server_random,
                                                first_half=audit_session.pms1)[0]
    audit_session.p_auditor = shared.tls_10_prf('master secret'+audit_session.client_random+audit_session.server_random,
                                                second_half=audit_session.pms2)[1]
    audit_session.set_master_secret_half()
    audit_session.do_key_expansion()
    audit_session.store_server_app_data_records(audit_data['response'][1:])   
    audit_session.IV_after_finished = (map(ord,audit_data['IV'][:256]),ord(audit_data['IV'][256]), \
            ord(audit_data['IV'][257])) if audit_data['cipher_suite'] in [4,5] else audit_data['IV'] 
    plaintext, bad_mac = audit_session.process_server_app_data_records(is_for_auditor=True)
    if bad_mac:
        print ('Audit FAILED. Decrypted data has bad HMACs.')
    print ('HTML decryption with correct HMACs OK.')
    plaintext = shared.dechunk_http(plaintext)
    plaintext = shared.gunzip_http(plaintext)
    #5 Display html + success.
    with open(join(current_session_dir,'audited.html'),'wb') as f:
        f.write(plaintext)
    #print out the info about the domain
    n_hexlified = binascii.hexlify(shared.bi2ba(server_mod))
    #pubkey in the format 09 56 23 ....
    n_write = " ".join(n_hexlified[i:i+2] for i in range(0, len(n_hexlified), 2))
    with open(join(current_session_dir,'domain_data.txt'), 'wb') as f: 
        f.write('Server pubkey:' + '\n\n' + n_write+'\n')    

    print ("Audit passed! You can read the html at: ",
           join(current_session_dir,'audited.html'), 
           'and check the server certificate with the data provided in ',
           join(current_session_dir,'domain_data.txt'))
    
    