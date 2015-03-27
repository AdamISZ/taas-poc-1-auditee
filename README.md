# taas-poc-1-auditee
tlsnotary-as-a-service client (auditee) side code, rudimentary set up for testing.

Dependencies: Python, Firefox and Openssl for signatures. 

You can run ./Start(etc).sh to start Firefox, as in normal TLSNotary.
The "splash screen" shown is just brief instructions. Click "Audit" as usual.
This will instigate a tlsnotary session with the remote server at 109.169.23.122 as notary.

Once the audit completes OK (with sig verified), you'll be able to take the file 1.audit 
(or 2.audit etc. if more than one) and pass it to someone else. You can rename them and
move them around as you like; they're self-contained.

The "someone else" (which can be you of course) can run:
`python src/auditee/tlsnotary-auditor.py <name of .audit file>` to check if the audit is valid
and, if so, to get the html and a domain file with the cert in hex to check against Firefox
(see the instructions in auditor guide on main TLSNotary repo and note that a new, more effective
certificate check is in the works.)
