# Browserless PageSigner

Intended to be run as a script.
Use the script tlsnotary-auditee.py in src/auditee
Syntax: `python tlsnotary-auditee.py www.reddit.com/r/all [awscheck]` (no need for https, assumed)

Important notes on usage
========================

1. HTTP request headers: currently the code constructs the minimum viable HTTP request; this may be unsuitable.
Please add headers as you wish to the 


