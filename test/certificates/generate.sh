#!/bin/bash

set -e

touch index.db

### Generate CA
openssl req -x509 -newkey rsa:2048 -keyout 'ca.key.pem' -nodes -sha256 -subj '/CN=ca' -days 1 -out 'ca.crt.pem'

### Generate server certificate
openssl req -new -newkey rsa:2048 -keyout 'server.key.pem' -nodes -sha256 -subj '/CN=server' -days 1 -out 'server.csr.pem'
openssl rand -hex -out 'serial.txt' 16
openssl ca -batch -config 'openssl-ca.conf' -policy signing_policy -extensions signing_req -in 'server.csr.pem' -out 'server.crt.pem'

# Generate revoked certificate
openssl req -new -newkey rsa:2048 -keyout 'revoked.key.pem' -nodes -sha256 -subj '/CN=revoked' -days 1 -out 'revoked.csr.pem'
openssl rand -hex -out 'serial.txt' 16
openssl ca -batch -config 'openssl-ca.conf' -policy signing_policy -extensions signing_req -in 'revoked.csr.pem' -out 'revoked.crt.pem'
openssl ca -config 'openssl-ca.conf' -revoke 'revoked.crt.pem'

### Generate CA CRL
openssl ca -gencrl -config 'openssl-ca.conf' -out 'ca.crl.pem'
