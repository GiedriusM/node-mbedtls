const fs = require('fs');

function readPem(f) {
  const buf = fs.readFileSync(__dirname + '/' + f);
  return Buffer.concat([buf, Buffer.from('\0')]);
}

const CA_CRT = readPem('ca.crt.pem');
const CA_KEY = readPem('ca.key.pem');
const CA_CRL = readPem('ca.crl.pem');

const SERVER_CRT = readPem('server.crt.pem');
const SERVER_KEY = readPem('server.key.pem');

const REVOKED_CRT = readPem('revoked.crt.pem');
const REVOKED_KEY = readPem('revoked.key.pem');

module.exports = {
  CA_CRT,
  CA_KEY,
  CA_CRL,
  SERVER_CRT,
  SERVER_KEY,
  REVOKED_CRT,
  REVOKED_KEY,
};
