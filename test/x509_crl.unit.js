const mbedtls = require('../index.js');
const expect = require('chai').expect;
const path = require('path');
const fs = require('fs');


function load_cert(f) {
  const buf = fs.readFileSync(path.resolve(__dirname, 'certificates', f));
  return Buffer.concat([buf, Buffer.from('\0')]);
}

const CA_CRL = load_cert('ca.crl.pem');

describe('X509Crl', () => {

  it('should initialize without parameters', () => {
    const crl = new mbedtls.X509Crl();
    expect(crl).to.be.an('mbedtls_x509_crl');
  });

  describe('parse function', () => {
    it('should validate input parameters', () => {
      const crl = new mbedtls.X509Crl();
      // Valid parameters
      expect(crl.parse(CA_CRL)).to.equal(0);
      // Invalid parameters
      expect(() => crl.parse()).to.throw(TypeError);
    });
  });
});
