const mbedtls = require('../index.js');
const expect = require('chai').expect;

const certs = require('./certificates');

describe('X509Crl', () => {

  it('should initialize without parameters', () => {
    expect(new mbedtls.X509Crl()).to.be.an('mbedtls_x509_crl');
    expect(mbedtls.X509Crl()).to.be.an('mbedtls_x509_crl');
  });

  describe('parse function', () => {
    it('should validate input parameters', () => {
      const crl = new mbedtls.X509Crl();
      // Valid parameters
      expect(crl.parse(certs.CA_CRL)).to.equal(0);
      // Invalid parameters
      expect(() => crl.parse()).to.throw(TypeError);
      expect(() => crl.parse({})).to.throw(TypeError);
    });
  });
});
