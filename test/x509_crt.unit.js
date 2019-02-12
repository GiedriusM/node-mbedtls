const mbedtls = require('../index.js');
const expect = require('chai').expect;

const certs = require('./certificates');


describe('X509Crt', () => {

  it('should initialize without parameters', () => {
    expect(new mbedtls.X509Crt()).to.be.an('mbedtls_x509_crt');
    expect(mbedtls.X509Crt()).to.be.an('mbedtls_x509_crt');
  });

  describe('parse function', () => {
    it('should validate input parameters', () => {
      const crt = new mbedtls.X509Crt();
      // Valid parameters
      expect(crt.parse(certs.SERVER_CRT)).to.equal(0);
      // Invalid parameters
      expect(() => crt.parse()).to.throw(TypeError);
      expect(() => crt.parse({})).to.throw(TypeError);
    });
  });
});
