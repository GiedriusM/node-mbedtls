const mbedtls = require('../index.js');
const expect = require('chai').expect;
const path = require('path');
const fs = require('fs');


function load_cert(f) {
  const buf = fs.readFileSync(path.resolve(__dirname, 'certificates', f));
  return Buffer.concat([buf, Buffer.from('\0')]);
}

const SERVER_CRT = load_cert('server.crt');

describe('X509Crt', () => {

  it('should initialize without parameters', () => {
    const crt = new mbedtls.X509Crt();
    expect(crt).to.be.an('mbedtls_x509_crt');
  });

  describe('parse function', () => {
    it('should validate input parameters', () => {
      const crt = new mbedtls.X509Crt();
      // Valid parameters
      expect(crt.parse(SERVER_CRT)).to.equal(0);
      // Invalid parameters
      expect(() => crt.parse()).to.throw(TypeError);
    });
  });
});
