const mbedtls = require('../index.js');
const expect = require('chai').expect;
const path = require('path');
const fs = require('fs');


function load_cert(f) {
  const buf = fs.readFileSync(path.resolve(__dirname, 'certificates', f));
  return Buffer.concat([buf, Buffer.from('\0')]);
}

const SERVER_KEY = load_cert('server.key');

describe('PKContext', () => {

  it('should initialize without parameters', () => {
    const pk = new mbedtls.PKContext();
    expect(pk).to.be.an('mbedtls_pk_context');
  });

  describe('parse_key function', () => {
    it('should validate input parameters', () => {
      const new_pk = () => new mbedtls.PKContext();
      // Valid parameters
      expect(new_pk().parse_key(SERVER_KEY, Buffer.from(''))).to.equal(0);
      expect(new_pk().parse_key(SERVER_KEY, null)).to.equal(0);
      // Invalid parameters
      expect(() => new_pk().parse_key()).to.throw(TypeError);
    });
  });
});
