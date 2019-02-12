const mbedtls = require('../index.js');
const expect = require('chai').expect;

const certs = require('./certificates');


describe('PKContext', () => {

  it('should initialize without parameters', () => {
    expect(new mbedtls.PKContext()).to.be.an('mbedtls_pk_context');
    expect(mbedtls.PKContext()).to.be.an('mbedtls_pk_context');
  });

  describe('parse_key function', () => {
    it('should validate input parameters', () => {
      const new_pk = () => new mbedtls.PKContext();
      // Valid parameters
      expect(new_pk().parse_key(certs.SERVER_KEY, Buffer.from(''))).to.equal(0);
      expect(new_pk().parse_key(certs.SERVER_KEY, null)).to.equal(0);
      // Invalid parameters
      expect(() => new_pk().parse_key()).to.throw(TypeError);
      expect(() => new_pk().parse_key({}, null)).to.throw(TypeError);
      expect(() => new_pk().parse_key(certs.SERVER_KEY, {})).to.throw(TypeError);
    });
  });
});
