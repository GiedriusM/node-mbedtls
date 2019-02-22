const mbedtls = require('../index.js');
const expect = require('chai').expect;
const crypto = require('crypto');

describe('SSLCookie', () => {

  it('should initialize without parameters', () => {
    expect(new mbedtls.SSLCookie()).to.be.an('mbedtls_ssl_cookie');
    expect(mbedtls.SSLCookie()).to.be.an('mbedtls_ssl_cookie');
  });

  describe('setup function', () => {
    it('should validate input parameters', () => {
      const cookies = new mbedtls.SSLCookie();
      // Valid parameters
      expect(cookies.setup(() => { return 0; })).to.equal(0);
      // Invalid parameters
      expect(() => cookies.setup()).to.throw(TypeError);
      expect(() => cookies.setup({})).to.throw(TypeError);
    });
  });

  describe('write function', () => {
    it('should validate input parameters', () => {
      const cookies = new mbedtls.SSLCookie();
      cookies.setup((buf) => {
        crypto.randomFillSync(buf);
        return 0;
      });

      // Valid parameters
      expect(cookies.write(Buffer.alloc(50), Buffer.from('foobar'))).to.be.above(16);
      expect(cookies.write(Buffer.alloc(0), Buffer.from('foobar'))).to.be.below(0);

      // Invalid parameters
      expect(() => cookies.write()).to.throw(TypeError);
      expect(() => cookies.write({}, Buffer.from('foobar'))).to.throw(TypeError);
      expect(() => cookies.write(Buffer.alloc(50), {})).to.throw(TypeError);
    });
  });

  describe('check function', () => {
    it('should validate input parameters', () => {
      const cookies = new mbedtls.SSLCookie();
      cookies.setup((buf) => {
        crypto.randomFillSync(buf);
        return 0;
      });

      let validCookie = Buffer.alloc(100);
      const validInfo = Buffer.from('foobar');
      const len = cookies.write(validCookie, validInfo);
      validCookie = validCookie.slice(0, len);

      // Valid parameters
      expect(cookies.check(validCookie, validInfo)).to.equal(0);
      expect(cookies.check(validCookie, Buffer.from('foobaz'))).to.not.equal(0);
      // Invalid parameters
      expect(() => cookies.check()).to.throw(TypeError);
      expect(() => cookies.check({}, validInfo)).to.throw(TypeError);
      expect(() => cookies.check(validCookie, {})).to.throw(TypeError);
    });
  });
});
