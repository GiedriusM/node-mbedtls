const mbedtls = require('../index.js');
const expect = require('chai').expect;

describe('SSLConfig', () => {

  it('should initialize without parameters', () => {
    expect(new mbedtls.SSLConfig()).to.be.an('mbedtls_ssl_config');
    expect(mbedtls.SSLConfig()).to.be.an('mbedtls_ssl_config');
  });

  describe('authmode function', () => {
    it('should validate input parameters', () => {
      const conf = new mbedtls.SSLConfig();
      // Valid parameters
      expect(() => conf.authmode(mbedtls.SSL_VERIFY_NONE)).to.not.throw();
      expect(() => conf.authmode(mbedtls.SSL_VERIFY_OPTIONAL)).to.not.throw();
      expect(() => conf.authmode(mbedtls.SSL_VERIFY_REQUIRED)).to.not.throw();
      // Invalid parameters
      expect(() => conf.authmode()).to.throw(TypeError);
      expect(() => conf.authmode({})).to.throw(TypeError);
    });
  });

  describe('rng function', () => {
    it('should validate input parameters', () => {
      const conf = new mbedtls.SSLConfig();
      // Valid parameters
      expect(() => conf.rng(() => { })).to.not.throw();
      expect(() => conf.rng(null)).to.not.throw();
      // Invalid parameters
      expect(() => conf.rng()).to.throw(TypeError);
      expect(() => conf.rng({})).to.throw(TypeError);
    });
  });

  describe('dbg function', () => {
    it('should validate input parameters', () => {
      const conf = new mbedtls.SSLConfig();
      // Valid parameters
      expect(() => conf.dbg(() => { })).to.not.throw();
      expect(() => conf.dbg(null)).to.not.throw();
      // Invalid parameters
      expect(() => conf.dbg()).to.throw(TypeError);
      expect(() => conf.dbg({})).to.throw(TypeError);
    });
  });

  describe('dtls_cookies function', () => {
    it('should validate input parameters', () => {
      const conf = new mbedtls.SSLConfig();
      // Valid parameters
      expect(() => conf.dtls_cookies(() => { }, () => { })).to.not.throw();
      expect(() => conf.dtls_cookies(null, null)).to.not.throw();
      // Invalid parameters
      expect(() => conf.dtls_cookies()).to.throw(TypeError);
      expect(() => conf.dtls_cookies({}, null)).to.throw(TypeError);
      expect(() => conf.dtls_cookies(null, {})).to.throw(TypeError);
    });
  });

  describe('ciphersuites function', () => {
    it('should validate input parameters', () => {
      const conf = new mbedtls.SSLConfig();
      // Valid inputs
      expect(() => conf.ciphersuites([])).to.not.throw();
      expect(() => conf.ciphersuites([0x90, 0xAE, 0xC0AC])).to.not.throw();
      expect(() => conf.ciphersuites([0x90, 0xAE, 0xC0AC, 0])).to.not.throw();
      // Invalid inputs
      expect(() => conf.ciphersuites()).to.throw(TypeError);
      expect(() => conf.ciphersuites({})).to.throw(TypeError);
    });
  });

  describe('ca_chain function', () => {
    it('should validate input parameters', () => {
      const conf = new mbedtls.SSLConfig();
      const crt = new mbedtls.X509Crt();
      const crl = new mbedtls.X509Crl();
      // Valid inputs
      expect(() => conf.ca_chain(crt, crl)).to.not.throw();
      expect(() => conf.ca_chain(crt, null)).to.not.throw();
      expect(() => conf.ca_chain(null, null)).to.not.throw();
      // Invalid inputs
      expect(() => conf.ca_chain()).to.throw(TypeError);
      expect(() => conf.ca_chain({}, null)).to.throw(TypeError);
      expect(() => conf.ca_chain(null, {})).to.throw(TypeError);
    });
  });

  describe('own_cert function', () => {
    it('should validate input parameters', () => {
      const conf = new mbedtls.SSLConfig();
      const crt = new mbedtls.X509Crt();
      const pk = new mbedtls.PKContext();
      // Valid inputs
      expect(() => conf.own_cert(crt, pk)).to.not.throw();
      expect(() => conf.own_cert(crt, null)).to.not.throw();
      expect(() => conf.own_cert(null, null)).to.not.throw();
      // Invalid inputs
      expect(() => conf.own_cert()).to.throw(TypeError);
      expect(() => conf.own_cert({}, null)).to.throw(TypeError);
      expect(() => conf.own_cert(null, {})).to.throw(TypeError);
    });
  });

  describe('psk function', () => {
    it('should validate input parameters', () => {
      const conf = new mbedtls.SSLConfig();
      // Valid inputs
      expect(() => conf.psk(Buffer.from('psk'), Buffer.from('psk_identity'))).to.not.throw();
      expect(() => conf.psk(Buffer.from([1, 2, 3]), Buffer.from([4, 5, 6]))).to.not.throw();
      expect(() => conf.psk(null, null)).to.not.throw();
      // Invalid inputs
      expect(() => conf.psk()).to.throw(TypeError);
      expect(() => conf.psk({}, null)).to.throw(TypeError);
      expect(() => conf.psk(null, {})).to.throw(TypeError);
    });
  });

  describe('psk_cb function', () => {
    it('should validate input parameters', () => {
      const conf = new mbedtls.SSLConfig();
      // Valid inputs
      expect(() => conf.psk_cb(() => {})).to.not.throw();
      expect(() => conf.psk_cb(null)).to.not.throw();
      // Invalid inputs
      expect(() => conf.psk_cb()).to.throw(TypeError);
      expect(() => conf.psk_cb({})).to.throw(TypeError);
    });
  });

  describe('defaults function', () => {
    it('should validate input parameters', () => {
      const conf = new mbedtls.SSLConfig();
      // Valid inputs
      expect(conf.defaults(mbedtls.SSL_IS_CLIENT, mbedtls.SSL_TRANSPORT_DATAGRAM, mbedtls.SSL_PRESET_DEFAULT)).to.equal(0);
      expect(conf.defaults(mbedtls.SSL_IS_SERVER, mbedtls.SSL_TRANSPORT_STREAM, mbedtls.SSL_PRESET_SUITEB)).to.equal(0);
      expect(conf.defaults(0, 0, 0)).to.equal(0);
      expect(conf.defaults(1, 1, 1)).to.equal(0);
      // Invalid inputs
      expect(() => conf.defaults()).to.throw(TypeError);
      expect(() => conf.defaults({}, 0, 0)).to.throw(TypeError);
      expect(() => conf.defaults(0, {}, 0)).to.throw(TypeError);
      expect(() => conf.defaults(0, 0, {})).to.throw(TypeError);
    });
  });

});
