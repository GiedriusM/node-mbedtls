const mbedtls = require('../index.js');
const expect = require('chai').expect;

describe('SSLContext', () => {
  it('should initialize without parameters', () => {
    expect(new mbedtls.SSLContext()).to.be.an('mbedtls_ssl_context');
    expect(mbedtls.SSLContext()).to.be.an('mbedtls_ssl_context');
  });

  describe('state', () => {
    it('should be read-only number', () => {
      const ctx = new mbedtls.SSLContext();
      expect(ctx.state).to.be.a('number');
      ctx.state = 314;
      expect(ctx.state).to.equal(0);
    });
  });

  describe('setup function', () => {
    it('should validate input parameters', () => {
      const ctx = new mbedtls.SSLContext();
      const conf = new mbedtls.SSLConfig();
      // Valid parameters
      expect(ctx.setup(conf)).to.equal(0);
      // Invalid parameters
      expect(() => ctx.setup()).to.throw(TypeError);
    });
  });

  describe('set_bio function', () => {
    it('should validate input parameters', () => {
      const ctx = new mbedtls.SSLContext();
      // Valid parameters
      expect(() => ctx.set_bio(() => { }, () => { }, () => { })).to.not.throw();
      expect(() => ctx.set_bio(() => { }, null, () => { })).to.not.throw();
      expect(() => ctx.set_bio(null, null, null)).to.not.throw();
      // Invalid parameters
      expect(() => ctx.set_bio()).to.throw(TypeError);
      expect(() => ctx.set_bio({}, null, null)).to.throw(TypeError);
      expect(() => ctx.set_bio(null, {}, null)).to.throw(TypeError);
      expect(() => ctx.set_bio(null, null, {})).to.throw(TypeError);
    });
  });

  describe('set_timer_cb function', () => {
    it('should validate input parameters', () => {
      const ctx = new mbedtls.SSLContext();
      // Valid parameters
      expect(() => ctx.set_timer_cb(() => { }, () => { })).to.not.throw();
      expect(() => ctx.set_timer_cb(null, null)).to.not.throw();
      // Invalid parameters
      expect(() => ctx.set_timer_cb()).to.throw(TypeError);
      expect(() => ctx.set_timer_cb({}, null)).to.throw(TypeError);
      expect(() => ctx.set_timer_cb(null, {})).to.throw(TypeError);
    });
  });

  describe('session_reset function', () => {
    it('should validate input parameters', () => {
      const ctx = new mbedtls.SSLContext();
      const conf = new mbedtls.SSLConfig();
      ctx.setup(conf); // Segfaults if config is not set
      // Valid parameters
      expect(ctx.session_reset()).to.equal(0);
    });
  });

  describe('handshake function', () => {
    it('should validate input parameters', () => {
      const ctx = new mbedtls.SSLContext();
      // Valid parameters
      expect(ctx.handshake()).to.be.a('number');
    });
  });

  describe('read function', () => {
    it('should validate input parameters', () => {
      const ctx = new mbedtls.SSLContext();
      const buf = Buffer.alloc(128);
      // Valid parameters
      expect(ctx.read(buf)).to.be.a('number');
      // Invalid parameters
      expect(() => ctx.read()).to.throw(TypeError);
      expect(() => ctx.read("")).to.throw(TypeError);
    });
  });

  describe('write function', () => {
    it('should validate input parameters', () => {
      const ctx = new mbedtls.SSLContext();
      const buf = Buffer.alloc(128);
      // Valid parameters
      expect(ctx.write(buf)).to.be.a('number');
      // Invalid parameters
      expect(() => ctx.write()).to.throw(TypeError);
      expect(() => ctx.write({})).to.throw(TypeError);
    });
  });

  describe('send_alert_message function', () => {
    it('should validate input parameters', () => {
      const ctx = new mbedtls.SSLContext();
      // Valid parameters
      expect(ctx.send_alert_message(0, 0)).to.be.a('number');
      // Invalid parameters
      expect(() => ctx.send_alert_message()).to.throw(TypeError);
    });
  });

  describe('close_notify function', () => {
    it('should validate input parameters', () => {
      const ctx = new mbedtls.SSLContext();
      // Valid parameters
      expect(ctx.close_notify()).to.be.a('number');
    });
  });
});
