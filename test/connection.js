const mbedtls = require('../index.js');
const expect = require('chai').expect;

const SERVER_PORT = 31415;

function generateMessage() {
  return Math.random().toString(16).replace('0.', '');
}

describe('Connection', () => {

  let server;
  let sock;

  before((done) => {
    server = mbedtls.createServer('udp4');
    server.bind(SERVER_PORT, done);
    server.setPskCallback(() => Buffer.from("password"));
    server.on('message', (msg, rinfo) => {
      server.send(msg, rinfo.port, rinfo.address);
    });
  });

  after((done) => {
    server.close(done);
  });

  beforeEach(() => {
    sock = new mbedtls.Connection('udp4');
    sock.ssl_config.psk(Buffer.from("password"), Buffer.from("user"));
  });

  afterEach((done) => {
    sock.close(done);
  });

  it('should fail without options', () => {
    expect(() => new mbedtls.Connection()).to.throw(TypeError);
  });

  it('should initialize with type', () => {
    expect(new mbedtls.Connection('udp4')).to.be.a('object');
  });

  describe('address function', () => {
    it('should return socket address', (done) => {
      sock.bind(() => {
        const addr = sock.address();
        expect(addr).to.have.property('address');
        expect(addr).to.have.property('port');
        expect(addr).to.have.property('family');
        done();
      });
    });
  });

  describe('bind function', () => {
    it('should execute without parameters', () => {
      expect(() => sock.bind()).to.not.throw();
    });

    it('should call callback', (done) => {
      sock.bind(done);
    });

    it('should bind to specified port', (done) => {
      sock.bind(27182, () => {
        expect(sock.address().port).to.equal(27182);
        done();
      });
    });
  });

  describe('close function', () => {
    it('should call callback', (done) => {
      const s = new mbedtls.Connection('udp4');
      s.close(done);
    });
  });

  describe('send function', () => {
    it('should send a message', (done) => {
      const message = generateMessage();
      server.once('message', (msg, rinfo) => {
        expect(msg.toString()).to.equal(message);
        done();
      });

      sock.send(message, SERVER_PORT);
    });

    it('should call callback', (done) => {
      sock.send(generateMessage(), SERVER_PORT, done);
    });
  });

  describe('close event', () => {
    it('should be emitted after close', (done) => {
      const s = new mbedtls.Connection('udp4');
      s.on('close', done);
      s.close();
    });
  });

  describe('error event', () => {

  });

  describe('listening event', () => {
    it('should be emitted after bind', (done) => {
      sock.on('listening', done);
      sock.bind();
    });
  });

  describe('message event', () => {
    it('should be emitted on message', (done) => {
      const message = generateMessage();

      sock.once('message', (msg, rinfo) => {
        expect(msg.toString()).to.equal(message);
        expect(rinfo).to.have.property('address');
        expect(rinfo).to.have.property('family');
        expect(rinfo.port).to.equal(SERVER_PORT);
        done();
      });

      sock.send(message, SERVER_PORT);
    });
  });
});
