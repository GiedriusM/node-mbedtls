const mbedtls = require('../index.js');
const expect = require('chai').expect;

const SERVER_PORT = 31415;

function generateMessage() {
  return Math.random().toString(16).replace('0.', '');
}

describe('Server', () => {

  let server;

  beforeEach(() => {
    server = mbedtls.createServer('udp4');
    server.setPskCallback(() => Buffer.from("password"));
  });

  afterEach((done) => {
    server.close(done);
  });

  describe('createServerSocket function', () => {
    it('should fail without options', () => {
      expect(() => mbedtls.createServer()).to.throw(TypeError);
    });

    it('should initialize with type', () => {
      expect(mbedtls.createServer('udp4')).to.be.a('object');
    });
  });

  describe('address function', () => {
    it('should return socket address', (done) => {
      server.bind(() => {
        const addr = server.address();
        expect(addr).to.have.property('address');
        expect(addr).to.have.property('port');
        expect(addr).to.have.property('family');
        done();
      });
    });
  });

  describe('bind function', () => {
    it('should execute without parameters', () => {
      expect(() => server.bind()).to.not.throw();
    });

    it('should call callback', (done) => {
      server.bind(done);
    });

    it('should bind to specified port', (done) => {
      server.bind(27182, () => {
        expect(server.address().port).to.equal(27182);
        done();
      });
    });
  });

  describe('close function', () => {
    it('should call callback', (done) => {
      const s = mbedtls.createServer('udp4');
      s.close(done);
    });
  });

  describe('send function', () => {
    let sock;

    beforeEach(() => {
      sock = mbedtls.createConnection('udp4');
      sock.ssl_config.psk(Buffer.from('password'), Buffer.from('user'));
    });

    afterEach((done) => {
      sock.close(done);
    });

    it('should send a message', (done) => {
      const message = generateMessage();

      server.bind(SERVER_PORT, () => {
        sock.send('a', SERVER_PORT);
      });

      server.once('message', (msg, rinfo) => {
        server.send(message, rinfo.port, rinfo.address);
      });

      sock.once('message', (msg, rinfo) => {
        expect(msg.toString()).to.equal(message);
        done();
      });
    });

    it('should call callback', (done) => {
      server.bind(SERVER_PORT, () => {
        sock.send('a', SERVER_PORT);
      });

      server.once('message', (msg, rinfo) => {
        server.send(generateMessage(), rinfo.port, rinfo.address, done);
      });
    });
  });

  describe('close event', () => {
    it('should be emitted after close', (done) => {
      const s = mbedtls.createServer('udp4');
      s.on('close', done);
      s.close();
    });
  });

  describe('error event', () => {

  });

  describe('listening event', () => {
    it('should be emitted after bind', (done) => {
      server.on('listening', done);
      server.bind();
    });
  });

  describe('message event', () => {
    let sock;

    beforeEach(() => {
      sock = mbedtls.createConnection('udp4');
      sock.ssl_config.psk(Buffer.from('password'), Buffer.from('user'));
    });

    afterEach((done) => {
      sock.close(done);
    });

    it('should be emitted on message', (done) => {
      const message = generateMessage();

      server.once('message', (msg, rinfo) => {
        const addr = sock.address();
        expect(msg.toString()).to.equal(message);
        expect(rinfo).to.have.property('address');
        expect(rinfo).to.have.property('family');
        expect(rinfo).to.have.property('port');
        expect(rinfo.family).to.equal(addr.family);
        expect(rinfo.port).to.equal(addr.port);
        done();
      });

      server.bind(SERVER_PORT, () => {
        sock.send(message, SERVER_PORT);
      });
    });
  });
});
