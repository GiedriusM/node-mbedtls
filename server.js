const crypto = require('crypto');
const dgram = require('dgram');
const { EventEmitter } = require('events');
const mbed = require('./mbedtls.js');
const { DtlsConnection } = require('./connection');

class VirtualSocket extends EventEmitter {
  constructor(sock) {
    super();

    this.socket = sock;
  }

  address(...args) { return this.socket.address(...args); }

  send(msg, offset, length, port, address, callback) {
    this.socket.send(msg, offset, length, port, address, callback);
  }

  close() {
    this.emit('close');
  }
}

function getConnectionId(rinfo) {
  const hash = crypto.createHash('sha256');
  hash.update(`[${rinfo.address}]:${rinfo.port}`);
  return hash.digest('hex').slice(0, 12);
}

function createCookie(ctx, cookie, info) {
  // TODO: implement proper cookie mechanism with DoS protection
  return cookie.write('I like cookies');
}

function verifyCookie(ctx, cookie, info) {
  return cookie.length > 0 ? 0 : -1;
}

class DtlsServer extends EventEmitter {
  constructor(opts, callback) {
    super();

    this.options = {
      backlog: opts.backlog || 5,
    };

    this.backlog = {};
    this.connections = {};

    this.ssl_config = new mbed.SSLConfig();
    this.ssl_config.defaults(1, 1, 0);
    this.ssl_config.authmode(2); // MBEDTLS_SSL_VERIFY_REQUIRED
    this.ssl_config.rng((ctx, buf) => {
      crypto.randomFillSync(buf);
      return 0;
    });
    this.ssl_config.dtls_cookies(createCookie, verifyCookie);

    this.sock = dgram.createSocket(opts, callback);
    this.sock.on('close', () => this.emit('close'));
    this.sock.on('error', err => this.emit('error', err));
    this.sock.on('listening', () => this.emit('listening'));
    this.sock.on('message', (msg, rinfo) => {
      const id = getConnectionId(rinfo);
      let con = this.connections[id] || this.backlog[id];

      if (con === undefined) {
        if (Object.keys(this.backlog).length < this.options.backlog) {
          // Create new connection
          const vsock = new VirtualSocket(this.sock);

          const conOpts = {
            ssl_config: this.ssl_config,
            socket: vsock,
          };

          con = new DtlsConnection(conOpts);
          con.remoteAddress = rinfo.address;
          con.remoteFamily = rinfo.family;
          con.remotePort = rinfo.port;

          this.backlog[id] = con;

          con.once('handshake', (err) => {
            delete this.backlog[id];

            if (!err) {
              this.connections[id] = con;
              con.on('message', (...args) => {
                this.emit('message', ...args);
              });
            } else {
              con.close();
            }
          });
        } else {
          this.emit('error', 'Dropping incoming connection. Backlog limit reached.');
        }
      }

      if (con) {
        con.socket.emit('message', msg, rinfo);
      }
    });
  }

  address(...args) {
    return this.sock.address(...args);
  }

  bind(...args) {
    return this.sock.bind(...args);
  }

  close(...args) {
    // XXX: do not close if sock was passed
    return this.sock.close(...args);
  }

  send(...args /* msg[, offset, length], port[, address][, callback] */) {
    let [msg, offset, length, port, address, callback] = args;

    if (!(msg instanceof Buffer)) {
      msg = Buffer.from(args[0], 'utf8');
    }

    // No offset and length - shift args by 2
    if (Number.isNaN(Number(offset)) || Number.isNaN(Number(length))) {
      callback = port;
      address = length;
      port = offset;
      length = msg.length;
      offset = 0;
    }

    offset = Number(offset);
    length = Number(length);

    // No address
    if (typeof (address) !== 'string') {
      callback = address;
      address = undefined;
    }

    const id = getConnectionId({ address: address, port: port });
    const con = this.connections[id]; // backlog connections are not yet established

    if (con) {
      con.send(msg, offset, length, port, address, callback);
    } else {
      const err = new Error(`connection ENOTFOUND ${address}`);
      err.code = 'ENOTFOUND';

      if (callback) {
        callback(err);
      } else {
        this.emit('error', err);
      }
    }
  }

  setPskCallback(callback) {
    if (callback) {
      this.ssl_config.psk_cb((ctx, pskId) => callback(pskId));
    } else {
      this.ssl_config.psk_cb(null);
    }
  }
}

module.exports.DtlsServer = DtlsServer;
