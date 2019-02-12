const dgram = require('dgram');
const EventEmitter = require('events').EventEmitter;
const mbed = require('./mbedtls.js');
const crypto = require('crypto');
const DtlsConnection = require('./connection').DtlsConnection;

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

function get_connection_id(rinfo) {
  const hash = crypto.createHash('sha256');
  hash.update('[' + rinfo.address + ']:' + rinfo.port);
  return hash.digest('hex').slice(0, 12);
}

class DtlsServer extends EventEmitter {
  constructor(opts, callback) {
    super();

    this.options = {
      backlog: opts.backlog | 5,
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
    this.ssl_config.dtls_cookies(
      (ctx, cookie, info) => {
        // TODO: implement proper cookie mechanism with DoS protection
        return cookie.write("I like cookies");
      },
      (ctx, cookie, info) => {
        return cookie.length > 0 ? 0 : -1;
      },
      0
    );

    this.sock = dgram.createSocket(opts, callback);
    this.sock.on('close', () => this.emit('close'));
    this.sock.on('error', (err) => this.emit('error', err));
    this.sock.on('listening', () => this.emit('listening'));
    this.sock.on('message', (msg, rinfo) => {
      const id = get_connection_id(rinfo);
      let con = this.connections[id] || this.backlog[id];

      if (con === undefined) {
        if (Object.keys(this.backlog).length < this.options.backlog) {
          // Create new connection
          const vsock = new VirtualSocket(this.sock);

          const opts = {
            ssl_config: this.ssl_config,
            socket: vsock,
          };

          con = new DtlsConnection(opts);
          con.connect(rinfo.port, rinfo.address);

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

  send(msg, offset, length, port, addr, callback) {
    if (Array.isArray(msg)) {
      throw new TypeError('Array msg parameter is not supported');
    }

    const id = get_connection_id({address: addr, port: port});
    let con = this.connections[id]; // backlog connections are not yet established

    if (con) {
      con.send(msg, offset, length, port, addr, callback);
    } else {
      callback("Connection not found");
    }
  }

  setPskCallback(callback) {
    if (callback) {
      this.ssl_config.psk_cb((ctx, psk_id) => {
        return callback(psk_id);
      });
    } else {
      this.ssl_config.psk_cb(null);
    }
  }
}

module.exports.DtlsServer = DtlsServer;
