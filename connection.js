const assert = require('assert');
const crypto = require('crypto');
const dgram = require('dgram');
const dns = require('dns');
const net = require('net');

const EventEmitter = require('events').EventEmitter;
const mbed = require('./mbedtls.js');


function status_in_progress(ret) {
  return  ret == -0x6900 || // MBEDTLS_ERR_SSL_WANT_READ
          ret == -0x6880 || // MBEDTLS_ERR_SSL_WANT_WRITE
          ret == -0x6500;   // MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS
}

class DtlsConnection extends EventEmitter {
  constructor(opts) {
    super();

    this.messages = [];
    this.send_messages = [];

    this.interval_timer = null;
    this.final_timer = undefined;

    /* Parse options, create default values if missing */
    opts = opts || 'udp4';

    this.socket = opts.socket;
    if (!this.socket) {
      this.socket = dgram.createSocket(opts);
      this.socket.bind();
    }

    this.remotePort = undefined;
    this.remoteAddress = undefined;

    this.ssl_config = opts.ssl_config;
    if (!this.ssl_config) {
      this.ssl_config = new mbed.SSLConfig();
      this.ssl_config.defaults(0, 1, 0);
      this.ssl_config.authmode(2);
      this.ssl_config.rng((ctx, buf) => {
        crypto.randomFillSync(buf);
        return 0;
      });
    }

    this.lookup = opts.lookup || dns.lookup;

    // Setup new SSL context
    this.ssl = new mbed.SSLContext();
    this.ssl.setup(this.ssl_config);
    this.ssl.set_bio(
      0,
      (ctx, buf) => {
        if (this.remoteAddress === undefined) {
          return -0x6880; // MBEDTLS_ERR_SSL_WANT_WRITE
        }

        this.socket.send(buf, 0, buf.length, this.remotePort, this.remoteAddress);
        return buf.length;
      },
      null,
      (ctx, buf, timeout) => {
        const msg = this.messages.pop();

        if (msg && msg.length <= buf.length) {
          return msg.copy(buf);
        }

        return -0x6900;
      }
    );

    this.ssl.set_timer_cb(
      0,
      (ctx, int_ms, fin_ms) => {
        if (this.interval_timer) {
          clearTimeout(this.interval_timer);
          this.interval_timer = null;
        }
        if (this.final_timer) {
          clearTimeout(this.final_timer);
          this.final_timer = undefined;
        }

        if (fin_ms > 0) {
          if (int_ms > 0) {
            this.interval_timer = setTimeout(() => {
              this.interval_timer = null;
            }, int_ms);
          }

          this.final_timer = setTimeout(() => {
            this.final_timer = null;
            this.process();
          }, fin_ms);

        } else {
          this.final_timer = undefined;
        }
      },
      (ctx) => {
        if (this.final_timer && this.interval_timer) {
          return 0;
        } else if (this.final_timer && this.interval_timer === null) {
          return 1;
        } else if (this.final_timer === null && this.interval_timer === null) {
          return 2;
        } else if (this.final_timer === undefined && this.interval_timer === null) {
          return -1;
        }
      }
    );

    this.ssl.session_reset();

    this.socket.on('message', (msg, rinfo) => {
      assert(rinfo.address === this.remoteAddress);
      assert(rinfo.port === this.remotePort);
      this.messages.unshift(msg);
      this.process();
    });

    this.socket.on('error', (err) => {
      // TODO
      assert(false);
    });

    this.socket.on('close', () => {
      this.emit('close');
    });
  }

  address(...args) {
    return this.socket.address(...args);
  }

  connect(port, host) {
    port = parseInt(port) || undefined;
    host = host || 'localhost';

    assert(port);
    assert(typeof(port) === 'number');

    if (net.isIP(host)) {
      this.remotePort = port;
      this.remoteAddress = host;
      this.process();
    } else {
      this.remoteAddress = undefined;
      this.lookup(host, (err, address) => {
        if (err) {
          this.emit('error', err);
        } else {
          this.remotePort = port;
          this.remoteAddress = address || this.remoteAddress;
          this.process();
        }
      });
    }
  }

  close() {
    this.socket.close(); // TODO: don't close if it was passed from outside
  }

  process() {
    const buf = Buffer.alloc(1024);

    while (1) {
      let ret = -1;

      if (this.ssl.state != 16 /* MBEDTLS_SSL_HANDSHAKE_OVER */) {
        ret = this.ssl.handshake();
        if (this.ssl.state === 16) {
          this.emit('handshake');
        }
      } else {
        ret = this.ssl.read(buf, buf.length);

        if (ret > 0) {
          const rinfo = {
            address: this.remoteAddress,
            port: this.remotePort,
          };
          this.emit('message', buf.slice(0, ret), rinfo);
        } else if (ret === -0x6900 && this.send_messages.length) {
          const msg = this.send_messages.pop();
          ret = this.ssl.write(msg.buffer, msg.offset, msg.length);
          assert(ret === msg.length);
          if (msg.callback) {
            msg.callback();
          }
        }
      }

      if (ret >= 0) {
        continue;
      } else if (status_in_progress(ret))  {
        break;
      } else {
        if (ret === -0x7880 || ret === -0x7780) {
          this.ssl.close_notify();
        } else if (ret === -0x6A80) {
          // Do nothing??
        } else {
          this.ssl.send_alert_message(2, 40);
        }

        // TODO: this should not reset, but do close and cleanup
        this.ssl.session_reset();
        //this.emit('error', ret);
        break;
      }
    }
  }

  send(msg, offset, length, port, addr, callback) {
    if (Array.isArray(msg)) {
      throw new TypeError('Array msg parameter is not supported');
    }

    if (!this.remoteAddress) {
      this.connect(port, addr);
    }

    let send_msg = {
      buffer: msg,
      offset: offset,
      length: length,
      port: port,
      addr: addr,
      callback: callback
    };
    this.send_messages.unshift(send_msg);
    this.process();
  }
}

module.exports.DtlsConnection = DtlsConnection;
