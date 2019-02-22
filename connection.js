const assert = require('assert');
const crypto = require('crypto');
const dgram = require('dgram');
const dns = require('dns');

const { EventEmitter } = require('events');
const mbed = require('./mbedtls.js');


function isStatusInProgress(ret) {
  return ret === -0x6900      // MBEDTLS_ERR_SSL_WANT_READ
         || ret === -0x6880   // MBEDTLS_ERR_SSL_WANT_WRITE
         || ret === -0x6500;  // MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS
}

class DtlsConnection extends EventEmitter {
  constructor(opts) {
    super();

    this.messages = [];
    this.send_messages = [];

    this.interval_timer = null;
    this.final_timer = undefined;

    /* Parse options, create default values if missing */
    if (!opts) {
      throw new TypeError('Invalid socket options');
    }

    this.socket = opts.socket || dgram.createSocket(opts);

    this.remoteAddress = undefined;
    this.remoteFamily = undefined;
    this.remotePort = undefined;

    this.ssl_config = opts.ssl_config;
    if (!this.ssl_config) {
      this.ssl_config = new mbed.SSLConfig();
      this.ssl_config.defaults(0, 1, 0);
      this.ssl_config.authmode(2);
      this.ssl_config.rng((buf) => {
        crypto.randomFillSync(buf);
        return 0;
      });
    }

    this.lookup = opts.lookup || dns.lookup;

    // Setup new SSL context
    this.ssl = new mbed.SSLContext();
    this.ssl.setup(this.ssl_config);
    this.ssl.set_bio(
      (buf) => {
        if (this.remoteAddress === undefined) {
          return -0x6880; // MBEDTLS_ERR_SSL_WANT_WRITE
        }

        this.socket.send(buf, 0, buf.length, this.remotePort, this.remoteAddress);
        return buf.length;
      },
      null,
      (buf, timeout) => {
        const msg = this.messages.pop();

        if (msg && msg.length <= buf.length) {
          return msg.copy(buf);
        }

        return -0x6900;
      }
    );

    this.ssl.set_timer_cb(
      (interval, finish) => {
        if (this.interval_timer) {
          clearTimeout(this.interval_timer);
          this.interval_timer = null;
        }
        if (this.final_timer) {
          clearTimeout(this.final_timer);
          this.final_timer = undefined;
        }

        if (finish > 0) {
          if (interval > 0) {
            this.interval_timer = setTimeout(() => {
              this.interval_timer = null;
            }, interval);
          }

          this.final_timer = setTimeout(() => {
            this.final_timer = null;
            this.process();
          }, finish);
        } else {
          this.final_timer = undefined;
        }
      },
      () => {
        let status = -1;

        if (this.final_timer && this.interval_timer) {
          status = 0;
        } else if (this.final_timer && this.interval_timer === null) {
          status = 1;
        } else if (this.final_timer === null && this.interval_timer === null) {
          status = 2;
        }

        return status;
      }
    );

    this.ssl.session_reset();

    this.socket.on('listening', () => this.emit('listening'));

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

  bind(...args) {
    return this.socket.bind(...args);
  }

  close(...args) {
    // XXX: should close be called for external sockets?
    this.socket.close(...args);
  }

  connect(...args /* port[, host] */) {
    let [port, host] = args;

    port = Number(port) || undefined;
    host = host || 'localhost';

    assert(port);
    assert(typeof (port) === 'number');

    this.remoteAddress = undefined;
    this.remoteFamily = undefined;
    this.remotePort = undefined;
    this.lookup(host, (err, address, family) => {
      if (err) {
        this.emit('error', err);
      } else {
        this.remoteAddress = address;
        this.remoteFamily = family;
        this.remotePort = port;
        this.process();
      }
    });
  }

  process() {
    const buf = Buffer.alloc(1024);

    let ret = -1;
    do {
      if (this.ssl.state !== 16 /* MBEDTLS_SSL_HANDSHAKE_OVER */) {
        ret = this.ssl.handshake();
        if (this.ssl.state === 16) {
          this.emit('handshake');
        }
      } else {
        ret = this.ssl.read(buf, buf.length);

        if (ret > 0) {
          const rinfo = {
            address: this.remoteAddress,
            family: this.remoteFamily,
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

      if (isStatusInProgress(ret)) {
        break;
      } else if (ret < 0) {
        if (ret === -0x7880 || ret === -0x7780) {
          this.ssl.close_notify();
        } else if (ret === -0x6A80) {
          // Do nothing??
        } else {
          this.ssl.send_alert_message(2, 40);
        }

        // TODO: this should not reset, but do close and cleanup
        this.ssl.session_reset();
        // this.emit('error', ret);
        break;
      }
    } while (ret >= 0);
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

    if (!this.remoteAddress) {
      this.connect(port, address);
    }

    const packet = {
      buffer: msg,
      offset: offset,
      length: length,
      callback: callback
    };
    this.send_messages.unshift(packet);
    this.process();
  }
}

module.exports.DtlsConnection = DtlsConnection;
