const mbedtls = require('./build/Release/mbedtls');
const { DtlsServer } = require('./server.js');
const { DtlsClient } = require('./client.js');

module.exports = mbedtls;

module.exports.Server = DtlsServer;
module.exports.Socket = DtlsClient;

module.exports.createServer = (opts, callback) => {
  return new DtlsServer(opts, callback);
}
