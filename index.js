const mbedtls = require('./mbedtls.js');
const { DtlsServer } = require('./server.js');
const { DtlsConnection } = require('./connection.js');

module.exports = mbedtls;

module.exports.Server = DtlsServer;
module.exports.Connection = DtlsConnection;

module.exports.createServer = (opts, callback) => new DtlsServer(opts, callback);

module.exports.createConnection = (opts, callback) => new DtlsConnection(opts, callback);
