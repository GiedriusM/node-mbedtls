try {
  module.exports = require('./build/Release/mbedtls');
} catch (err) {
  module.exports = require('./build/Debug/mbedtls');
}
