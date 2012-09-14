var proxyServer = require('./proxy.js');

var config = {
  addProxyHeader: false
};

var httpProxyServer = proxyServer.createServer(config);
httpProxyServer.listen(parseInt(process.argv[2]))
