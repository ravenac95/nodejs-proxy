/*
** Peteris Krumins (peter@catonmat.net)
** http://www.catonmat.net  --  good coders code, great reuse
**
** A simple proxy server written in node.js.
**
*/

var http = require('http'),
    https = require('https');
    util = require('util');
    fs   = require('fs');

exports.createServer = function(config) {
  blacklist = config.blacklist || [],
  ipList = config.ipList || [],
  hostFilters = config.hostFilters || {};
  //support functions
  
  //decode host and port info from header
  function decodeHost(host){
      out={};
      host = host.split(':');
      out.host = host[0];
      out.port = host[1] || 80;
      return out;
  }
  
  //encode host field
  function encodeHost(host){
      return host.host+((host.port==80)?"":":"+host.port);
  }
  
  //config files watchers
  //fs.watchFile(config.blacklist,    function(c,p) { updateBlacklist(); });
  //fs.watchFile(config.allowIpList, function(c,p) { updateIpList(); });
  //fs.watchFile(config.hostFilters,  function(c,p) { updateHostFilters(); });
  
  //add a X-Forwarded-For header ?
  config.addProxyHeader = (config.addProxyHeader !== undefined && config.addProxyHeader == true);
  
  //config files loaders/updaters
  function updateList(msg, file, mapf, collectorf) {
    fs.stat(file, function(err, stats) {
      if (!err) {
        util.log(msg);
        fs.readFile(file, function(err, data) {
          collectorf(data.toString().split("\n")
                     .filter(function(rx){return rx.length;})
                     .map(mapf));
        });
      }
      else {
        util.log("File '" + file + "' was not found.");
        collectorf([]);
      }
    });
  }
  
  //filtering rules
  function ipAllowed(ip) {
    return ipList.some(function(ip_) { return ip==ip_; }) || ipList.length <1;
  }
  
  function hostAllowed(host) {
    return !blacklist.some(function(host_) { return host_.test(host); });
  }
  
  //header decoding
  function authenticate(request){
    token={
          "login":"anonymous",
          "pass":""
        };
    if (request.headers.authorization && request.headers.authorization.search('Basic ') === 0) {
      // fetch login and password
      basic = (new Buffer(request.headers.authorization.split(' ')[1], 'base64').toString());
      util.log("Authentication token received: "+basic);
      basic = basic.split(':');
      token.login = basic[0];
  	token.pass = "";
  	for(i=1;i<basic.length;i++){
  		token.pass += basic[i];
  	}
    }
    return token;
  }
  
  //proxying
  //handle 2 rules:
  //  * redirect (301)
  //  * proxyto
  function handleProxyRule(rule, target, token){
    //handle authorization
    if("validuser" in rule){
        if(!(token.login in rule.validuser) || (rule.validuser[token.login] != token.pass)){
           target.action = "authenticate";
           target.msg = rule.description || "";
           return target;
        }
    }
    
    //handle real actions
    if("redirect" in rule){
      target = decodeHost(rule.redirect);
      target.action = "redirect";
    } else if("proxyto" in rule){
      target = decodeHost(rule.proxyto);
      target.action = "proxyto";
    }
    return target;
  }
  
  function handleProxyRoute(host, token) {
      //extract target host and port
      action = decodeHost(host);
      action.action="proxyto";//default action
      
      //try to find a matching rule
      if(action.host+':'+action.port in hostFilters){//rule of the form "foo.domain.tld:port"
        rule=hostFilters[action.host+':'+action.port];
        action=handleProxyRule(rule, action, token);
      }else if (action.host in hostFilters){//rule of the form "foo.domain.tld"
        rule=hostFilters[action.host];
        action=handleProxyRule(rule, action, token);
      }else if ("*:"+action.port in hostFilters){//rule of the form "*:port"
        rule=hostFilters['*:'+action.port];
        action=handleProxyRule(rule, action, token);
      }else if ("*" in hostFilters){//default rule "*"
        rule=hostFilters['*'];
        action=handleProxyRule(rule, action, token);
      }
      return action;
  }
  
  function preventLoop(request, response){
    if(request.headers.proxy=="node.jtlebi"){//if request is already tooted => loop
      util.log("Loop detected");
      response.writeHead(500);
      response.write("Proxy loop !");
      response.end();
      return false;
    } else {//append a tattoo to it
      request.headers.proxy="node.jtlebi";
      return request;
    }
  }
  
  function actionAuthenticate(response, msg){
    response.writeHead(401,{
      'WWW-Authenticate': "Basic realm=\""+msg+"\""
    });
    response.end();
  }
  
  function actionDeny(response, msg) {
    response.writeHead(403);
    response.write(msg);
    response.end();
  }
  
  function actionNotFound(response, msg){
    response.writeHead(404);
    response.write(msg);
    response.end();
  }
  
  function actionRedirect(response, host){
    util.log("Redirecting to " + host);
    response.writeHead(301,{
      'Location': "http://"+host
    });
    response.end();
  }
  
  function actionProxy(response, request, host){
    util.log("Proxying to " + host);
    
    //detect HTTP version
    var legacyHttp = request.httpVersionMajor == 1 && request.httpVersionMinor < 1 || request.httpVersionMajor < 1;
      
    //launch new request + insert proxy specific header
    var headers = request.headers;
    if(config.addProxyHeader){
      if(headers['X-Forwarded-For'] !== undefined){
        headers['X-Forwarded-For'] = request.connection.remoteAddress + ", " + headers['X-Forwarded-For'];
      }
      else{ 
        headers['X-Forwarded-For'] = request.connection.remoteAddress;
      }
    }
    var proxyOptions = {
      method: request.method,
      host: action.host,
      port: action.port,
      path: request.url,
      headers: request.headers
    };
    var proxyRequest = http.request(proxyOptions);
    //var proxyRequest = proxy.request(request.method, request.url, request.headers);
    
    //deal with errors, timeout, con refused, ...
    proxyRequest.on('error', function(err) {
      util.log(err.toString() + " on request to " + host);
      return actionNotFound(response, "Requested resource ("+request.url+") is not accessible on host \""+host+"\"");
    });
    
    //proxies to FORWARD answer to real client
    proxyRequest.addListener('response', function(proxyResponse) {
      if(legacyHttp && proxyResponse.headers['transfer-encoding'] != undefined){
          console.log("legacy HTTP: "+request.httpVersion);
          
          //filter headers
          var headers = proxyResponse.headers;
          delete proxyResponse.headers['transfer-encoding'];        
          var buffer = "";
          
          //buffer answer
          proxyResponse.addListener('data', function(chunk) {
            buffer += chunk;
          });
          proxyResponse.addListener('end', function() {
            headers['Content-length'] = buffer.length;//cancel transfer encoding "chunked"
            response.writeHead(proxyResponse.statusCode, headers);
            response.write(buffer, 'binary');
            response.end();
          });
      } else {
          //send headers as received
          response.writeHead(proxyResponse.statusCode, proxyResponse.headers);
          
          //easy data forward
          proxyResponse.addListener('data', function(chunk) {
            response.write(chunk, 'binary');
          });
          proxyResponse.addListener('end', function() {
            response.end();
          });
      }
    });
  
    //proxies to SEND request to real server
    request.addListener('data', function(chunk) {
      proxyRequest.write(chunk, 'binary');
    });
    request.addListener('end', function() {
      proxyRequest.end();
    });
  }
  
  //special security logging function
  function securityLog(request, response, msg){
    var ip = request.connection.remoteAddress;
    msg = "**SECURITY VIOLATION**, "+ip+","+(request.method||"!NO METHOD!")+" "+(request.headers.host||"!NO HOST!")+"=>"+(request.url||"!NO URL!")+","+msg;
    
    util.log(msg);
  }
  
  //security filter
  // true if OK
  // false to return immediatlely
  function securityFilter(request, response){
    //HTTP 1.1 protocol violation: no host, no method, no url
    if(request.headers.host === undefined ||
       request.method === undefined ||
       request.url === undefined){
      securityLog(request, response, "Either host, method or url is poorly defined");
      return false;
    }
    return true;
  }
  
  //actual server loop
  function serverCallback(request, response) {
    //the *very* first action here is to handle security conditions
    //all related actions including logging are done by specialized functions
    //to ensure compartimentation
    if(!securityFilter(request, response)) return;
    
    
    var ip = request.connection.remoteAddress;
    if (!ipAllowed(ip)) {
      msg = "IP " + ip + " is not allowed to use this proxy";
      actionDeny(response, msg);
      securityLog(request, response, msg);    
      return;
    }
  
    if (!hostAllowed(request.url)) {
      msg = "Host " + request.url + " has been denied by proxy configuration";
      actionDeny(response, msg);
      securityLog(request, response, msg);    
      return;
    }
    
    //loop filter
    request = preventLoop(request, response);
    if(!request){return;}
    
    util.log(ip + ": " + request.method + " " + request.headers.host + "=>" + request.url);
    
    //get authorization token
    authorization = authenticate(request);
    
    //calc new host info
    var action = handleProxyRoute(request.headers.host, authorization);
    host = encodeHost(action);
    
    //handle action
    if(action.action == "redirect"){
      actionRedirect(response, host);
    }else if(action.action == "proxyto"){
      actionProxy(response, request, host);
    } else if(action.action == "authenticate"){
      actionAuthenticate(response, action.msg);
    }
  }
  
  //last chance error handler
  //it catch the exception preventing the application from crashing.
  //I recommend to comment it in a development environment as it
  //"Hides" very interesting bits of debugging informations.
  process.on('uncaughtException', function (err) {
    console.log('LAST ERROR: Caught exception: ' + err);
    util.log(err.stack);
  });
  
  if(!config.ssl) {
    console.log("HTTP Proxy Created");
    return http.createServer(serverCallback)
  } else {
    console.log("HTTPS Proxy Created");
    return https.createServer(config.ssl, serverCallback)
  }
}
