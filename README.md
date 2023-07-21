node-proxywrap-all
==============

This module wraps node's various `Server` interfaces so that they are compatible with the [PROXY protocol](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt).  It automatically parses the PROXY headers and resets `socket.remoteAddress` and `socket.remotePort` so that they have the correct values.
supports V1, V2 proxy protocols and will also work when no header exists.
The module is based on the original "proxywrap"(https://github.com/daguej/node-proxywrap) project made by Josh Dague.
v2 parsing is done by using proxy-protocol-js by moznion.

    npm install node-proxywrap-all

This module is especially useful if you need to get the client IP address when you're behind an AWS ELB in TCP mode.

In HTTP or HTTPS mode (aka SSL termination at ELB or NLB), the ELB inserts `X-Forwarded-For` headers for you.  However, in TCP mode, the ELB can't understand the underlying protocol, so you lose the client's IP address.  With the PROXY protocol and this module, you're able to retain the client IP address with any protocol.

In order to receive the proxy header, you must [enable the PROXY protocol on your ELB](http://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/enable-proxy-protocol.html)/NLB (or whatever proxy your app is behind).

Usage
-----

node-proxywrap-all is a drop-in replacement.  Here's a simple Express app:

    var http = require('http')
        , proxiedHttp = require('node-proxywrap-all').proxy(http, {timeout: 5000})
        , express = require('express')
        , app = express()
        , srv = proxiedHttp.createServer(app); // instead of http.createServer(app)

    app.get('/', function(req, res) {
        res.send('IP = ' + req.connection.remoteAddress + ':' + req.connection.remotePort);
    });

    srv.listen(80);

The magic happens in the `proxywrap.proxy()` call.  It wraps the module's `Server` constructor and handles a bunch of messy details for you.

You can do the same with `net` (raw TCP streams), `https`, and `spdy`.  It will probably work with other modules that follow the same pattern, but none have been tested.

*Note*: If you're wrapping [node-spdy](https://github.com/indutny/node-spdy), its exports are a little strange:

    var proxiedSpdy = require('proxywrap').proxy(require('spdy').server);

API
---

### `proxy(Server[, options])`

Wraps something that inherits from the `net` module, exposing a `Server` and `createServer`.  Returns the same module patched to support the PROXY protocol.

Options:

- `debug` (default `false`): will print parsing debug info to console.
- `timeout` (default 5000) prevent DOS attacks and bad clients not
              closing sockets properly. 
              this is mainly used for node servers connected directly through NLB's.
