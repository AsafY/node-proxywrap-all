/*
 * node-proxywrap
 *
 * Copyright (c) 2013, Josh Dague
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*node-proxywrap-all
* by Asaf Yarkoni 2023
* https://github.com/AsafY/node-proxywrap-all
* */

const util = require('util');
const ppv2 = require('proxy-protocol-js').V2ProxyProtocol;

exports.defaults = {
	strict: true
};

// Wraps the given module (ie, http, https, net, tls, etc) interface so that
// `socket.remoteAddress` and `remotePort` work correctly when used with the
// PROXY protocol (http://haproxy.1wt.eu/download/1.5/doc/proxy-protocol.txt)
// strict option drops requests without proxy headers, enabled by default to match previous behavior, disable to allow both proxied and non-proxied requests
exports.proxy = function (iFace, options) {
	const exports = {};

	options = options || {};
	for (const k in module.exports.defaults) if (!(k in options)) options[k] = module.exports.defaults[k];

	// copy iFace's exports to myself
	for (const k in iFace) exports[k] = iFace[k];

	let _openSockets = 0;
	Object.defineProperty(exports, 'openSockets', {
		enumerable: false,
		configurable: true,
		get: function () {
			return _openSockets;
		}
	});

	function ProxiedServer(options, requestListener) {
		if (!(this instanceof ProxiedServer)) return new ProxiedServer(options, requestListener);

		if (typeof options == 'function') {
			requestListener = options;
			options = null;
		}

		// iFace.Server *requires* an arity of 1; iFaces.Server needs 2
		if (options) iFace.Server.call(this, options, requestListener);
		else iFace.Server.call(this, requestListener);

		// remove the connection listener attached by iFace[s].Server and replace it with our own.
		const cl = this.listeners('connection');
		this.removeAllListeners('connection');
		this.addListener('connection', connectionListener);

		// add the old connection listeners to a custom event, which we'll fire after processing the PROXY header
		for (let i = 0; i < cl.length; i++) {
			this.addListener('proxiedConnection', cl[i]);
		}

		_openSockets = 0;
	}

	util.inherits(ProxiedServer, iFace.Server);

	exports.createServer = function (opts, requestListener) {
		return new ProxiedServer(opts, requestListener);
	}

	exports.Server = ProxiedServer;


	function connectionListener(socket) {
		const self = this, realEmit = socket.emit;
		let history = [];

		_openSockets++;
		socket.on('close', () => {
			_openSockets--;
		});

		/**
		 * on node 18+ there is a default timout setting to prevent DOS attacks.
		 * since we hijack the socket events this setting only comes into effect after we return control over to the server.
		 * so if a client connects and doesn't send anything we are still exposed to malicious attacks.
		 * if data was already received then we should ignore the emitted timeout and let the calling server take care of it.
		 * @type {*|number}
		 */
		const timeOut = options.timeout || 5000;
		let _timeoutTimer = setTimeout(() => {
			if (!_timeoutTimer) return;// just a sanity check.
			socket.destroy();
			_openSockets--;
		}, timeOut);

		// override the socket's event emitter, so we can process data (and discard the PROXY protocol header) before the underlying Server gets it
		socket.emit = function (event, data) {
			history.push(Array.prototype.slice.call(arguments));
			if (event === 'readable') {
				onReadable();
			}
		}

		function restore() {
			// restore normal socket functionality, and fire any events that were emitted while we had control of emit()
			socket.emit = realEmit;
			for (let i = 0; i < history.length; i++) {
				realEmit.apply(socket, history[i]);
				if (history[i][0] === 'end' && socket.onend) socket.onend();
			}
			history = null;
		}


		socket.on('readable', onReadable);

		const v2Header = Buffer.from([13, 10, 13, 10, 0, 13, 10, 81, 85, 73, 84, 10]);
		let buf = new Buffer.from('');

		function onReadable() {
			let chunk, proxyVersion, connectionData, headerLength = 0;
			while (null != (chunk = socket.read())) {
				buf = Buffer.concat([buf, chunk]);

				if (!proxyVersion && buf.length >= 12 && (buf.subarray(0, 12).compare(v2Header) === 0)) {
					proxyVersion = 2;
					const upperLengthByte = buf[14];
					const lowerLengthByte = buf[15];
					headerLength = (upperLengthByte << 8) + lowerLengthByte + 16;
				} else if (!proxyVersion && buf.length >= 5 && buf.subarray(0, 5).toString('ascii') === 'PROXY') {
					proxyVersion = 1;
				} else if (buf.length >= 12) {
					proxyVersion = -1;
				} else {
					continue;// continue reading
				}

				if (proxyVersion === 2) {
					if (buf.length >= headerLength) {
						const proxyData = ppv2.parse(buf.subarray(0, headerLength));
						connectionData = {
							sourceAddress: (proxyData.proxyAddress?.sourceAddress?.address || [0, 0, 0, 0]).join('.'),
							sourcePort: proxyData.proxyAddress?.sourcePort
						}
					}
				} else if (proxyVersion === 1) {
					const crlf = buf.toString('ascii').indexOf('\r');
					if (crlf > 0) {
						headerLength = crlf + 2;
						const header = buf.subarray(0, headerLength).toString('ascii').split(' ');
						connectionData = {
							sourceAddress: header[2],
							sourcePort: parseInt(header[4], 10)
						}
					}
				}

				if (proxyVersion === -1 || connectionData) {
					if (options.debug) {
						console.log(`proxy version = ${proxyVersion}`);
						console.log(JSON.stringify(connectionData || {}));
						console.log(buf.subarray(headerLength, buf.length).toString('ascii'))
					}

					if (connectionData) {
						Object.defineProperty(socket, 'remoteAddress', {
							enumerable: false,
							configurable: true,
							get: function () {
								return connectionData.sourceAddress;
							}
						});

						Object.defineProperty(socket, 'remotePort', {
							enumerable: false,
							configurable: true,
							get: function () {
								return connectionData.sourcePort || 0;
							}
						});
					}

					socket.removeListener('readable', onReadable);
					// unshifting will fire the readable event
					restore();
					socket.unshift(buf.slice(headerLength));

					self.emit('proxiedConnection', socket);

					if (socket.ondata) {
						const data = socket.read();
						if (data) socket.ondata(data, 0, data.length);
					}

					break;
				}
			}

			clearTimeout(_timeoutTimer);//clear our timout timer.
			_timeoutTimer = null;
		}
	}

	return exports;
}
