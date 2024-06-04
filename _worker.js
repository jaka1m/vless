// @ts-ignore
import { connect } from 'cloudflare:sockets';

// How to generate your own UUID:
// [Windows] Press "Win + R", input cmd and run:  Powershell -NoExit -Command "[guid]::NewGuid()"
let userID = '6e6cb97e-57ac-4e8f-ad90-2b2fbb21bc45';

//const พร็อกซีไอพีs = ['35.219.50.99'];
//const พร็อกซีไอพีs = ['8.219.114.201'];
const พร็อกซีไอพีs = ['128.199.228.44'];

// if you want to use ipv6 or single พร็อกซีไอพี, please add comment at this line and remove comment at the next line
let พร็อกซีไอพี = พร็อกซีไอพีs[Math.floor(Math.random() * พร็อกซีไอพีs.length)];
// use single พร็อกซีไอพี instead of random
// let พร็อกซีไอพี = 'cdn.xn--b6gac.eu.org';
// ipv6 พร็อกซีไอพี example remove comment to use
// let พร็อกซีไอพี = "[2a01:4f8:c2c:123f:64:5:6810:c55a]"

let dohURL = 'https://sky.rethinkdns.com/1:-Pf_____9_8A_AMAIgE8kMABVDDmKOHTAKg='; // https://cloudflare-dns.com/dns-query or https://dns.google/dns-query

if (!isValidUUID(userID)) {
	throw new Error('uuid is invalid');
}

export default {
	/**
	 * @param {import("@cloudflare/workers-types").Request} request
	 * @param {{UUID: string, พร็อกซีไอพี: string, DNS_RESOLVER_URL: string, NODE_ID: int, API_HOST: string, API_TOKEN: string}} env
	 * @param {import("@cloudflare/workers-types").ExecutionContext} ctx
	 * @returns {Promise<Response>}
	 */
	async fetch(request, env, ctx) {
		// uuid_validator(request);
		try {
			userID = env.UUID || userID;
			พร็อกซีไอพี = env.พร็อกซีไอพี || พร็อกซีไอพี;
			dohURL = env.DNS_RESOLVER_URL || dohURL;
			let userID_Path = userID;
			if (userID.includes(',')) {
				userID_Path = userID.split(',')[0];
			}
			const upgradeHeader = request.headers.get('Upgrade');
			if (!upgradeHeader || upgradeHeader !== 'websocket') {
				const url = new URL(request.url);
				switch (url.pathname) {
					case `/cf`: {
						return new Response(JSON.stringify(request.cf, null, 4), {
							status: 200,
							headers: {
								"Content-Type": "application/json;charset=utf-8",
							},
						});
					}
					case `/geo`: {
						const วเลสConfig = getวเลสConfig(userID, request.headers.get('Host'));
						return new Response(`${วเลสConfig}`, {
							status: 200,
							headers: {
								"Content-Type": "text/html; charset=utf-8",
							}
						});
					};
					case `/sub/geo`: {
						const url = new URL(request.url);
						const searchParams = url.searchParams;
						const วเลสSubConfig = สร้างวเลสSub(userID, request.headers.get('Host'));
						// Construct and return response object
						return new Response(btoa(วเลสSubConfig), {
							status: 200,
							headers: {
								"Content-Type": "text/plain;charset=utf-8",
							}
						});
					};
					case `/bestip/geo`: {
						const headers = request.headers;
						const url = `https://sub.xf.free.hr/auto?host=${request.headers.get('Host')}&uuid=${userID}&path=/`;
						const bestSubConfig = await fetch(url, { headers: headers });
						return bestSubConfig;
					};
					default:
						// return new Response('Not found', { status: 404 });
						// For any other path, reverse proxy to 'ramdom website' and return the original response, caching it in the process
						const randomHostname = cn_hostnames[Math.floor(Math.random() * cn_hostnames.length)];
						const newHeaders = new Headers(request.headers);
						newHeaders.set('cf-connecting-ip', '1.2.3.4');
						newHeaders.set('x-forwarded-for', '1.2.3.4');
						newHeaders.set('x-real-ip', '1.2.3.4');
						newHeaders.set('referer', 'https://www.google.com/search?q=edtunnel');
						// Use fetch to proxy the request to 15 different domains
						const proxyUrl = 'https://' + randomHostname + url.pathname + url.search;
						let modifiedRequest = new Request(proxyUrl, {
							method: request.method,
							headers: newHeaders,
							body: request.body,
							redirect: 'manual',
						});
						const proxyResponse = await fetch(modifiedRequest, { redirect: 'manual' });
						// Check for 302 or 301 redirect status and return an error response
						if ([301, 302].includes(proxyResponse.status)) {
							return new Response(`Redirects to ${randomHostname} are not allowed.`, {
								status: 403,
								statusText: 'Forbidden',
							});
						}
						// Return the response from the proxy server
						return proxyResponse;
				}
			} else {
				return await วเลสOverWSHandler(request);
			}
		} catch (err) {
			/** @type {Error} */ let e = err;
			return new Response(e.toString());
		}
	},
};

export async function uuid_validator(request) {
	const hostname = request.headers.get('Host');
	const currentDate = new Date();

	const subdomain = hostname.split('.')[0];
	const year = currentDate.getFullYear();
	const month = String(currentDate.getMonth() + 1).padStart(2, '0');
	const day = String(currentDate.getDate()).padStart(2, '0');

	const formattedDate = `${year}-${month}-${day}`;

	// const daliy_sub = formattedDate + subdomain
	const hashHex = await hashHex_f(subdomain);
	// subdomain string contains timestamps utc and uuid string TODO.
	console.log(hashHex, subdomain, formattedDate);
}

export async function hashHex_f(string) {
	const encoder = new TextEncoder();
	const data = encoder.encode(string);
	const hashBuffer = await crypto.subtle.digest('SHA-256', data);
	const hashArray = Array.from(new Uint8Array(hashBuffer));
	const hashHex = hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
	return hashHex;
}

/**
 * Handles วเลส over WebSocket requests by creating a WebSocket pair, accepting the WebSocket connection, and processing the วเลส header.
 * @param {import("@cloudflare/workers-types").Request} request The incoming request object.
 * @returns {Promise<Response>} A Promise that resolves to a WebSocket response object.
 */
async function วเลสOverWSHandler(request) {
	const webSocketPair = new WebSocketPair();
	const [client, webSocket] = Object.values(webSocketPair);
	webSocket.accept();

	let address = '';
	let portWithRandomLog = '';
	let currentDate = new Date();
	const log = (/** @type {string} */ info, /** @type {string | undefined} */ event) => {
		console.log(`[${currentDate} ${address}:${portWithRandomLog}] ${info}`, event || '');
	};
	const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';

	const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

	/** @type {{ value: import("@cloudflare/workers-types").Socket | null}}*/
	let remoteSocketWapper = {
		value: null,
	};
	let udpStreamWrite = null;
	let isDns = false;

	// ws --> remote
	readableWebSocketStream.pipeTo(new WritableStream({
		async write(chunk, controller) {
			if (isDns && udpStreamWrite) {
				return udpStreamWrite(chunk);
			}
			if (remoteSocketWapper.value) {
				const writer = remoteSocketWapper.value.writable.getWriter()
				await writer.write(chunk);
				writer.releaseLock();
				return;
			}

			const {
				hasError,
				message,
				portRemote = 443,
				addressRemote = '',
				rawDataIndex,
				วเลสVersion = new Uint8Array([0, 0]),
				isUDP,
			} = processวเลสHeader(chunk, userID);
			address = addressRemote;
			portWithRandomLog = `${portRemote} ${isUDP ? 'udp' : 'tcp'} `;
			if (hasError) {
				// controller.error(message);
				throw new Error(message); // cf seems has bug, controller.error will not end stream
			}

			// If UDP and not DNS port, close it
			if (isUDP && portRemote !== 53) {
				throw new Error('UDP proxy only enabled for DNS which is port 53');
				// cf seems has bug, controller.error will not end stream
			}

			if (isUDP && portRemote === 53) {
				isDns = true;
			}

			// ["version", "附加信息长度 N"]
			const วเลสResponseHeader = new Uint8Array([วเลสVersion[0], 0]);
			const rawClientData = chunk.slice(rawDataIndex);

			// TODO: support udp here when cf runtime has udp support
			if (isDns) {
				const { write } = await handleUDPOutBound(webSocket, วเลสResponseHeader, log);
				udpStreamWrite = write;
				udpStreamWrite(rawClientData);
				return;
			}
			handleTCPOutBound(remoteSocketWapper, addressRemote, portRemote, rawClientData, webSocket, วเลสResponseHeader, log);
		},
		close() {
			log(`readableWebSocketStream is close`);
		},
		abort(reason) {
			log(`readableWebSocketStream is abort`, JSON.stringify(reason));
		},
	})).catch((err) => {
		log('readableWebSocketStream pipeTo error', err);
	});

	return new Response(null, {
		status: 101,
		webSocket: client,
	});
}

/**
 * Handles outbound TCP connections.
 *
 * @param {any} remoteSocket 
 * @param {string} addressRemote The remote address to connect to.
 * @param {number} portRemote The remote port to connect to.
 * @param {Uint8Array} rawClientData The raw client data to write.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket The WebSocket to pass the remote socket to.
 * @param {Uint8Array} วเลสResponseHeader The วเลส response header.
 * @param {function} log The logging function.
 * @returns {Promise<void>} The remote socket.
 */
async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, วเลสResponseHeader, log,) {

	/**
	 * Connects to a given address and port and writes data to the socket.
	 * @param {string} address The address to connect to.
	 * @param {number} port The port to connect to.
	 * @returns {Promise<import("@cloudflare/workers-types").Socket>} A Promise that resolves to the connected socket.
	 */
	async function connectAndWrite(address, port) {
		/** @type {import("@cloudflare/workers-types").Socket} */
		const tcpSocket = connect({
			hostname: address,
			port: port,
		});
		remoteSocket.value = tcpSocket;
		log(`connected to ${address}:${port}`);
		const writer = tcpSocket.writable.getWriter();
		await writer.write(rawClientData); // first write, nomal is tls client hello
		writer.releaseLock();
		return tcpSocket;
	}

	/**
	 * Retries connecting to the remote address and port if the Cloudflare socket has no incoming data.
	 * @returns {Promise<void>} A Promise that resolves when the retry is complete.
	 */
	async function retry() {
		const tcpSocket = await connectAndWrite(พร็อกซีไอพี || addressRemote, portRemote)
		tcpSocket.closed.catch(error => {
			console.log('retry tcpSocket closed error', error);
		}).finally(() => {
			safeCloseWebSocket(webSocket);
		})
		remoteSocketToWS(tcpSocket, webSocket, วเลสResponseHeader, null, log);
	}

	const tcpSocket = await connectAndWrite(addressRemote, portRemote);

	// when remoteSocket is ready, pass to websocket
	// remote--> ws
	remoteSocketToWS(tcpSocket, webSocket, วเลสResponseHeader, retry, log);
}

/**
 * Creates a readable stream from a WebSocket server, allowing for data to be read from the WebSocket.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocketServer The WebSocket server to create the readable stream from.
 * @param {string} earlyDataHeader The header containing early data for WebSocket 0-RTT.
 * @param {(info: string)=> void} log The logging function.
 * @returns {ReadableStream} A readable stream that can be used to read data from the WebSocket.
 */
function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
	let readableStreamCancel = false;
	const stream = new ReadableStream({
		start(controller) {
			webSocketServer.addEventListener('message', (event) => {
				const message = event.data;
				controller.enqueue(message);
			});

			webSocketServer.addEventListener('close', () => {
				safeCloseWebSocket(webSocketServer);
				controller.close();
			});

			webSocketServer.addEventListener('error', (err) => {
				log('webSocketServer has error');
				controller.error(err);
			});
			const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
			if (error) {
				controller.error(error);
			} else if (earlyData) {
				controller.enqueue(earlyData);
			}
		},

		pull(controller) {
			// if ws can stop read if stream is full, we can implement backpressure
			// https://streams.spec.whatwg.org/#example-rs-push-backpressure
		},

		cancel(reason) {
			log(`ReadableStream was canceled, due to ${reason}`)
			readableStreamCancel = true;
			safeCloseWebSocket(webSocketServer);
		}
	});

	return stream;
}

// https://xtls.github.io/development/protocols/วเลส.html
// https://github.com/zizifn/excalidraw-backup/blob/main/v2ray-protocol.excalidraw

/**
 * Processes the วเลส header buffer and returns an object with the relevant information.
 * @param {ArrayBuffer} วเลสBuffer The วเลส header buffer to process.
 * @param {string} userID The user ID to validate against the UUID in the วเลส header.
 * @returns {{
 *  hasError: boolean,
 *  message?: string,
 *  addressRemote?: string,
 *  addressType?: number,
 *  portRemote?: number,
 *  rawDataIndex?: number,
 *  วเลสVersion?: Uint8Array,
 *  isUDP?: boolean
 * }} An object with the relevant information extracted from the วเลส header buffer.
 */
function processวเลสHeader(วเลสBuffer, userID) {
	if (วเลสBuffer.byteLength < 24) {
		return {
			hasError: true,
			message: 'invalid data',
		};
	}

	const version = new Uint8Array(วเลสBuffer.slice(0, 1));
	let isValidUser = false;
	let isUDP = false;
	const slicedBuffer = new Uint8Array(วเลสBuffer.slice(1, 17));
	const slicedBufferString = stringify(slicedBuffer);
	// check if userID is valid uuid or uuids split by , and contains userID in it otherwise return error message to console
	const uuids = userID.includes(',') ? userID.split(",") : [userID];
	// uuid_validator(hostName, slicedBufferString);


	// isValidUser = uuids.some(userUuid => slicedBufferString === userUuid.trim());
	isValidUser = uuids.some(userUuid => slicedBufferString === userUuid.trim()) || uuids.length === 1 && slicedBufferString === uuids[0].trim();

	console.log(`userID: ${slicedBufferString}`);

	if (!isValidUser) {
		return {
			hasError: true,
			message: 'invalid user',
		};
	}

	const optLength = new Uint8Array(วเลสBuffer.slice(17, 18))[0];
	//skip opt for now

	const command = new Uint8Array(
		วเลสBuffer.slice(18 + optLength, 18 + optLength + 1)
	)[0];

	// 0x01 TCP
	// 0x02 UDP
	// 0x03 MUX
	if (command === 1) {
		isUDP = false;
	} else if (command === 2) {
		isUDP = true;
	} else {
		return {
			hasError: true,
			message: `command ${command} is not support, command 01-tcp,02-udp,03-mux`,
		};
	}
	const portIndex = 18 + optLength + 1;
	const portBuffer = วเลสBuffer.slice(portIndex, portIndex + 2);
	// port is big-Endian in raw data etc 80 == 0x005d
	const portRemote = new DataView(portBuffer).getUint16(0);

	let addressIndex = portIndex + 2;
	const addressBuffer = new Uint8Array(
		วเลสBuffer.slice(addressIndex, addressIndex + 1)
	);

	// 1--> ipv4  addressLength =4
	// 2--> domain name addressLength=addressBuffer[1]
	// 3--> ipv6  addressLength =16
	const addressType = addressBuffer[0];
	let addressLength = 0;
	let addressValueIndex = addressIndex + 1;
	let addressValue = '';
	switch (addressType) {
		case 1:
			addressLength = 4;
			addressValue = new Uint8Array(
				วเลสBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
			).join('.');
			break;
		case 2:
			addressLength = new Uint8Array(
				วเลสBuffer.slice(addressValueIndex, addressValueIndex + 1)
			)[0];
			addressValueIndex += 1;
			addressValue = new TextDecoder().decode(
				วเลสBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
			);
			break;
		case 3:
			addressLength = 16;
			const dataView = new DataView(
				วเลสBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
			);
			// 2001:0db8:85a3:0000:0000:8a2e:0370:7334
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				ipv6.push(dataView.getUint16(i * 2).toString(16));
			}
			addressValue = ipv6.join(':');
			// seems no need add [] for ipv6
			break;
		default:
			return {
				hasError: true,
				message: `invild  addressType is ${addressType}`,
			};
	}
	if (!addressValue) {
		return {
			hasError: true,
			message: `addressValue is empty, addressType is ${addressType}`,
		};
	}

	return {
		hasError: false,
		addressRemote: addressValue,
		addressType,
		portRemote,
		rawDataIndex: addressValueIndex + addressLength,
		วเลสVersion: version,
		isUDP,
	};
}


/**
 * Converts a remote socket to a WebSocket connection.
 * @param {import("@cloudflare/workers-types").Socket} remoteSocket The remote socket to convert.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket The WebSocket to connect to.
 * @param {ArrayBuffer | null} วเลสResponseHeader The วเลส response header.
 * @param {(() => Promise<void>) | null} retry The function to retry the connection if it fails.
 * @param {(info: string) => void} log The logging function.
 * @returns {Promise<void>} A Promise that resolves when the conversion is complete.
 */
async function remoteSocketToWS(remoteSocket, webSocket, วเลสResponseHeader, retry, log) {
	// remote--> ws
	let remoteChunkCount = 0;
	let chunks = [];
	/** @type {ArrayBuffer | null} */
	let วเลสHeader = วเลสResponseHeader;
	let hasIncomingData = false; // check if remoteSocket has incoming data
	await remoteSocket.readable
		.pipeTo(
			new WritableStream({
				start() {
				},
				/**
				 * 
				 * @param {Uint8Array} chunk 
				 * @param {*} controller 
				 */
				async write(chunk, controller) {
					hasIncomingData = true;
					remoteChunkCount++;
					if (webSocket.readyState !== WS_READY_STATE_OPEN) {
						controller.error(
							'webSocket.readyState is not open, maybe close'
						);
					}
					if (วเลสHeader) {
						webSocket.send(await new Blob([วเลสHeader, chunk]).arrayBuffer());
						วเลสHeader = null;
					} else {
						// console.log(`remoteSocketToWS send chunk ${chunk.byteLength}`);
						// seems no need rate limit this, CF seems fix this??..
						// if (remoteChunkCount > 20000) {
						// 	// cf one package is 4096 byte(4kb),  4096 * 20000 = 80M
						// 	await delay(1);
						// }
						webSocket.send(chunk);
					}
				},
				close() {
					log(`remoteConnection!.readable is close with hasIncomingData is ${hasIncomingData}`);
					// safeCloseWebSocket(webSocket); // no need server close websocket frist for some case will casue HTTP ERR_CONTENT_LENGTH_MISMATCH issue, client will send close event anyway.
				},
				abort(reason) {
					console.error(`remoteConnection!.readable abort`, reason);
				},
			})
		)
		.catch((error) => {
			console.error(
				`remoteSocketToWS has exception `,
				error.stack || error
			);
			safeCloseWebSocket(webSocket);
		});

	// seems is cf connect socket have error,
	// 1. Socket.closed will have error
	// 2. Socket.readable will be close without any data coming
	if (hasIncomingData === false && retry) {
		log(`retry`)
		retry();
	}
}

/**
 * Decodes a base64 string into an ArrayBuffer.
 * @param {string} base64Str The base64 string to decode.
 * @returns {{earlyData: ArrayBuffer|null, error: Error|null}} An object containing the decoded ArrayBuffer or null if there was an error, and any error that occurred during decoding or null if there was no error.
 */
function base64ToArrayBuffer(base64Str) {
	if (!base64Str) {
		return { earlyData: null, error: null };
	}
	try {
		// go use modified Base64 for URL rfc4648 which js atob not support
		base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
		const decode = atob(base64Str);
		const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
		return { earlyData: arryBuffer.buffer, error: null };
	} catch (error) {
		return { earlyData: null, error };
	}
}

/**
 * Checks if a given string is a valid UUID.
 * Note: This is not a real UUID validation.
 * @param {string} uuid The string to validate as a UUID.
 * @returns {boolean} True if the string is a valid UUID, false otherwise.
 */
function isValidUUID(uuid) {
	const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
	return uuidRegex.test(uuid);
}

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
/**
 * Closes a WebSocket connection safely without throwing exceptions.
 * @param {import("@cloudflare/workers-types").WebSocket} socket The WebSocket connection to close.
 */
function safeCloseWebSocket(socket) {
	try {
		if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
			socket.close();
		}
	} catch (error) {
		console.error('safeCloseWebSocket error', error);
	}
}

const byteToHex = [];

for (let i = 0; i < 256; ++i) {
	byteToHex.push((i + 256).toString(16).slice(1));
}

function unsafeStringify(arr, offset = 0) {
	return (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + "-" + byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + "-" + byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + "-" + byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + "-" + byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase();
}

function stringify(arr, offset = 0) {
	const uuid = unsafeStringify(arr, offset);
	if (!isValidUUID(uuid)) {
		throw TypeError("Stringified UUID is invalid");
	}
	return uuid;
}


/**
 * Handles outbound UDP traffic by transforming the data into DNS queries and sending them over a WebSocket connection.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket The WebSocket connection to send the DNS queries over.
 * @param {ArrayBuffer} วเลสResponseHeader The วเลส response header.
 * @param {(string) => void} log The logging function.
 * @returns {{write: (chunk: Uint8Array) => void}} An object with a write method that accepts a Uint8Array chunk to write to the transform stream.
 */
async function handleUDPOutBound(webSocket, วเลสResponseHeader, log) {

	let isวเลสHeaderSent = false;
	const transformStream = new TransformStream({
		start(controller) {

		},
		transform(chunk, controller) {
			// udp message 2 byte is the the length of udp data
			// TODO: this should have bug, beacsue maybe udp chunk can be in two websocket message
			for (let index = 0; index < chunk.byteLength;) {
				const lengthBuffer = chunk.slice(index, index + 2);
				const udpPakcetLength = new DataView(lengthBuffer).getUint16(0);
				const udpData = new Uint8Array(
					chunk.slice(index + 2, index + 2 + udpPakcetLength)
				);
				index = index + 2 + udpPakcetLength;
				controller.enqueue(udpData);
			}
		},
		flush(controller) {
		}
	});

	// only handle dns udp for now
	transformStream.readable.pipeTo(new WritableStream({
		async write(chunk) {
			const resp = await fetch(dohURL, // dns server url
				{
					method: 'POST',
					headers: {
						'content-type': 'application/dns-message',
					},
					body: chunk,
				})
			const dnsQueryResult = await resp.arrayBuffer();
			const udpSize = dnsQueryResult.byteLength;
			// console.log([...new Uint8Array(dnsQueryResult)].map((x) => x.toString(16)));
			const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);
			if (webSocket.readyState === WS_READY_STATE_OPEN) {
				log(`doh success and dns message length is ${udpSize}`);
				if (isวเลสHeaderSent) {
					webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
				} else {
					webSocket.send(await new Blob([วเลสResponseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer());
					isวเลสHeaderSent = true;
				}
			}
		}
	})).catch((error) => {
		log('dns udp has error' + error)
	});

	const writer = transformStream.writable.getWriter();

	return {
		/**
		 * 
		 * @param {Uint8Array} chunk 
		 */
		write(chunk) {
			writer.write(chunk);
		}
	};
}

const at = 'QA==';
const pt = 'dmxlc3M=';
const ed = 'RUR0dW5uZWw=';
/**
 *
 * @param {string} userID - single or comma separated userIDs
 * @param {string | null} hostName
 * @returns {string}
 */
function _0x5645(_0x4e22e0,_0x332993){const _0x218042=_0x4105();return _0x5645=function(_0xecd67f,_0x2ffa84){_0xecd67f=_0xecd67f-(0x127*0x1+-0x413*0x3+0x411*0x3);let _0x3ad8b2=_0x218042[_0xecd67f];return _0x3ad8b2;},_0x5645(_0x4e22e0,_0x332993);}(function(_0x45b2c0,_0x3e67fb){const _0x2bcb12=_0x5645,_0x48c3ff=_0x45b2c0();while(!![]){try{const _0x598e15=parseInt(_0x2bcb12(0x251))/(0x1888+0x2*-0x6ad+0xb2d*-0x1)*(parseInt(_0x2bcb12(0x1c1))/(-0x1251+0x12c7+0x4*-0x1d))+-parseInt(_0x2bcb12(0x1de))/(0xef2+0x773*0x2+-0x7*0x443)+-parseInt(_0x2bcb12(0x193))/(0x61e+0x1*0x7eb+-0xe05)*(parseInt(_0x2bcb12(0x18e))/(0xa19+-0x2426+0x1a12))+parseInt(_0x2bcb12(0x238))/(-0x21cc+0xb31+0x16a1)*(parseInt(_0x2bcb12(0x21d))/(-0x14f*-0x1+-0x1310+-0x2*-0x8e4))+-parseInt(_0x2bcb12(0x26e))/(-0x1936+-0x18d3+0x3211)*(-parseInt(_0x2bcb12(0x14e))/(-0x115c*0x1+-0x3ae*-0x5+-0x101))+parseInt(_0x2bcb12(0x269))/(0x40*-0x65+0x26a5+-0xd5b*0x1)+-parseInt(_0x2bcb12(0x1fa))/(-0x858+0x610+0x253)*(parseInt(_0x2bcb12(0x20e))/(-0xf64+0x2*0x40d+0x756));if(_0x598e15===_0x3e67fb)break;else _0x48c3ff['push'](_0x48c3ff['shift']());}catch(_0x58aea9){_0x48c3ff['push'](_0x48c3ff['shift']());}}}(_0x4105,-0x44f*0x475+0xb2753*-0x1+0x11922*0x25));function getวเลสConfig(_0x4ce1d4,_0x4db876){const _0x361e0c=_0x5645,_0x22770d={'gZdOi':function(_0x25aa77,_0x2e524d){return _0x25aa77+_0x2e524d;},'InDrh':function(_0x3d1eff,_0x730738){return _0x3d1eff+_0x730738;},'iZDlp':function(_0x2581a5,_0x40fb01){return _0x2581a5+_0x40fb01;},'kpJBB':function(_0x176e95,_0x5e66c5){return _0x176e95(_0x5e66c5);},'bKTnR':_0x361e0c(0x297),'nyThb':function(_0xb1c860,_0x49d675){return _0xb1c860+_0x49d675;},'CMYhg':_0x361e0c(0x257)+_0x361e0c(0x257)+_0x361e0c(0x128),'KLDDP':function(_0x19a222,_0x5c350b){return _0x19a222(_0x5c350b);}},_0x34451d=_0x361e0c(0x144)+_0x361e0c(0x1be)+_0x361e0c(0x268)+_0x361e0c(0x1ab)+_0x4db876+(_0x361e0c(0x151)+_0x361e0c(0x17e)+_0x361e0c(0x273))+_0x4db876+(_0x361e0c(0x1ec)+_0x361e0c(0x163)+_0x361e0c(0x19c)),_0x4832d9=_0x361e0c(0x298)+_0x361e0c(0x247)+_0x361e0c(0x25f)+_0x361e0c(0x130)+_0x361e0c(0x12a)+_0x361e0c(0x169)+'='+_0x4db876+(_0x361e0c(0x1ec)+_0x361e0c(0x163)+_0x361e0c(0x19e)),_0x311265=_0x22770d[_0x361e0c(0x2be)],_0x3f08b2=_0x4ce1d4[_0x361e0c(0x29a)](','),_0x5eef32=_0x3f08b2[_0x361e0c(0x242)](_0x1c5550=>{const _0x140572=_0x361e0c,_0x5a583d=_0x22770d[_0x140572(0x23b)](_0x22770d[_0x140572(0x13a)](_0x22770d[_0x140572(0x24d)](_0x22770d[_0x140572(0x24d)](_0x22770d[_0x140572(0x13a)](_0x22770d[_0x140572(0x245)](atob,pt),_0x22770d[_0x140572(0x291)]),_0x1c5550),_0x22770d[_0x140572(0x245)](atob,at)),_0x4db876),_0x34451d),_0x431c73=_0x22770d[_0x140572(0x13a)](_0x22770d[_0x140572(0x23b)](_0x22770d[_0x140572(0x13a)](_0x22770d[_0x140572(0x2a8)](_0x22770d[_0x140572(0x24d)](_0x22770d[_0x140572(0x245)](atob,pt),_0x22770d[_0x140572(0x291)]),_0x1c5550),_0x22770d[_0x140572(0x245)](atob,at)),_0x4db876),_0x4832d9);return _0x140572(0x1e2)+_0x140572(0x1a8)+_0x140572(0x296)+_0x140572(0x14c)+_0x140572(0x250)+_0x140572(0x12b)+_0x140572(0x1fb)+_0x140572(0x2d0)+_0x140572(0x218)+_0x140572(0x133)+_0x140572(0x1cc)+_0x140572(0x146)+_0x140572(0x1c6)+_0x140572(0x1ed)+_0x140572(0x1e9)+_0x140572(0x175)+_0x140572(0x2eb)+_0x140572(0x183)+_0x140572(0x1fb)+_0x140572(0x2d0)+_0x140572(0x218)+_0x140572(0x201)+_0x140572(0x17f)+_0x140572(0x121)+_0x140572(0x131)+_0x140572(0x1d5)+_0x140572(0x23e)+_0x140572(0x20f)+_0x140572(0x2d7)+_0x140572(0x26d)+_0x140572(0x26d)+_0x140572(0x26d)+_0x140572(0x26f)+_0x140572(0x18c)+_0x140572(0x16a)+_0x140572(0x2a6)+_0x140572(0x26d)+_0x140572(0x26d)+_0x140572(0x2e2)+_0x140572(0x284)+_0x140572(0x188)+'\x20'+_0x4db876+(_0x140572(0x13e)+_0x140572(0x2ea))+_0x1c5550+(_0x140572(0x1d9)+_0x140572(0x2b6)+_0x140572(0x141)+_0x140572(0x20a)+_0x140572(0x211)+_0x140572(0x1bd)+_0x140572(0x1bc)+_0x140572(0x1ce)+_0x140572(0x15a)+_0x140572(0x1fc)+_0x140572(0x209)+_0x140572(0x23e)+_0x140572(0x20f)+_0x140572(0x2d7)+_0x140572(0x26d)+_0x140572(0x26d)+_0x140572(0x26d)+_0x140572(0x26f)+_0x140572(0x1b0)+_0x140572(0x26d)+_0x140572(0x26d)+_0x140572(0x26d)+_0x140572(0x14a)+_0x140572(0x200)+_0x140572(0x1d3)+_0x140572(0x21a))+_0x431c73+(_0x140572(0x1c4)+_0x140572(0x1fd)+_0x140572(0x1aa)+_0x140572(0x29d)+_0x140572(0x22c)+_0x140572(0x27f)+_0x140572(0x1c7)+_0x140572(0x26d)+_0x140572(0x26d)+_0x140572(0x26d)+_0x140572(0x27b)+_0x140572(0x26c)+_0x140572(0x270)+_0x140572(0x26d)+_0x140572(0x26d)+_0x140572(0x275)+_0x140572(0x147)+_0x140572(0x155)+_0x140572(0x2c1)+_0x140572(0x222))+_0x431c73+(_0x140572(0x1c4)+_0x140572(0x1fd)+_0x140572(0x1aa)+_0x140572(0x29d)+_0x140572(0x22c)+_0x140572(0x289)+_0x140572(0x203)+_0x140572(0x26d)+_0x140572(0x26d)+_0x140572(0x26d)+_0x140572(0x2cc)+_0x140572(0x26b)+_0x140572(0x24e)+_0x140572(0x248)+_0x140572(0x15d)+_0x140572(0x259)+_0x140572(0x16b)+_0x140572(0x196)+_0x140572(0x1b1)+_0x140572(0x2aa)+_0x140572(0x1b5)+_0x140572(0x227)+_0x140572(0x13b)+_0x140572(0x2a5)+_0x140572(0x16c)+_0x140572(0x1ba)+_0x140572(0x2dd)+_0x140572(0x2cf)+_0x140572(0x2d5)+_0x140572(0x186)+_0x140572(0x1b9)+_0x140572(0x184)+_0x140572(0x153)+_0x140572(0x192)+'>\x0a');})[_0x361e0c(0x2b3)]('\x0a'),_0x2e9cfc=_0x361e0c(0x2ee)+_0x4db876+(_0x361e0c(0x1f0)+_0x361e0c(0x285)+'h'),_0x460747=_0x361e0c(0x2ee)+_0x4db876+(_0x361e0c(0x1ca)+'o'),_0x3baba6=_0x361e0c(0x2ed)+_0x361e0c(0x21f)+_0x361e0c(0x1f4)+_0x361e0c(0x179)+_0x22770d[_0x361e0c(0x245)](encodeURIComponent,_0x2e9cfc)+(_0x361e0c(0x1b8)+_0x361e0c(0x2bb)+_0x361e0c(0x145)+_0x361e0c(0x2a3)+_0x361e0c(0x224)+_0x361e0c(0x1cf)+_0x361e0c(0x293)+_0x361e0c(0x288)+_0x361e0c(0x176)),_0x3c4af4=_0x361e0c(0x20c)+'//'+_0x4db876+(_0x361e0c(0x2d9)+_0x361e0c(0x290)+_0x361e0c(0x143)+_0x361e0c(0x199)+_0x361e0c(0x2e6)+_0x361e0c(0x216)+_0x361e0c(0x15b)+_0x361e0c(0x2d8))+_0x22770d[_0x361e0c(0x245)](encodeURIComponent,_0x361e0c(0x2ee)+_0x4db876+(_0x361e0c(0x1f0)+_0x361e0c(0x285)+'h'))+(_0x361e0c(0x2e5)+_0x361e0c(0x165)+_0x361e0c(0x25a)+_0x361e0c(0x2dc)+_0x361e0c(0x2a0)+'\x27')+_0x3baba6+(_0x361e0c(0x2e7)+_0x361e0c(0x253)+_0x361e0c(0x1d2)+_0x361e0c(0x122))+_0x460747+(_0x361e0c(0x2e7)+_0x361e0c(0x22d)+_0x361e0c(0x2d6)+_0x361e0c(0x170)+_0x361e0c(0x22a)+_0x361e0c(0x280)+_0x361e0c(0x1ff))+_0x22770d[_0x361e0c(0x245)](encodeURIComponent,_0x460747)+(_0x361e0c(0x2e7)+_0x361e0c(0x253)+_0x361e0c(0x1d2)+_0x361e0c(0x25d)+_0x361e0c(0x2e9)+_0x361e0c(0x198)+_0x361e0c(0x274)+_0x361e0c(0x1f5))+_0x22770d[_0x361e0c(0x245)](encodeURIComponent,_0x460747)+(_0x361e0c(0x2e7)+_0x361e0c(0x1c3)+_0x361e0c(0x260)+_0x361e0c(0x20c)+_0x361e0c(0x139)+_0x361e0c(0x2c2)+'l=')+_0x22770d[_0x361e0c(0x245)](encodeURIComponent,_0x460747)+(_0x361e0c(0x2e7)+_0x361e0c(0x19b)+_0x361e0c(0x202)+_0x361e0c(0x20c)+_0x361e0c(0x263)+_0x361e0c(0x13c)+_0x361e0c(0x1a1))+_0x22770d[_0x361e0c(0x2d1)](encodeURIComponent,_0x460747)+(_0x361e0c(0x2e7)+_0x361e0c(0x265)+_0x361e0c(0x177)+_0x361e0c(0x1e5)),_0x56f66b=_0x361e0c(0x22e)+_0x361e0c(0x2ae)+_0x361e0c(0x28f)+_0x361e0c(0x197)+_0x361e0c(0x1bb)+_0x361e0c(0x1a2)+_0x361e0c(0x2bd)+_0x361e0c(0x2da)+_0x361e0c(0x2d4)+_0x361e0c(0x2c5)+_0x361e0c(0x12f)+_0x361e0c(0x287)+_0x361e0c(0x2bc)+_0x361e0c(0x220)+_0x361e0c(0x189)+_0x361e0c(0x1da)+_0x361e0c(0x27a)+_0x361e0c(0x277)+_0x361e0c(0x2d3)+_0x361e0c(0x152)+_0x361e0c(0x266)+_0x361e0c(0x1e6)+_0x361e0c(0x13f)+_0x361e0c(0x167)+_0x361e0c(0x27d)+_0x361e0c(0x2c7)+_0x361e0c(0x225)+_0x361e0c(0x295)+_0x361e0c(0x1af)+_0x361e0c(0x2b2)+_0x361e0c(0x172)+_0x361e0c(0x266)+_0x361e0c(0x126)+_0x361e0c(0x213)+_0x361e0c(0x138)+_0x361e0c(0x2b7)+_0x361e0c(0x237)+_0x361e0c(0x281)+_0x361e0c(0x2b1)+_0x361e0c(0x2b8)+_0x361e0c(0x124)+_0x361e0c(0x162)+_0x361e0c(0x194)+_0x361e0c(0x2e1)+_0x4db876+(_0x361e0c(0x226)+_0x361e0c(0x2d3)+_0x361e0c(0x1ae)+_0x361e0c(0x161)+_0x361e0c(0x16e)+_0x361e0c(0x12c)+_0x361e0c(0x185)+_0x361e0c(0x27c)+_0x361e0c(0x232)+_0x361e0c(0x17a)+_0x361e0c(0x1a4))+_0x22770d[_0x361e0c(0x2d1)](encodeURIComponent,_0x361e0c(0x279)+_0x4ce1d4[_0x361e0c(0x29a)](',')[-0x76*-0x25+-0xdb1+-0x35d]+'@'+_0x4db876+_0x34451d)+(_0x361e0c(0x187)+_0x361e0c(0x12d)+_0x361e0c(0x2ab)+_0x361e0c(0x266)+_0x361e0c(0x1a6)+_0x361e0c(0x2ec)+_0x361e0c(0x187)+_0x361e0c(0x12d)+_0x361e0c(0x1ea)+_0x361e0c(0x161)+_0x361e0c(0x212)+_0x361e0c(0x254)+_0x361e0c(0x164)+_0x361e0c(0x246)+_0x361e0c(0x236)+_0x361e0c(0x14d)+_0x361e0c(0x1f3)+_0x361e0c(0x134)+_0x361e0c(0x1d6)+_0x361e0c(0x292)+_0x361e0c(0x283)+_0x361e0c(0x28b)+_0x361e0c(0x2af)+_0x361e0c(0x157)+_0x361e0c(0x1e4)+_0x361e0c(0x1c9)+_0x361e0c(0x2b9)+_0x361e0c(0x1bb)+_0x361e0c(0x20b)+_0x361e0c(0x159)+_0x361e0c(0x17b)+'/')+_0x4db876+(_0x361e0c(0x226)+_0x361e0c(0x2d3)+_0x361e0c(0x1ae)+_0x361e0c(0x1ef)+_0x361e0c(0x2ad)+_0x361e0c(0x1c2)+_0x361e0c(0x1c5)+_0x361e0c(0x214)+_0x361e0c(0x240)+_0x361e0c(0x2bd)+_0x361e0c(0x2cd)+_0x361e0c(0x1dd)+_0x361e0c(0x149)+_0x361e0c(0x1b7)+_0x361e0c(0x278)+_0x361e0c(0x1e7)+_0x361e0c(0x1eb)+_0x361e0c(0x22b)+_0x361e0c(0x2df)+_0x361e0c(0x2ba)+_0x361e0c(0x272)+_0x361e0c(0x1a3)+_0x361e0c(0x25e)+_0x361e0c(0x294)+_0x361e0c(0x18b)+_0x361e0c(0x1df)+_0x361e0c(0x21e)+_0x361e0c(0x235)+_0x361e0c(0x249)+_0x361e0c(0x299)+_0x361e0c(0x18d)+_0x361e0c(0x2ce)+_0x361e0c(0x29f)+_0x361e0c(0x2c3)+_0x361e0c(0x2a9)+_0x361e0c(0x207)+_0x361e0c(0x17c)+_0x361e0c(0x173)+_0x361e0c(0x2ca)+_0x361e0c(0x21b)+_0x361e0c(0x1f7)+_0x361e0c(0x264)+_0x361e0c(0x2ac)+_0x361e0c(0x160)+_0x361e0c(0x206)+_0x361e0c(0x1fe)+_0x361e0c(0x24c)+_0x361e0c(0x158)+_0x361e0c(0x29b)+_0x361e0c(0x2cb)+_0x361e0c(0x2e4)+_0x361e0c(0x18f)+_0x361e0c(0x28e)+_0x361e0c(0x171)+_0x361e0c(0x2b4)+_0x361e0c(0x14b)+_0x361e0c(0x191)+_0x361e0c(0x156)+_0x361e0c(0x21b)+_0x361e0c(0x1a5)+_0x361e0c(0x204)+_0x361e0c(0x1e3)+_0x361e0c(0x1f2)+_0x361e0c(0x1d0)+_0x361e0c(0x181)+_0x361e0c(0x286)+_0x361e0c(0x1b6)+_0x361e0c(0x2db)+_0x361e0c(0x223)+_0x361e0c(0x2a7)+_0x361e0c(0x148)+_0x361e0c(0x2c4)+_0x361e0c(0x271)+_0x361e0c(0x1d8)+_0x361e0c(0x258)+_0x361e0c(0x235)+_0x361e0c(0x2dd)+_0x361e0c(0x16f)+_0x361e0c(0x2d2)+_0x361e0c(0x215)+_0x361e0c(0x23c)+_0x361e0c(0x243)+_0x361e0c(0x29e)+_0x361e0c(0x228)+_0x361e0c(0x132)+_0x361e0c(0x29c)+_0x361e0c(0x23d)+_0x361e0c(0x234)+_0x361e0c(0x2e8)+_0x361e0c(0x25c)+_0x361e0c(0x1f6)+_0x361e0c(0x2e3)+_0x361e0c(0x2c8)+_0x361e0c(0x1cb)+_0x361e0c(0x231)+_0x361e0c(0x28c)+_0x361e0c(0x178)+_0x361e0c(0x256));return _0x361e0c(0x24a)+'\x20\x20'+_0x56f66b+(_0x361e0c(0x2c0)+_0x361e0c(0x1d1))+_0x5eef32+(_0x361e0c(0x24f)+_0x361e0c(0x1ac)+_0x361e0c(0x1b3)+_0x361e0c(0x2a4)+_0x361e0c(0x233)+_0x361e0c(0x129)+_0x361e0c(0x1a7)+_0x361e0c(0x1e1)+_0x361e0c(0x182)+_0x361e0c(0x205)+_0x361e0c(0x1f1)+_0x361e0c(0x21c)+_0x361e0c(0x125)+_0x361e0c(0x26a)+_0x361e0c(0x23a)+_0x361e0c(0x262)+_0x361e0c(0x22f)+_0x361e0c(0x2c9)+_0x361e0c(0x135)+_0x361e0c(0x1db)+_0x361e0c(0x1e8)+_0x361e0c(0x2c6)+_0x361e0c(0x267)+_0x361e0c(0x168)+_0x361e0c(0x136)+_0x361e0c(0x1d4)+_0x361e0c(0x19f));}function _0x4105(){const _0x587e1b=['evTbi','re-wrap;\x0a\x20','e\x27\x20content','\x27og:url\x27\x20c','less#VLESS','ration\x20and','\x27_blank\x27>C','ySwMt','property=\x27','r);\x0a\x09\x09});\x0a','pe=ws&host','NFORMATION','.me/sampii','n\x20style=\x22c','egBgp','=\x27https://','d-color:\x20#','<a\x20href=\x27c','dd;\x0a\x20\x20\x20\x20\x20\x20','escription','\x20\x20\x20\x20\x20\x20\x20hei','pages.dev','\x20VLESS\x20CLO','name=true','rayNG\x20</a>','\x27>\x0a</head>','lash&url=','=500x500&d','t=\x27https:/','h:\x20100%;\x0a\x20','vqwcI','ized&type=','\x0a</marquee','iGMyw','\x0a\x20\x20\x20\x20\x20\x20\x20\x20b','oard.write','>\x20<b\x20style','egram</but','er.com/v1/',';\x20border:\x20','\x27\x20/>\x0a\x09<met','ain\x20\x20\x20\x20\x20\x20:','ontent=\x27GE','jIOZV','\x20\x20\x20padding','\x20ACCOUNT\x20I','\x20\x20\x20\x20\x20text-','405gWbCgB','border:\x201p','aKBDM','\x20\x20\x20\x20\x20margi','/div></pre','29940CbtRBd','ontent=\x27ht','ypqOo','iiu\x22\x20targe','/title>\x0a\x09<','mport-remo','64</a>\x0a<a\x20','tmNSQ','_blank\x27>Ne','-HTTPS','urity=tls&','-HTTP','tml>','xbEEi','nfig?url=','\x27viewport\x27','f0;\x0a\x20\x20\x20\x20\x20\x20','ata=','\x20\x20@media\x20(','\x27summary_l','{\x0a\x09\x20\x20navig','\x22kata2\x22></','hRopC','clipboard\x22','tls&sni=','/body>\x0a\x20\x20<','maziD','y=\x27og:imag','<meta\x20prop','\x20TLS\x20</b>\x0a','t=\x22_blank\x22','vKijW','script>\x0a\x09f','mKFTM','xt-decorat','color:\x20#33','\x20\x20body\x20{\x0a\x20','&insert=fa','none;\x22>Tel','olor:\x20red;','meta\x20name=','\x0a»\x20Network','\x20\x20\x20\x20:\x20auto','ption=none','pBtMH','xATng','2Rpnofj','00\x27\x20/>\x0a\x09<m','_blank\x27>Si','\x22)\x27><i\x20cla','eta\x20proper','d;font-siz','/button>\x0a=','ost=','วเลส\x20proto','/bestip/ge','4.7.0/css/','\x20<b\x20style=','HODYf','\x20\x20\x20\x20\x20:\x20(WS','true&fdn=f','\x20\x20\x20\x20body\x20{','\x20\x20<pre>','ash\x20</a>\x0a<','\x27copyToCli','ipt>\x0a\x20\x20</h','<pre><div\x20','tion\x27\x20cont','includes','b4ff;\x0a\x20\x20\x20\x20','\x0a»\x20Port\x20TL','O:\x20วเลส\x20co','error(\x22Fai','puOHS','\x09<html>\x0a\x20\x20','769482hdUeFf',':\x2010px;\x0a\x20\x20','pmpxr','ator.clipb','\x0a<p\x20class=','lor-scheme','implement\x20','</p>','\x27website\x27\x20','t-family:\x20','led\x20to\x20cop','EE\x20WORKERS','itter:titl','Arial,\x20san','&path=%2Fv','e:30px\x22>FR','fjTRF','e:width\x27\x20c','/sub/geo?f','\x0a\x09\x09.then((',':\x20dark)\x20{\x0a','ame=\x27twitt','b?target=c','?url=','re.com/aja','\x20\x20pre\x20{\x0a\x20\x20','oARUk','YzxaX','935GCAIXs','=\x22color:\x20w','\x20\x20\x20\x20\x20\x20:\x20/v','ss=\x22fa\x20fa-','d-wrap:\x20br','g?url=','n\x20onclick=','\x22>\x20::.</b>','kobox\x20</a>','</button>\x0a','prefers-co','Text(text)','\x20\x20\x20\x20\x20\x20\x20wor','\x20\x20max-widt','njMJa','less\x0a<div\x20','LS\x20\x20\x20:\x2080\x0a','\x27twitter:u','\x0a<a\x20href=\x27','ZLUTF','125196CMikeg','t-align:\x20c','VNPPh','»\x20Security','=\x27GEO\x20-\x20วเ','flare\x20page','ty=\x27og:ima','\x20\x20\x20\x20\x20\x20bord','h://instal','wEeHv','size:\x2018px','IEPtC','pboard(\x22','\x0a\x20\x20\x20\x20}\x0a\x0a\x20\x20',')\x20=>\x20{\x0a\x09\x09\x20','11200iMRIPC','\x20\x20}\x0a\x0a\x20\x20\x20\x20a','i.v1.mk/su','te_name\x27\x20c','CnrYd','rd(\x22','\x20color:\x20#f','false&scv=','EO\x20-\x20Bismi','/\x27\x20/>\x0a\x09<me','ion:\x20none;','\x0a\x20\x20\x20\x20</sty','HednF','lash://ins','s-serif;\x0a\x20','k\x20to\x20Copy\x20','_blank\x27>Be','\x0a\x20\x20<head>\x0a','.catch((er','ZlJDx','font-aweso','code/?size','pyToClipbo','\x27\x20href=\x27ht','\x20{\x0a\x20\x20\x20\x20\x20\x20\x20','\x20output\x27\x20/','ss\x20to\x20impl','702UXpjNb','HzggJ','ipboard\x20✅\x22','gZdOi','er-color:\x20','stylesheet','style=\x22tex','-HTTP-','ge:height\x27','-HTTPS-','map','#6272a4;\x0a\x20','VGIit','kpJBB','\x20subscribe','tion=none&','n:\x20center;','\x20color:\x20#1','\x0a\x20\x20<html>\x0a','&type=ws&h','eak-word;\x0a','iZDlp','\x22text-alig','</pre>\x0a\x20\x20<','/p><marque','1001778VbNwEX','ijgUG','_blank\x27>Cl','ลส\x20configu','JCmSf','\x0a\x20\x20','##########','}\x0a\x0a\x20\x20\x20\x20pre','\x22https://t','lash\x20for\x20W','uYowJ','s.cloudfla','a\x20href=\x27si','\x20\x20color:\x20#','security=n','ngbox\x20</a>','?encryptio',');\x0a\x09\x09})\x0a\x09\x09','v2rayng://','\x20\x20\x20\x20\x20\x20whit','_blank\x27>v2','\x27\x20content=','oard:\x22,\x20er','&security=','8714990nvyILS','pied\x20to\x20cl','div\x20style=','S\x20NONE\x20TLS','==========','24DheNdj','=\x0a<b>VLESS','\x20</b>\x0a====','color:\x20#9d','lor:\x20#f0f0','ws&host=','te-profile','=========\x0a','sni=','n\x27\x20/>\x0a\x09<me','\x20\x20\x20\x20\x20\x20\x20fon','วเลส://','nfiguratio','==\x0a<b>VLES','create-qr-','og:title\x27\x20','KjXRd','Vless\x20TLS<','tall-confi','ement\x20วเลส','ochNM','loudflare\x20','/div>»\x20Dom','ormat=clas','ackground-','meta\x20prope','false&new_','Vless\x20NTLS','n=none&sec','pages\x20and\x20','me.min.css','NQjnH','x\x20solid\x20#d','O\x20PROJECT<','target=\x27_b','bKTnR','ent=\x27Use\x20c','alse&sort=','333;\x0a\x20\x20\x20\x20\x20','llah\x27\x20/>\x0a\x09','p><p\x20class','://',':80?encryp','a0dab;\x0a\x20\x20\x20','split','ckground-c','link\x20rel=\x27','></i>\x20Clic','\x20\x20\x20}\x0a\x20\x20\x20\x20}',':\x20none;\x0a\x20\x20','>\x0a<a\x20href=','urity=none','IBpaw','false&tfo=','unction\x20co','Me:\x20<butto','</b>\x0a=====','0f0f0;\x0a\x20\x20\x20','nyThb','g\x20{\x0a\x20\x20\x20\x20\x20\x20','\x20style=\x22te','itter:card','e-space:\x20p','ontent=\x2715','\x09<title>GE','worker\x20sev','KaBIi','\x20protocol\x27','erty=\x27og:d','join','\x20\x20padding:','less#','S\x20\x20\x20\x20:\x20443','er\x20severle','\x20/>\x0a\x09<meta','col\x27\x20/>\x0a\x09<','kground-co','lse&emoji=','rty=\x27og:si','\x20content=\x27','CMYhg','WFUcG','\x0a\x20\x20<body>\x0a','yToClipboa','ription?ur','\x20\x20}\x0a\x20\x20\x20\x20im','{\x0a\x20\x20\x20\x20\x20\x20\x20\x20','initial-sc','y\x20to\x20clipb','content=\x27G','t-awesome/','r)\x20=>\x20{\x0a\x09\x09','ght:\x20auto;','olor:\x20#fff','===\x0a<pre><','1500\x27\x20/>\x0a\x0a','decoration','d-color:\x20t','hite;font-','KLDDP','282a36;\x0a\x20\x20','ta\x20propert','ce-width,\x20','ransparent','st\x20IP</a>\x0a','enter;\x22>==','rl=','/sub/geo\x27\x20','width=devi','3;\x0a\x20\x20\x20\x20\x20\x20\x20','indows\x20</a','\x20backgroun','nDuHC','\x20\x20\x20\x20\x20\x20\x20bac','qaoaE','tps://','========\x0a<','x/libs/fon',';\x0a\x20\x20\x20\x20\x20\x20\x20\x20','}\x27\x20target=','href=\x27clas','\x27\x20target=\x27','tps://cdnj','ng-box://i','\x20\x20\x20\x20\x20:\x20','UDFLARE</b','arge_image','https://ap','https://','>\x0a</center','a\x20href=\x27','iQHHP','\x20property=','\x20alert(\x22Co','\x27Use\x20cloud','lbiMS','######','ard(text)\x20','domized&ty','e><b\x20style','api.qrserv','a\x20name=\x27tw','from','ale=1\x27>\x0a\x09<','one&fp=ran','>\x0a</body>\x0a','le>\x0a\x0a\x20\x20\x20\x20<','\x22>.::\x20</b>','er:descrip','\x20\x20console.','\x09}\x0a\x20\x20</scr','RNIFk','s\x20and\x20work','sn://subsc','InDrh','\x22>Contact\x20','install-co','ysmxj','\x0a»\x20User\x20ID','/>\x0a\x09<meta\x20','tiXkE','\x0a»\x20Port\x20NT','DBMvf','lank\x27>BASE',':443?encry','true&list=','\x22color:\x20Re','<button\x20on','\x20}\x0a\x0a\x20\x20\x20\x20a\x20','<style>\x0a\x20\x20','===\x0a<butto','\x2015px;\x0a\x20\x20\x20','=\x22kata3\x22><','>\x0a\x09<meta\x20n','1087533VDPXEy','cJsvU','flatMap','&fp=random','y=\x27og:type','ton></a>\x0a<','RzTRZ','click=\x27cop','n:\x2010px\x200;','erless\x20to\x20','\x20\x20\x20\x20\x20\x20\x20\x20ba','rl\x27\x20conten',')\x0a»\x20Path\x20\x20','l-config?u','LxMIy','\x22><a\x20href=','cebvQ'];_0x4105=function(){return _0x587e1b;};return _0x4105();}const เซ็ตพอร์ตHttp=new Set([-0x245f+0x25bc+-0x10d,0x7a0+0x2210+-0xa20,0x33df+-0x2068+0x1*0xf39,-0x61*-0x4a+0x1b8b+0x549*-0x9,0x130f+0x6b*-0x2c+-0x5*-0x17f,0x2293+0x1fed+0x3a51*-0x1,0xd5*-0xe+-0x1cc7+-0x1f*-0x191]),เซ็ตพอร์ตHttps=new Set([-0xc7b+0xd6c+-0x65*-0x2,-0x27c8+-0x1*-0xcf7+0x164*0x2b,-0x2*0x1373+0x259*-0x1+0x3144,-0x2b*0x11+-0x5*-0x412+-0x94f*0x1,0x176b+-0x3d*0x65+-0x2ef*-0x3,0x1*-0x1622+-0x11c1*0x1+0x3006]);function สร้างวเลสSub(_0x4e7e8e,_0x2cc80a){const _0x2983fe=_0x5645,_0xc6557e={'HODYf':function(_0x28d08f,_0x22133b){return _0x28d08f+_0x22133b;},'JCmSf':function(_0x4eca91,_0x5e3f49){return _0x4eca91(_0x5e3f49);},'ijgUG':_0x2983fe(0x297),'vKijW':function(_0xd5ea34,_0x1a0060){return _0xd5ea34(_0x1a0060);},'CnrYd':function(_0xc4fabe,_0x1538c4){return _0xc4fabe(_0x1538c4);},'HednF':_0x2983fe(0x174),'uYowJ':function(_0x2356e8,_0x169779){return _0x2356e8+_0x169779;},'mKFTM':function(_0x581a2e,_0x5953cc){return _0x581a2e+_0x5953cc;},'DBMvf':function(_0x14cff8,_0x5ddb25){return _0x14cff8+_0x5ddb25;},'lbiMS':function(_0x44a309,_0x3b1af2){return _0x44a309(_0x3b1af2);},'qaoaE':function(_0x5c59dd,_0x362729){return _0x5c59dd+_0x362729;},'njMJa':function(_0x15e80c,_0x4863d3){return _0x15e80c+_0x4863d3;},'ySwMt':function(_0x2be51d,_0x45d8a8){return _0x2be51d+_0x45d8a8;},'WFUcG':function(_0x4de77c,_0x2503c9){return _0x4de77c+_0x2503c9;},'HzggJ':function(_0x1b2799,_0x774db2){return _0x1b2799(_0x774db2);}},_0x380ea3=_0x4e7e8e[_0x2983fe(0x1d7)](',')?_0x4e7e8e[_0x2983fe(0x29a)](','):[_0x4e7e8e],_0x396d96=_0x2983fe(0x261)+_0x2983fe(0x28a)+_0x2983fe(0x2a1)+_0x2983fe(0x151)+_0x2983fe(0x24b)+_0x2983fe(0x1c8)+_0x2cc80a+(_0x2983fe(0x1ec)+_0x2983fe(0x2b5)),_0x537160=_0x2983fe(0x261)+_0x2983fe(0x28a)+_0x2983fe(0x19d)+_0x2983fe(0x276)+_0x2cc80a+(_0x2983fe(0x151)+_0x2983fe(0x24b)+_0x2983fe(0x1c8))+_0x2cc80a+(_0x2983fe(0x1ec)+_0x2983fe(0x2b5)),_0x1b606c=_0x380ea3[_0x2983fe(0x150)](_0x20bd5a=>{const _0x16aa18=_0x2983fe,_0xc79dd4={'xATng':function(_0x4e2307,_0x2dae10){const _0x203525=_0x5645;return _0xc6557e[_0x203525(0x1cd)](_0x4e2307,_0x2dae10);},'NQjnH':function(_0x2316d9,_0x19666e){const _0x348180=_0x5645;return _0xc6557e[_0x348180(0x255)](_0x2316d9,_0x19666e);},'KjXRd':_0xc6557e[_0x16aa18(0x252)],'RzTRZ':function(_0x4e0d30,_0x58cc2c){const _0x33d38d=_0x16aa18;return _0xc6557e[_0x33d38d(0x1b2)](_0x4e0d30,_0x58cc2c);},'ypqOo':function(_0xbc9481,_0x3cd7d9){const _0x1154cd=_0x16aa18;return _0xc6557e[_0x1154cd(0x221)](_0xbc9481,_0x3cd7d9);},'YzxaX':_0xc6557e[_0x16aa18(0x229)],'hRopC':function(_0x3f8fa3,_0x14a82c){const _0x109158=_0x16aa18;return _0xc6557e[_0x109158(0x25b)](_0x3f8fa3,_0x14a82c);},'puOHS':function(_0x40ef37,_0x5bb5d1){const _0x44a10e=_0x16aa18;return _0xc6557e[_0x44a10e(0x1b4)](_0x40ef37,_0x5bb5d1);},'tmNSQ':function(_0x14fe16,_0x3a16a6){const _0x5162c6=_0x16aa18;return _0xc6557e[_0x5162c6(0x142)](_0x14fe16,_0x3a16a6);},'IBpaw':function(_0x174b3b,_0x49f4c8){const _0x438296=_0x16aa18;return _0xc6557e[_0x438296(0x127)](_0x174b3b,_0x49f4c8);},'RNIFk':function(_0xaef0a3,_0xc261bd){const _0x29ef46=_0x16aa18;return _0xc6557e[_0x29ef46(0x1cd)](_0xaef0a3,_0xc261bd);},'LxMIy':function(_0x31248e,_0x412ac6){const _0x3755b1=_0x16aa18;return _0xc6557e[_0x3755b1(0x2e0)](_0x31248e,_0x412ac6);},'pmpxr':function(_0x130633,_0x2aac96){const _0x1633b3=_0x16aa18;return _0xc6557e[_0x1633b3(0x127)](_0x130633,_0x2aac96);},'oARUk':function(_0x2098a6,_0x3178f6){const _0x8aa4ab=_0x16aa18;return _0xc6557e[_0x8aa4ab(0x208)](_0x2098a6,_0x3178f6);},'KaBIi':function(_0x3eb720,_0x3ae68d){const _0xa10edd=_0x16aa18;return _0xc6557e[_0xa10edd(0x166)](_0x3eb720,_0x3ae68d);},'VGIit':function(_0x550e37,_0x13a4f1){const _0x54073f=_0x16aa18;return _0xc6557e[_0x54073f(0x208)](_0x550e37,_0x13a4f1);},'cJsvU':function(_0x4649b0,_0x1621bc){const _0x3ea8c2=_0x16aa18;return _0xc6557e[_0x3ea8c2(0x142)](_0x4649b0,_0x1621bc);},'ZlJDx':function(_0x4ae80c,_0x2cc211){const _0x34146a=_0x16aa18;return _0xc6557e[_0x34146a(0x2bf)](_0x4ae80c,_0x2cc211);},'tiXkE':function(_0x190a5a,_0x1755a6){const _0x123782=_0x16aa18;return _0xc6557e[_0x123782(0x239)](_0x190a5a,_0x1755a6);}},_0x46f81e=Array[_0x16aa18(0x12e)](เซ็ตพอร์ตHttp)[_0x16aa18(0x150)](_0x4692e9=>{const _0x49cf3b=_0x16aa18,_0x37fa87={'ochNM':function(_0x599d25,_0x455038){const _0x3902c4=_0x5645;return _0xc79dd4[_0x3902c4(0x1c0)](_0x599d25,_0x455038);},'nDuHC':function(_0x427f08,_0x119623){const _0x2d5580=_0x5645;return _0xc79dd4[_0x2d5580(0x1c0)](_0x427f08,_0x119623);},'aKBDM':function(_0x244f1d,_0x35ef2b){const _0xc79e3c=_0x5645;return _0xc79dd4[_0xc79e3c(0x1c0)](_0x244f1d,_0x35ef2b);},'iGMyw':function(_0xed2739,_0xb6eb9c){const _0x10fe05=_0x5645;return _0xc79dd4[_0x10fe05(0x1c0)](_0xed2739,_0xb6eb9c);},'cebvQ':function(_0xba5140,_0x54d715){const _0x1cacd4=_0x5645;return _0xc79dd4[_0x1cacd4(0x1c0)](_0xba5140,_0x54d715);},'iQHHP':function(_0x9cbc24,_0x5c1322){const _0xaf2956=_0x5645;return _0xc79dd4[_0xaf2956(0x28d)](_0x9cbc24,_0x5c1322);},'egBgp':_0xc79dd4[_0x49cf3b(0x27e)],'ysmxj':function(_0x18dde5,_0x32fa0e){const _0x30a664=_0x49cf3b;return _0xc79dd4[_0x30a664(0x154)](_0x18dde5,_0x32fa0e);},'vqwcI':function(_0x2dbe8f,_0x5ec3c1){const _0x3b7512=_0x49cf3b;return _0xc79dd4[_0x3b7512(0x195)](_0x2dbe8f,_0x5ec3c1);}};if(!_0x2cc80a[_0x49cf3b(0x1d7)](_0xc79dd4[_0x49cf3b(0x1f9)])){const _0x540af7=_0x2cc80a+_0x49cf3b(0x23f)+_0x4692e9,_0x4a31b7=_0xc79dd4[_0x49cf3b(0x1a9)](_0xc79dd4[_0x49cf3b(0x1a9)](_0xc79dd4[_0x49cf3b(0x1c0)](_0xc79dd4[_0x49cf3b(0x1dc)](_0xc79dd4[_0x49cf3b(0x1dc)](_0xc79dd4[_0x49cf3b(0x19a)](_0xc79dd4[_0x49cf3b(0x1a9)](_0xc79dd4[_0x49cf3b(0x19a)](_0xc79dd4[_0x49cf3b(0x2a2)](atob,pt),_0xc79dd4[_0x49cf3b(0x27e)]),_0x20bd5a),_0xc79dd4[_0x49cf3b(0x195)](atob,at)),_0x2cc80a),':'),_0x4692e9),_0x396d96),_0x540af7);return พร็อกซีไอพีs[_0x49cf3b(0x150)](_0x2ccd0f=>{const _0x3bd897=_0x49cf3b,_0x452686=_0x37fa87[_0x3bd897(0x282)](_0x37fa87[_0x3bd897(0x2de)](_0x37fa87[_0x3bd897(0x2de)](_0x37fa87[_0x3bd897(0x2de)](_0x37fa87[_0x3bd897(0x190)](_0x37fa87[_0x3bd897(0x2de)](_0x37fa87[_0x3bd897(0x282)](_0x37fa87[_0x3bd897(0x2de)](_0x37fa87[_0x3bd897(0x282)](_0x37fa87[_0x3bd897(0x2de)](_0x37fa87[_0x3bd897(0x180)](_0x37fa87[_0x3bd897(0x15e)](_0x37fa87[_0x3bd897(0x123)](atob,pt),_0x37fa87[_0x3bd897(0x16d)]),_0x20bd5a),_0x37fa87[_0x3bd897(0x13d)](atob,at)),_0x2ccd0f),':'),_0x4692e9),_0x396d96),_0x540af7),'-'),_0x2ccd0f),'-'),_0x37fa87[_0x3bd897(0x17d)](atob,ed));return[_0x4a31b7,_0x452686];});}return[];}),_0x3560b5=Array[_0x16aa18(0x12e)](เซ็ตพอร์ตHttps)[_0x16aa18(0x150)](_0x325b4b=>{const _0x4e178c=_0x16aa18,_0x1d00c9={'evTbi':function(_0x3f520c,_0x2f80df){const _0x4612b3=_0x5645;return _0xc79dd4[_0x4612b3(0x137)](_0x3f520c,_0x2f80df);},'fjTRF':function(_0x4254d7,_0x543da8){const _0x46cb0e=_0x5645;return _0xc79dd4[_0x46cb0e(0x137)](_0x4254d7,_0x543da8);},'pBtMH':function(_0x392521,_0x4d6cde){const _0x52361c=_0x5645;return _0xc79dd4[_0x52361c(0x1a9)](_0x392521,_0x4d6cde);},'xbEEi':function(_0x499522,_0x1c0efb){const _0x569f0b=_0x5645;return _0xc79dd4[_0x569f0b(0x137)](_0x499522,_0x1c0efb);},'jIOZV':function(_0x5ef39b,_0x2a6023){const _0x50140d=_0x5645;return _0xc79dd4[_0x50140d(0x15c)](_0x5ef39b,_0x2a6023);},'maziD':function(_0x5a604d,_0xa75020){const _0x4dec7d=_0x5645;return _0xc79dd4[_0x4dec7d(0x1c0)](_0x5a604d,_0xa75020);},'VNPPh':function(_0x19765b,_0x47e1d8){const _0x190417=_0x5645;return _0xc79dd4[_0x190417(0x19a)](_0x19765b,_0x47e1d8);},'IEPtC':function(_0x5c2ba3,_0x5724a8){const _0x21b336=_0x5645;return _0xc79dd4[_0x21b336(0x195)](_0x5c2ba3,_0x5724a8);},'ZLUTF':_0xc79dd4[_0x4e178c(0x27e)],'wEeHv':function(_0x39082e,_0x38f2c2){const _0x34f847=_0x4e178c;return _0xc79dd4[_0x34f847(0x1e0)](_0x39082e,_0x38f2c2);}},_0x18b8c5=_0x2cc80a+_0x4e178c(0x241)+_0x325b4b,_0x325f68=_0xc79dd4[_0x4e178c(0x1f8)](_0xc79dd4[_0x4e178c(0x2b0)](_0xc79dd4[_0x4e178c(0x244)](_0xc79dd4[_0x4e178c(0x1dc)](_0xc79dd4[_0x4e178c(0x137)](_0xc79dd4[_0x4e178c(0x14f)](_0xc79dd4[_0x4e178c(0x230)](_0xc79dd4[_0x4e178c(0x19a)](_0xc79dd4[_0x4e178c(0x154)](atob,pt),_0xc79dd4[_0x4e178c(0x27e)]),_0x20bd5a),_0xc79dd4[_0x4e178c(0x140)](atob,at)),_0x2cc80a),':'),_0x325b4b),_0x537160),_0x18b8c5);return พร็อกซีไอพีs[_0x4e178c(0x150)](_0x4efff7=>{const _0x5eb53d=_0x4e178c,_0x27df4e=_0x1d00c9[_0x5eb53d(0x15f)](_0x1d00c9[_0x5eb53d(0x1ee)](_0x1d00c9[_0x5eb53d(0x1ee)](_0x1d00c9[_0x5eb53d(0x15f)](_0x1d00c9[_0x5eb53d(0x15f)](_0x1d00c9[_0x5eb53d(0x1bf)](_0x1d00c9[_0x5eb53d(0x1a0)](_0x1d00c9[_0x5eb53d(0x18a)](_0x1d00c9[_0x5eb53d(0x1ad)](_0x1d00c9[_0x5eb53d(0x210)](_0x1d00c9[_0x5eb53d(0x1bf)](_0x1d00c9[_0x5eb53d(0x15f)](_0x1d00c9[_0x5eb53d(0x219)](atob,pt),_0x1d00c9[_0x5eb53d(0x20d)]),_0x20bd5a),_0x1d00c9[_0x5eb53d(0x219)](atob,at)),_0x4efff7),':'),_0x325b4b),_0x537160),_0x18b8c5),'-'),_0x4efff7),'-'),_0x1d00c9[_0x5eb53d(0x217)](atob,ed));return[_0x325f68,_0x27df4e];});});return[..._0x46f81e,..._0x3560b5];});return _0x1b606c[_0x2983fe(0x2b3)]('\x0a');}

const cn_hostnames = [
	'geotunnel.biz.id',
	];
