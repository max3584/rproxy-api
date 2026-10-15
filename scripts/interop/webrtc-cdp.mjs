// Runs one WebRTC check in a headless Chromium over the DevTools protocol (no npm
// packages: Node's own fetch and WebSocket). Used by scripts/interop/webrtc.sh.
//
//   node webrtc-cdp.mjs <devtools port> <page url> <mode: direct | relay> [turn url]
//
// On the page (MediaMTX's WebRTC server, reached through rproxy) it publishes a
// canvas over WHIP, reads it back over WHEP and prints what getStats saw as JSON:
// frames decoded, and the selected candidate pair of the reader.
const [port, pageUrl, mode, turnUrl] = process.argv.slice(2);

const target = await (await fetch(`http://127.0.0.1:${port}/json/new?about:blank`, { method: 'PUT' })).json();
const ws = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((ok, bad) => { ws.onopen = ok; ws.onerror = bad; });
let next = 0;
const waiting = new Map();
ws.onmessage = (m) => {
	const msg = JSON.parse(m.data);
	if (msg.id && waiting.has(msg.id)) {
		waiting.get(msg.id)(msg);
		waiting.delete(msg.id);
	}
};
const send = (method, params = {}) => new Promise((ok) => {
	const id = ++next;
	waiting.set(id, ok);
	ws.send(JSON.stringify({ id, method, params }));
});

await send('Page.enable');
await send('Page.navigate', { url: pageUrl });
// wait for the page to be there (any answer of the server will do: same origin for WHIP / WHEP)
for (let i = 0; i < 50; i++) {
	const r = await send('Runtime.evaluate', { expression: 'document.readyState', returnByValue: true });
	if (r.result?.result?.value === 'complete') break;
	await new Promise((ok) => setTimeout(ok, 200));
}

const check = async (mode, turnUrl) => {
	const sleep = (ms) => new Promise((ok) => setTimeout(ok, ms));
	const gathered = (pc) => new Promise((ok) => {
		if (pc.iceGatheringState === 'complete') return ok();
		pc.addEventListener('icegatheringstatechange', () => pc.iceGatheringState === 'complete' && ok());
		setTimeout(ok, 5000);
	});
	// WHIP / WHEP without trickle: the offer with all candidates, the answer back
	const exchange = async (pc, url) => {
		await pc.setLocalDescription(await pc.createOffer());
		await gathered(pc);
		const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/sdp' }, body: pc.localDescription.sdp });
		if (r.status !== 201) throw new Error(`${url}: ${r.status} ${await r.text()}`);
		await pc.setRemoteDescription({ type: 'answer', sdp: await r.text() });
	};

	// a moving canvas as the camera
	const canvas = document.createElement('canvas');
	canvas.width = 320;
	canvas.height = 240;
	const g = canvas.getContext('2d');
	let n = 0;
	setInterval(() => {
		g.fillStyle = `hsl(${(n += 7) % 360} 80% 50%)`;
		g.fillRect(0, 0, 320, 240);
		g.fillStyle = '#000';
		g.fillText(String(n), 10, 20);
	}, 50);
	const stream = canvas.captureStream(15);

	const publisher = new RTCPeerConnection();
	publisher.addTransceiver(stream.getVideoTracks()[0], { direction: 'sendonly' });
	await exchange(publisher, '/interop/whip');

	const config = mode === 'relay'
		? { iceServers: [{ urls: turnUrl, username: 'interop', credential: 'interop-pass' }], iceTransportPolicy: 'relay' }
		: {};
	const reader = new RTCPeerConnection(config);
	reader.addTransceiver('video', { direction: 'recvonly' });
	await exchange(reader, '/interop/whep');

	let out = { framesDecoded: 0 };
	for (let i = 0; i < 60; i++) {
		await sleep(500);
		const stats = await reader.getStats();
		let inbound, pair;
		stats.forEach((s) => {
			if (s.type === 'inbound-rtp' && s.kind === 'video') inbound = s;
			if (s.type === 'transport' && s.selectedCandidatePairId) pair = stats.get(s.selectedCandidatePairId);
		});
		const local = pair && stats.get(pair.localCandidateId);
		const remote = pair && stats.get(pair.remoteCandidateId);
		out = {
			framesDecoded: inbound?.framesDecoded ?? 0,
			bytesReceived: inbound?.bytesReceived ?? 0,
			codec: inbound?.codecId && stats.get(inbound.codecId)?.mimeType,
			local: local && { type: local.candidateType, address: local.address, port: local.port, protocol: local.protocol },
			remote: remote && { type: remote.candidateType, address: remote.address, port: remote.port },
			state: reader.connectionState,
		};
		if (out.framesDecoded >= 30) break;
	}
	publisher.close();
	reader.close();
	return out;
};

const r = await send('Runtime.evaluate', {
	expression: `(${check.toString()})(${JSON.stringify(mode)}, ${JSON.stringify(turnUrl ?? '')})`,
	awaitPromise: true,
	returnByValue: true,
});
ws.close();
if (r.result?.exceptionDetails) {
	console.error(JSON.stringify(r.result.exceptionDetails));
	process.exit(1);
}
console.log(JSON.stringify(r.result.result.value));
