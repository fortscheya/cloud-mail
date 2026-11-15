const encoder = new TextEncoder();

function decode(value) {
	return Uint8Array.from(atob(value), char => char.charCodeAt(0));
}

// Svix signs the exact bytes: id + '.' + timestamp + '.' + raw request body.
// Use WebCrypto verification for a constant-time MAC comparison.
export async function verifyResendSignature(headers, body, secret, now = Date.now()) {
	if (typeof secret !== 'string' || !secret.startsWith('whsec_')) return false;
	const id = headers.get('svix-id');
	const timestamp = headers.get('svix-timestamp');
	const signatures = headers.get('svix-signature');
	if (!id || id.length > 256 || !/^\d{1,12}$/.test(timestamp || '') || !signatures || signatures.length > 2048) return false;
	if (Math.abs(Math.floor(now / 1000) - Number(timestamp)) > 300) return false;
	try {
		const bytes = decode(secret.slice(6));
		if (bytes.length < 24) return false;
		const key = await crypto.subtle.importKey('raw', bytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
		const message = encoder.encode(`${id}.${timestamp}.${body}`);
		for (const signature of signatures.split(/\s+/)) {
			const [version, value] = signature.split(',');
			if (version !== 'v1' || !value) continue;
			try {
				if (await crypto.subtle.verify('HMAC', key, decode(value), message)) return true;
			} catch { /* An invalid candidate must not hide a later valid signature. */ }
		}
	} catch { return false; }
	return false;
}
