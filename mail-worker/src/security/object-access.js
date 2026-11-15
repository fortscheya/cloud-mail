// Only object keys created by the application may reach object storage.
// Configuration, sessions and API keys never belong to this namespace.
const background = /^static\/background\/[a-f0-9]{32}(?:\.[a-zA-Z0-9.+-]{1,32})?$/;
const attachment = /^attachments\/[a-f0-9]{32}(?:\.[a-zA-Z0-9.+-]{1,100})?$/;

export function isPublicObject(key) {
	return typeof key === 'string' && background.test(key);
}

export async function canReadObject(c, key) {
	if (isPublicObject(key)) return true;
	if (typeof key !== 'string' || !attachment.test(key)) return false;
	const user = c.get?.('user');
	if (!user?.userId) return false;

	const admin = user.email === c.env.admin;
	const row = await c.env.db.prepare(
		'SELECT att_id FROM attachments WHERE key = ? AND (user_id = ? OR ? = 1) LIMIT 1'
	).bind(key, user.userId, admin ? 1 : 0).first();
	return !!row;
}

export function objectResponse(response, key) {
	if (!response) return null;
	const result = new Response(response.body, response);
	result.headers.set('X-Content-Type-Options', 'nosniff');
	if (key.startsWith('attachments/')) {
		result.headers.set('Cache-Control', 'private, no-store');
		// Untrusted HTML/SVG attachments must not acquire the mail site's origin.
		result.headers.set('Content-Security-Policy', 'sandbox');
	}
	return result;
}
