import resendService from '../service/resend-service';
import app from '../hono/hono';
import { verifyResendSignature } from '../security/resend-signature';

async function readBody(request, limit) {
	const reader = request.body?.getReader();
	if (!reader) return '';
	const chunks = [];
	let size = 0;
	try {
		while (true) {
			const { done, value } = await reader.read();
			if (done) break;
			size += value.length;
			if (size > limit) { await reader.cancel(); return null; }
			chunks.push(value);
		}
	} finally { reader.releaseLock(); }
	const bytes = new Uint8Array(size);
	let offset = 0;
	for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
	return new TextDecoder().decode(bytes);
}

app.post('/webhooks',async (c) => {
	if (!c.env.RESEND_WEBHOOK_SECRET) return c.text('Webhook temporarily unavailable', 503);
	const raw = await readBody(c.req.raw, 65536);
	if (raw === null) return c.text('Payload too large', 413);
	if (!await verifyResendSignature(c.req.raw.headers, raw, c.env.RESEND_WEBHOOK_SECRET)) {
		return c.text('Invalid webhook signature', 401);
	}
	let body;
	try {
		body = JSON.parse(raw);
	} catch { return c.text('Invalid webhook payload', 400); }
	if (typeof body?.data?.email_id !== 'string' || body.data.email_id.length > 128) {
		return c.text('Invalid webhook payload', 400);
	}
	const events = ['email.sent', 'email.delivered', 'email.complained', 'email.bounced', 'email.delivery_delayed', 'email.failed'];
	if (!events.includes(body.type)) return c.text('ignored', 200);
	if (body.type === 'email.failed' && typeof body.data.failed?.reason !== 'string') return c.text('Invalid webhook payload', 400);
	try {
		await resendService.webhooks(c, body);
		return c.text('success', 200)
	} catch (e) {
		console.error('Resend webhook processing failed', e.name);
		return c.text('Webhook processing failed', 500);
	}
})
