import { sessionHash } from './session';

// Workers Rate Limiting binding, configured in every production Wrangler file.
// A missing binding fails closed instead of silently enabling password guessing.
export async function authRateLimit(c, account) {
	if (!c.env.AUTH_RATE_LIMITER) {
		return c.json({ code: 503, message: 'Authentication temporarily unavailable' }, 503);
	}
	const ip = c.req.header('CF-Connecting-IP') || 'unknown';
	const key = account
		? 'account:' + await sessionHash(String(account).trim().toLowerCase())
		: 'ip:' + ip;
	const { success } = await c.env.AUTH_RATE_LIMITER.limit({ key });
	if (!success) {
		c.header('Retry-After', '60');
		return c.json({ code: 429, message: 'Too many authentication attempts' }, 429);
	}
	return null;
}
