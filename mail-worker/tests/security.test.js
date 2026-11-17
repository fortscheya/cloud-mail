import { beforeEach, describe, expect, it, vi } from 'vitest';
import { env } from 'cloudflare:test';
import worker from '../src/index';
import app from '../src/hono/hono';
import jwt from '../src/utils/jwt-utils';
import passwords from '../src/utils/crypto-utils';
import { sessionHash, ASSET_COOKIE } from '../src/security/session';
import settingService from '../src/service/setting-service';
import { validNewPassword } from '../src/utils/crypto-utils';
import userService from '../src/service/user-service';
import settingSchema from '../src/entity/setting';
import { getTableConfig } from 'drizzle-orm/sqlite-core';

const password = 'test-only-Strong-Password-47';
const key = 'attachments/' + 'a'.repeat(32) + '.png';
const background = 'static/background/' + 'b'.repeat(32) + '.png';
const webhookBytes = new Uint8Array(32).fill(19);
const webhookSecret = 'whsec_' + btoa(String.fromCharCode(...webhookBytes));
let bindings;
app.get('/login-diagnostic-fixture', () => { throw new Error('SQLITE_ERROR: sensitive SQL and bindings'); });

async function request(path, { token, cookie, body, method = body ? 'POST' : 'GET', headers = {} } = {}) {
	return worker.fetch(new Request('https://mail.example.test' + path, {
		method, headers: {
			...(token ? { Authorization: token } : {}),
			...(cookie ? { Cookie: cookie } : {}),
			...(body ? { 'Content-Type': 'application/json' } : {}), ...headers,
		}, body: body ? JSON.stringify(body) : undefined,
	}), bindings, {});
}

async function session(userId = 1, email = 'admin@example.test', gen = 2) {
	const token = 'test-session-' + userId;
	const value = await jwt.generateToken({ env: bindings }, { userId, token, gen }, 600);
	await env.kv.put('auth-uid:' + userId, JSON.stringify({
		gen, tokens: [await sessionHash(token)], user: { userId, email }, refreshTime: new Date().toISOString(),
	}));
	return value;
}

async function signed(raw, { timestamp = Math.floor(Date.now() / 1000), id = 'msg_test_1' } = {}) {
	const signingKey = await crypto.subtle.importKey('raw', webhookBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
	const signature = await crypto.subtle.sign('HMAC', signingKey, new TextEncoder().encode(`${id}.${timestamp}.${raw}`));
	return { 'svix-id': id, 'svix-timestamp': String(timestamp), 'svix-signature': 'v1,' + btoa(String.fromCharCode(...new Uint8Array(signature))) };
}

beforeEach(async () => {
	bindings = { ...env, admin: 'admin@example.test', domain: ['example.test'], jwt_secret: 'test-only-secret-never-use-in-production',
		AUTH_RATE_LIMITER: { limit: async () => ({ success: true }) }, RESEND_WEBHOOK_SECRET: webhookSecret };
	await env.db.exec(`
CREATE TABLE user (user_id INTEGER PRIMARY KEY AUTOINCREMENT,email TEXT UNIQUE,type INTEGER DEFAULT 1,password TEXT NOT NULL,salt TEXT NOT NULL,status INTEGER DEFAULT 0,create_time TEXT DEFAULT CURRENT_TIMESTAMP,active_time TEXT,create_ip TEXT,active_ip TEXT,os TEXT,browser TEXT,device TEXT,sort TEXT DEFAULT '0',send_count TEXT DEFAULT '0',reg_key_id INTEGER DEFAULT 0,is_del INTEGER DEFAULT 0);
CREATE TABLE account (account_id INTEGER PRIMARY KEY AUTOINCREMENT,email TEXT UNIQUE,name TEXT,user_id INTEGER,is_del INTEGER DEFAULT 0,status INTEGER DEFAULT 0,latest_email_time TEXT,create_time TEXT DEFAULT CURRENT_TIMESTAMP,all_receive INTEGER DEFAULT 0,sort INTEGER DEFAULT 0);
CREATE TABLE verify_record (vr_id INTEGER PRIMARY KEY,ip TEXT,count INTEGER,type INTEGER,update_time TEXT);
CREATE TABLE oauth (user_id INTEGER,username TEXT,trust_level INTEGER,avatar TEXT,name TEXT,platform TEXT);
CREATE TABLE perm (perm_id INTEGER PRIMARY KEY,perm_key TEXT,type INTEGER DEFAULT 2);
CREATE TABLE role_perm (id INTEGER PRIMARY KEY,role_id INTEGER,perm_id INTEGER);
CREATE TABLE role (role_id INTEGER PRIMARY KEY,name TEXT,key TEXT,description TEXT,ban_email TEXT DEFAULT '',ban_email_type INTEGER DEFAULT 0,avail_domain TEXT DEFAULT '',sort INTEGER,is_default INTEGER,create_time TEXT DEFAULT CURRENT_TIMESTAMP,user_id INTEGER,send_count INTEGER,send_type TEXT DEFAULT 'count',account_count INTEGER);
CREATE TABLE attachments (att_id INTEGER PRIMARY KEY,user_id INTEGER,email_id INTEGER,account_id INTEGER,key TEXT);
CREATE TABLE email (email_id INTEGER PRIMARY KEY,send_email TEXT,name TEXT,sender_email TEXT DEFAULT '',account_id INTEGER,user_id INTEGER,subject TEXT,code TEXT DEFAULT '',text TEXT,content TEXT,cc TEXT DEFAULT '[]',bcc TEXT DEFAULT '[]',recipient TEXT DEFAULT '[]',to_email TEXT DEFAULT '',to_name TEXT DEFAULT '',in_reply_to TEXT DEFAULT '',relation TEXT DEFAULT '',message_id TEXT DEFAULT '',type INTEGER DEFAULT 0,status INTEGER DEFAULT 0,resend_email_id TEXT,message TEXT,unread INTEGER DEFAULT 0,create_time TEXT DEFAULT CURRENT_TIMESTAMP,is_del INTEGER DEFAULT 0);
INSERT INTO role(role_id,name,is_default) VALUES(1,'default',1);
INSERT INTO email(email_id,user_id,account_id,resend_email_id,status) VALUES(1,2,1,'known-email',0);
`);
	await env.db.prepare('INSERT INTO attachments(att_id,user_id,email_id,key) VALUES(1,2,1,?)').bind(key).run();
	await env.kv.put('setting:', JSON.stringify({ resendTokens: { 'example.test': 'compromised-fixture-only' }, emailPrefixFilter: '', bucket: '', endpoint: '', s3AccessKey: '', s3SecretKey: '' }));
	await env.kv.put('public_key:', 'old-shared-token');
	await env.kv.put(key, 'private attachment', { metadata: { contentType: 'image/png', cacheControl: 'public, max-age=300' } });
	await env.kv.put(background, 'public background');
});

describe('Resend configuration availability', () => {
	const invalidValues = [
		'plain-api-key-fixture',
		'```json\n{"example.test":"fixture"}\n```',
		JSON.stringify(JSON.stringify({ 'example.test': 'fixture' })),
		'null', '[]', '{"example.test":null}', '{"example.test":"   "}',
	];
	it.each(invalidValues)('keeps system settings and website configuration available for invalid input %#', async raw => {
		bindings.RESEND_TOKENS = raw;
		const response = await request('/api/setting/query', { token: await session() });
		expect(response.status).toBe(200);
		const body = await response.json();
		expect(body.code).toBe(200);
		expect(body.data.resendConfigStatus).toBe('invalid');
		expect(body.data.resendTokens).toEqual({});
		expect(JSON.stringify(body)).not.toContain('plain-api-key-fixture');
		const publicResponse = await request('/api/setting/websiteConfig');
		expect(publicResponse.status).toBe(200);
		const publicBody = await publicResponse.json();
		expect(publicBody.code).toBe(200);
		expect(publicBody.data).not.toHaveProperty('resendConfigStatus');
		expect(publicBody.data).not.toHaveProperty('resendTokens');
	});
	it('lets administrators save ordinary settings without persisting status or sending keys', async () => {
		const columns = getTableConfig(settingSchema).columns.map(column =>
			`"${column.name}" ${column.getSQLType()} DEFAULT ${column.dataType === 'number' ? '0' : "''"}`);
		await env.db.exec(`CREATE TABLE setting (${columns.join(',')}); INSERT INTO setting(title,resend_tokens) VALUES('before','{"example.test":"compromised-fixture-only"}');`);
		bindings.RESEND_TOKENS = 'plain-api-key-fixture';
		const token = await session();
		const response = await request('/api/setting/set', { token, method: 'PUT', body: { title: 'after', resendConfigStatus: 'configured' } });
		expect(response.status).toBe(200);
		expect((await response.json()).code).toBe(200);
		const saved = await env.db.prepare('SELECT title,resend_tokens FROM setting').first();
		expect(saved).toEqual({ title: 'after', resend_tokens: '{}' });
		const cache = await env.kv.get('setting:', 'json');
		expect(cache.title).toBe('after');
		expect(cache.resendTokens).toEqual({});
		expect(cache).not.toHaveProperty('resendConfigStatus');
		const current = await (await request('/api/setting/query', { token })).json();
		expect(current.data.resendConfigStatus).toBe('invalid');
	});
	it('rejects an external Resend send before any provider request for invalid configuration', async () => {
		bindings.RESEND_TOKENS = 'plain-api-key-fixture';
		await env.db.prepare('INSERT INTO user(user_id,email,password,salt) VALUES(1,?,?,?)').bind('admin@example.test', 'unused', 'unused').run();
		await env.db.prepare('INSERT INTO account(account_id,user_id,email,name) VALUES(1,1,?,?)').bind('admin@example.test', 'admin').run();
		const fetch = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('Provider must not be called'));
		try {
			const response = await request('/api/email/send', { token: await session(), body: {
				accountId: 1, receiveEmail: ['outside@other.test'], content: '<p>fixture</p>', text: 'fixture', subject: 'fixture',
			} });
			expect(response.status).toBe(503);
			const body = await response.json();
			expect(body.message).toContain('RESEND_TOKENS');
			expect(body.message).not.toContain('plain-api-key-fixture');
			expect(fetch).not.toHaveBeenCalled();
		} finally { fetch.mockRestore(); }
	});
	it('recovers immediately after the Secret is corrected without using legacy keys', async () => {
		bindings.RESEND_TOKENS = 'plain-api-key-fixture';
		expect(() => settingService.resendToken({ env: bindings }, 'example.test')).toThrow('RESEND_TOKENS');
		bindings.RESEND_TOKENS = '\uFEFF  ' + JSON.stringify({ 'example.test': 'new-test-only-fixture' }) + '\n';
		expect(settingService.resendToken({ env: bindings }, 'example.test')).toBe('new-test-only-fixture');
		const response = await request('/api/setting/query', { token: await session() });
		const body = await response.json();
		expect(body.data.resendConfigStatus).toBe('configured');
		expect(JSON.stringify(body)).not.toContain('new-test-only-fixture');
		delete bindings.RESEND_TOKENS;
		expect(settingService.resendToken({ env: bindings }, 'example.test')).toBeUndefined();
	});
});

describe('HTTP access boundaries', () => {
	it('denies every internal-key alias, including authenticated administrators', async () => {
		const token = await session();
		for (const path of ['/api/oss/public_key:', '/oss/setting:', '/api/oss/auth-uid:1', '/oss/auth-uid%3A1', '/oss/static/../setting:']) {
			for (const auth of [undefined, token]) {
				const response = await request(path, { token: auth });
				expect([401, 404]).toContain(response.status);
				expect(await response.text()).not.toContain('compromised-fixture-only');
			}
		}
	});
	it('allows only application background objects without authentication', async () => {
		for (const path of ['/' + background, '/oss/' + background, '/api/oss/' + background]) {
			const response = await request(path);
			expect(response.status).toBe(200);
			expect(await response.text()).toBe('public background');
		}
	});
	it('authorizes attachment aliases by owner and a revocable HttpOnly session', async () => {
		const owner = await session(2, 'owner@example.test');
		const stranger = await session(3, 'stranger@example.test');
		for (const path of ['/' + key, '/oss/' + key, '/api/oss/' + key]) {
			expect((await request(path)).status).toBe(401);
			expect((await request(path, { token: stranger })).status).toBe(404);
			const response = await request(path, { cookie: `${ASSET_COOKIE}=${owner}` });
			expect(response.status).toBe(200);
			expect(response.headers.get('cache-control')).toBe('private, no-store');
			expect(response.headers.get('content-security-policy')).toBe('sandbox');
			expect(await response.text()).toBe('private attachment');
		}
		await env.kv.delete('auth-uid:2');
		expect((await request('/' + key, { cookie: `${ASSET_COOKIE}=${owner}` })).status).toBe(401);
	});
	it('rejects shared tokens, normal users and API cookie authentication', async () => {
		const normal = await session(2, 'normal@example.test');
		const admin = await session();
		for (const path of ['/api/public/emailList', '/api/public/addUser', '/api/public/genToken']) {
			for (const token of [undefined, 'old-shared-token']) expect((await request(path, { token, body: {} })).status).toBe(401);
			expect((await request(path, { token: normal, body: {} })).status).toBe(403);
			expect((await request(path, { cookie: `${ASSET_COOKIE}=${admin}`, body: {} })).status).toBe(401);
		}
		expect((await request('/api/public/emailList', { token: admin, body: { size: 1 } })).status).toBe(200);
	});
	it('rejects all pre-incident sessions and disables initialization', async () => {
		const old = await session(2, 'owner@example.test', 1);
		expect((await request('/' + key, { token: old })).status).toBe(401);
		for (const candidate of ['wrong', bindings.jwt_secret]) expect((await request('/api/init/' + candidate)).status).toBe(404);
	});
	it('enforces IP/account limits and fails closed without the binding', async () => {
		bindings.AUTH_RATE_LIMITER.limit = async () => ({ success: false });
		expect((await request('/api/login', { body: { email: 'a@example.test', password } })).status).toBe(429);
		delete bindings.AUTH_RATE_LIMITER;
		expect((await request('/api/login', { body: {} })).status).toBe(503);
	});
	it('limits a distributed attack on one account independently of IP', async () => {
		bindings.AUTH_RATE_LIMITER.limit = async ({ key }) => ({ success: !key.startsWith('account:') });
		expect((await request('/api/login', { body: { email: 'a@example.test', password } })).status).toBe(429);
	});
});

describe('database writes and credential migration', () => {
	it('stores apostrophes and SQL-looking text literally using D1 bindings', async () => {
		const token = await session();
		const email = "a'||'b@example.test";
		const response = await request('/api/public/addUser', { token, body: { list: [{ email, password }] }, headers: { 'CF-Connecting-IP': "x'", 'User-Agent': "Mozilla/5.0 ' test" } });
		expect(response.status).toBe(200);
		expect((await response.json()).code).toBe(200);
		const user = await env.db.prepare('SELECT * FROM user WHERE email=?').bind(email).first();
		const account = await env.db.prepare('SELECT * FROM account WHERE email=?').bind(email).first();
		expect(user.email).toBe(email);
		expect(account.user_id).toBe(user.user_id);
		expect(user.password).toMatch(/^pbkdf2-sha256\$100000\$/);
		expect(await passwords.verifyPassword(password, user.salt, user.password)).toBe(true);
	});
	it('upgrades a legacy login and keeps passwords, salts and raw session IDs out of KV', async () => {
		const salt = 'AAAAAAAAAAAAAAAAAAAAAA==';
		const legacy = btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(salt + password)))));
		await env.db.prepare('INSERT INTO user(user_id,email,password,salt) VALUES(2,?,?,?)').bind('owner@example.test', legacy, salt).run();
		const response = await request('/api/login', { body: { email: 'owner@example.test', password } });
		expect(response.status).toBe(200);
		const value = await response.json();
		const payload = await jwt.verifyToken({ env: bindings }, value.data.token);
		const user = await env.db.prepare('SELECT * FROM user WHERE user_id=2').first();
		const cached = await env.kv.get('auth-uid:2', 'json');
		expect(user.password).toMatch(/^pbkdf2-sha256\$100000\$/);
		expect(cached.user).not.toHaveProperty('password');
		expect(cached.user).not.toHaveProperty('salt');
		expect(cached.tokens).toEqual([await sessionHash(payload.token)]);
		expect(payload.gen).toBe(2);
		expect(payload.exp).toBeGreaterThan(payload.iat);
		const cookie = response.headers.get('set-cookie');
		for (const flag of ['HttpOnly', 'Secure', 'SameSite=Strict']) expect(cookie).toContain(flag);
		expect((await request('/' + key, { cookie: cookie.split(';')[0] })).status).toBe(200);
		expect((await request('/api/logout', { token: value.data.token, method: 'DELETE' })).status).toBe(200);
		expect((await request('/' + key, { cookie: cookie.split(';')[0] })).status).toBe(401);
	});
	it('checks new hashes, rejects wrong passwords and malformed formats', async () => {
		const { hash, salt } = await passwords.hashPassword(password);
		expect(await passwords.verifyPassword(password, salt, hash)).toBe(true);
		expect(await passwords.verifyPassword('wrong', salt, hash)).toBe(false);
		expect(await passwords.verifyPassword(password, salt, 'pbkdf2-sha256$999999999$x')).toBe(false);
		expect(passwords.genRandomPwd()).toHaveLength(20);
		expect(validNewPassword('short')).toBe(false);
		expect(validNewPassword(password)).toBe(true);
		expect(validNewPassword('x'.repeat(129))).toBe(false);
	});
	it('revokes every active session when the password changes', async () => {
		const owner = await session(2, 'owner@example.test');
		await env.db.prepare('INSERT INTO user(user_id,email,password,salt) VALUES(2,?,?,?)').bind('owner@example.test', 'unused-fixture', 'unused').run();
		await userService.resetPassword({ env: bindings }, { password }, 2);
		expect(await env.kv.get('auth-uid:2')).toBeNull();
		expect((await request('/' + key, { token: owner })).status).toBe(401);
	});
	it('does not expose password hashes or salts even to an authenticated user administrator', async () => {
		await env.db.prepare('INSERT INTO user(user_id,email,password,salt) VALUES(1,?,?,?)').bind('admin@example.test', 'sensitive-hash-fixture', 'sensitive-salt-fixture').run();
		const response = await request('/api/user/list', { token: await session() });
		expect(response.status).toBe(200);
		const body = await response.json();
		expect(body.code).toBe(200);
		expect(body.data.list).toHaveLength(1);
		expect(body.data.list[0]).not.toHaveProperty('password');
		expect(body.data.list[0]).not.toHaveProperty('salt');
	});
	it('ignores compromised KV keys and uses only the Worker sending Secret', async () => {
		const values = new Map();
		const context = { env: bindings, get: name => values.get(name), set: (name, value) => values.set(name, value) };
		expect((await settingService.query(context)).resendTokens).toEqual({});
		values.clear();
		bindings.RESEND_TOKENS = JSON.stringify({ 'example.test': 'new-test-only-fixture' });
		expect((await settingService.query(context)).resendTokens).toEqual({ 'example.test': 'new-test-only-fixture' });
		expect((await env.kv.get('setting:')).includes('new-test-only-fixture')).toBe(false);
	});
});

describe('Resend webhook trust boundary', () => {
	const body = { type: 'email.delivered', data: { email_id: 'known-email' } };
	it('rejects unsigned, tampered, stale and future messages before writing', async () => {
		const raw = JSON.stringify(body);
		const good = await signed(raw);
		for (const headers of [{}, { ...good, 'svix-signature': 'v1,invalid' }, await signed(raw, { timestamp: Math.floor(Date.now() / 1000) - 301 }), await signed(raw, { timestamp: Math.floor(Date.now() / 1000) + 301 })]) {
			expect((await request('/api/webhooks', { body, headers })).status).toBe(401);
		}
		expect((await request('/api/webhooks', { body: { ...body, type: 'email.failed' }, headers: good })).status).toBe(401);
		expect((await env.db.prepare('SELECT status FROM email WHERE email_id=1').first()).status).toBe(0);
	});
	it('accepts a valid signed update, handles unknown IDs and ignores unknown events', async () => {
		const response = await request('/api/webhooks', { body, headers: await signed(JSON.stringify(body)) });
		expect(response.status).toBe(200);
		expect((await env.db.prepare('SELECT status FROM email WHERE email_id=1').first()).status).not.toBe(0);
		for (const value of [{ ...body, data: { email_id: 'unknown-email' } }, { ...body, type: 'unrelated.event' }]) {
			expect((await request('/api/webhooks', { body: value, headers: await signed(JSON.stringify(value)) })).status).toBe(200);
		}
	});
	it('rejects missing configuration and malformed signed payloads', async () => {
		delete bindings.RESEND_WEBHOOK_SECRET;
		expect((await request('/api/webhooks', { body })).status).toBe(503);
		bindings.RESEND_WEBHOOK_SECRET = webhookSecret;
		const invalid = { type: 'email.failed', data: { email_id: 'known-email' } };
		expect((await request('/api/webhooks', { body: invalid, headers: await signed(JSON.stringify(invalid)) })).status).toBe(400);
		expect((await request('/api/webhooks', { body: { padding: 'x'.repeat(65536) } })).status).toBe(413);
	});
	it('never reflects internal SQL or provider errors', async () => {
		const response = await request('/api/login-diagnostic-fixture', { token: await session() });
		expect(response.status).toBe(500);
		expect(await response.text()).not.toMatch(/SQLITE|bindings|sensitive/);
	});
});
