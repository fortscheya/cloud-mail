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
import { dbInit } from '../src/init/init';
import replyToMigration from '../migrations/0001_add_email_reply_to.sql?raw';
import archiveMigration from '../migrations/0002_add_raw_email_archive.sql?raw';
import rawEmailService from '../src/service/raw-email-service';
import r2Service from '../src/service/r2-service';
import s3Service from '../src/service/s3-service';
import emailService from '../src/service/email-service';
import PostalMime from 'postal-mime';
import { getReplyRecipients, normalizeMailboxes } from '../../shared/mail-addresses.js';

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
CREATE TABLE attachments (att_id INTEGER PRIMARY KEY,user_id INTEGER,email_id INTEGER,account_id INTEGER,key TEXT,filename TEXT,mime_type TEXT,size INTEGER,status INTEGER DEFAULT 0,type INTEGER DEFAULT 0,disposition TEXT,related TEXT,content_id TEXT,encoding TEXT,create_time TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE star (star_id INTEGER PRIMARY KEY,user_id INTEGER,email_id INTEGER,create_time TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE email (email_id INTEGER PRIMARY KEY,send_email TEXT,name TEXT,sender_email TEXT DEFAULT '',account_id INTEGER,user_id INTEGER,subject TEXT,code TEXT DEFAULT '',text TEXT,content TEXT,cc TEXT DEFAULT '[]',bcc TEXT DEFAULT '[]',recipient TEXT DEFAULT '[]',to_email TEXT DEFAULT '',to_name TEXT DEFAULT '',in_reply_to TEXT DEFAULT '',relation TEXT DEFAULT '',message_id TEXT DEFAULT '',type INTEGER DEFAULT 0,status INTEGER DEFAULT 0,resend_email_id TEXT,message TEXT,unread INTEGER DEFAULT 0,create_time TEXT DEFAULT CURRENT_TIMESTAMP,is_del INTEGER DEFAULT 0);
INSERT INTO role(role_id,name,is_default) VALUES(1,'default',1);
INSERT INTO email(email_id,user_id,account_id,resend_email_id,status) VALUES(1,2,1,'known-email',0);
`);
	await env.db.exec(replyToMigration);
	await env.db.exec(archiveMigration);
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

describe('Original email archives', () => {
	const source = ['Received: from original.test by routing.test;', '\tThu, 26 Nov 2026 08:00:00 +0000',
		'From: Sender <sender@other.test>', 'To: owner@example.test', 'Reply-To: Reply Desk <reply@other.test>',
		'Subject: Original MIME fixture', 'X-Preserve-This: Case AND spaces  ', 'MIME-Version: 1.0',
		'Content-Type: multipart/mixed; boundary="raw-fixture"', '', '--raw-fixture',
		'Content-Type: text/plain; charset=utf-8', '', '原始正文', '--raw-fixture',
		'Content-Type: application/octet-stream', 'Content-Disposition: attachment; filename="binary.bin"',
		'Content-Transfer-Encoding: base64', '', 'AP+ADQo=', '--raw-fixture--', ''].join('\r\n');
	const sourceBytes = new TextEncoder().encode(source);
	beforeEach(async () => {
		await env.db.exec(`
INSERT INTO user(user_id,email,password,salt) VALUES(1,'admin@example.test','unused','unused'),(2,'owner@example.test','unused','unused'),(3,'other@example.test','unused','unused');
INSERT INTO account(account_id,user_id,email,name) VALUES(1,1,'admin@example.test','Admin'),(2,2,'owner@example.test','Owner'),(3,3,'other@example.test','Other');
INSERT INTO perm(perm_id,perm_key) VALUES(1,'email:send'),(2,'email:delete');
INSERT INTO role_perm(id,role_id,perm_id) VALUES(1,1,1),(2,1,2);
`);
	});
	async function receive(to = 'owner@example.test', raw = sourceBytes) {
		const message = { from: 'bounce@transport.test', to, raw: new Response(raw).body, setReject: vi.fn() };
		await worker.email(message, bindings, {});
		expect(message.setReject).not.toHaveBeenCalled();
		return env.db.prepare('SELECT email_id,raw_key,raw_storage FROM email WHERE raw_key != ? ORDER BY email_id DESC LIMIT 1').bind('').first();
	}
	async function download(id, token = undefined) { return request('/api/email/raw?emailId=' + id, { token }); }

	it('keeps existing records and supports repeated initialization after the archive migration', async () => {
		await dbInit.v3_6DB({ env: bindings });
		await dbInit.v3_6DB({ env: bindings });
		expect(await env.db.prepare('SELECT resend_email_id,raw_key,raw_storage FROM email WHERE email_id=1').first())
			.toEqual({ resend_email_id: 'known-email', raw_key: '', raw_storage: '' });
	});
	it('stores and downloads exact original bytes including headers, Reply-To and attachments', async () => {
		const row = await receive();
		expect(row.raw_storage).toBe('KV');
		const response = await download(row.email_id, await session(2, 'owner@example.test'));
		expect(response.status).toBe(200);
		expect(new Uint8Array(await response.arrayBuffer())).toEqual(sourceBytes);
		expect(response.headers.get('content-type')).toBe('message/rfc822');
		expect(response.headers.get('content-disposition')).toBe(`attachment; filename="email-${row.email_id}.eml"`);
		expect(response.headers.get('cache-control')).toBe('private, no-store');
		expect(response.headers.get('x-content-type-options')).toBe('nosniff');
		expect(response.headers.get('content-security-policy')).toBe('sandbox');
		const list = (await (await request('/api/email/list?type=0&accountId=2&allReceive=1&size=10&full=0', { token: await session(2, 'owner@example.test') })).json()).data;
		expect(list.list[0].hasRaw).toBe(1);
		expect(list.list[0]).not.toHaveProperty('rawKey');
		const full = (await (await request('/api/email/list?type=0&accountId=2&allReceive=1&size=10&full=1', { token: await session(2, 'owner@example.test') })).json()).data;
		expect(full.list[0].hasRaw).toBe(1);
		expect(full.list[0]).not.toHaveProperty('rawKey');
		expect(full.list[0]).not.toHaveProperty('rawStorage');
	});
	it('allows only the owner or administrator and blocks direct object aliases and revoked sessions', async () => {
		const row = await receive();
		const owner = await session(2, 'owner@example.test');
		expect((await download(row.email_id, await session())).status).toBe(200);
		expect((await download(row.email_id)).status).toBe(401);
		expect((await download(row.email_id, await session(3, 'other@example.test'))).status).toBe(404);
		expect((await request('/api/email/raw?emailId=' + row.email_id, { cookie: `${ASSET_COOKIE}=${owner}` })).status).toBe(401);
		for (const alias of ['/oss/', '/api/oss/']) expect((await request(alias + row.raw_key, { token: owner })).status).toBe(404);
		await env.kv.delete('auth-uid:2');
		expect((await download(row.email_id, owner)).status).toBe(401);
	});
	it('makes unregistered-recipient archives available only to the administrator', async () => {
		const row = await receive('unregistered@example.test');
		expect((await download(row.email_id, await session())).status).toBe(200);
		expect((await download(row.email_id, await session(2, 'owner@example.test'))).status).toBe(404);
	});
	it('returns an unavailable result for old messages, invalid IDs and missing objects', async () => {
		const owner = await session(2, 'owner@example.test');
		for (const id of [1, -1, 'invalid', '1 OR 1=1']) expect((await download(encodeURIComponent(id), owner)).status).toBe(404);
		const row = await receive();
		await env.kv.delete(row.raw_key);
		expect((await download(row.email_id, owner)).status).toBe(404);
	});
	it('keeps logical deletions but cleans up only the permanently deleted message archive', async () => {
		const first = await receive();
		const second = await receive('other@example.test');
		await emailService.delete({ env: bindings }, { emailIds: String(first.email_id) }, 2);
		expect(await env.kv.get(first.raw_key)).not.toBeNull();
		await emailService.physicsDelete({ env: bindings }, { emailIds: String(first.email_id) });
		expect(await env.kv.get(first.raw_key)).toBeNull();
		expect(await env.kv.get(second.raw_key)).not.toBeNull();
	});
	it.each(['user', 'account', 'batch', 'autoClean'])('cleans up archives with the existing %s deletion path', async mode => {
		const row = await receive();
		const c = { env: bindings };
		if (mode === 'user') await emailService.physicsDeleteUserIds(c, [2]);
		if (mode === 'account') await emailService.physicsDeleteByAccountId(c, 2);
		if (mode === 'batch') await emailService.batchDelete(c, { subject: 'Original MIME fixture' });
		if (mode === 'autoClean') {
			const settings = await env.kv.get('setting:', 'json');
			await env.kv.put('setting:', JSON.stringify({ ...settings, autoCleanDays: 1 }));
			await env.db.prepare("UPDATE email SET create_time='2000-01-01 00:00:00'").run();
			await emailService.autoClean(c);
		}
		expect(await env.kv.get(row.raw_key)).toBeNull();
	});
	it('does not accept a mail record when archiving fails and removes archives after failed database inserts', async () => {
		const put = vi.spyOn(r2Service, 'putObj').mockRejectedValue(new Error('archive unavailable'));
		try { await expect(receive()).rejects.toThrow('archive unavailable'); } finally { put.mockRestore(); }
		expect(await env.db.prepare('SELECT count(*) AS n FROM email').first()).toEqual({ n: 1 });
		await expect(rawEmailService.insert({ env: bindings }, { emailId: 1, userId: 2, accountId: 2 }, sourceBytes)).rejects.toThrow();
		expect((await env.kv.list({ prefix: 'raw-emails/' })).keys).toEqual([]);
	});
	it('stores actual station-internal delivery MIME with correct sender, recipient, body and attachment', async () => {
		const response = await request('/api/email/send', { token: await session(), body: {
			accountId: 1, receiveEmail: ['owner@example.test'], subject: 'Internal MIME', text: '内文', content: '<p>内文</p>',
			attachments: [{ content: btoa('attachment'), filename: 'note.txt', type: 'text/plain' }]
		} });
		expect((await response.json()).code).toBe(200);
		const row = await env.db.prepare('SELECT email_id FROM email WHERE user_id=2 AND raw_key != ? ORDER BY email_id DESC LIMIT 1').bind('').first();
		const original = await download(row.email_id, await session(2, 'owner@example.test'));
		const parsed = await PostalMime.parse(await original.arrayBuffer());
		expect(parsed.from.address).toBe('admin@example.test');
		expect(parsed.to.map(item => item.address)).toEqual(['owner@example.test']);
		expect(parsed.text.trim()).toBe('内文');
		expect(new TextDecoder().decode(parsed.attachments[0].content)).toBe('attachment');
	});
	it('reads pinned R2 archives even when the preferred storage type changes', async () => {
		bindings.r2 = env.archiveBucket;
		const row = await receive();
		expect(row.raw_storage).toBe('R2');
		const type = vi.spyOn(r2Service, 'storageType').mockResolvedValue('KV');
		try {
			expect(new Uint8Array(await (await download(row.email_id, await session())).arrayBuffer())).toEqual(sourceBytes);
			await emailService.physicsDelete({ env: bindings }, { emailIds: String(row.email_id) });
			expect(await env.archiveBucket.get(row.raw_key)).toBeNull();
		} finally { type.mockRestore(); }
	});
	it('uses the existing S3 backend without exposing a bucket URL', async () => {
		const settings = await env.kv.get('setting:', 'json');
		await env.kv.put('setting:', JSON.stringify({ ...settings, bucket: 'fixture-bucket', endpoint: 'https://storage.example.test', s3AccessKey: 'fixture-access', s3SecretKey: 'fixture-secret' }));
		const objects = new Map();
		const put = vi.spyOn(s3Service, 'putObj').mockImplementation(async (c, key, bytes) => objects.set(key, bytes));
		const get = vi.spyOn(s3Service, 'getObj').mockImplementation(async (c, key) => objects.has(key) ? new Response(objects.get(key)) : null);
		const del = vi.spyOn(s3Service, 'deleteObj').mockImplementation(async (c, keys) => keys.forEach(key => objects.delete(key)));
		try {
			const row = await receive();
			expect(row.raw_storage).toBe('S3');
			expect(new Uint8Array(await (await download(row.email_id, await session())).arrayBuffer())).toEqual(sourceBytes);
			await emailService.physicsDelete({ env: bindings }, { emailIds: String(row.email_id) });
			expect(objects.size).toBe(0);
		} finally { put.mockRestore(); get.mockRestore(); del.mockRestore(); }
	});
});

describe('Reply-To preservation and reply recipients', () => {
	beforeEach(async () => {
		await env.db.exec(`
INSERT INTO user(user_id,email,password,salt) VALUES(1,'admin@example.test','unused','unused');
INSERT INTO account(account_id,user_id,email,name) VALUES(1,1,'admin@example.test','Admin');
`);
	});

	async function receive(headers, { splitBytes = false } = {}) {
		const raw = ['From: News <news@sender.test>', 'To: admin@example.test', 'Subject: Reply target fixture',
			'Message-ID: <original@sender.test>', ...headers, 'Content-Type: text/plain; charset=utf-8', '', 'Body'].join('\r\n');
		const bytes = new TextEncoder().encode(raw);
		const message = { from: 'bounce@transport.test', to: 'admin@example.test', setReject: vi.fn(),
			raw: splitBytes ? new ReadableStream({ start(controller) {
				for (const byte of bytes) controller.enqueue(new Uint8Array([byte]));
				controller.close();
			} }) : new Response(bytes).body };
		await worker.email(message, bindings, {});
		expect(message.setReject).not.toHaveBeenCalled();
		const token = await session();
		const data = (await (await request('/api/email/list?accountId=1&allReceive=1&type=0&size=10&full=1', { token })).json()).data;
		return data.list[0];
	}

	it('migrates existing mail without losing data and keeps initialization idempotent', async () => {
		expect(await env.db.prepare('SELECT resend_email_id,reply_to FROM email WHERE email_id=1').first())
			.toEqual({ resend_email_id: 'known-email', reply_to: '[]' });
		await dbInit.v3_5DB({ env: bindings });
		await dbInit.v3_5DB({ env: bindings });
		expect(await env.db.prepare('SELECT count(*) AS n FROM email').first()).toEqual({ n: 1 });
	});
	it('persists folded, named, grouped and multiple Reply-To addresses in both list modes', async () => {
		const received = await receive(['Reply-To: Help: "Desk, Team" <desk@help.test>,', '\tbackup@help.test, desk@HELP.TEST;']);
		expect(JSON.parse(received.replyTo)).toEqual([{ address: 'desk@help.test', name: 'Desk, Team' }, { address: 'backup@help.test', name: '' }]);
		expect(getReplyRecipients(received, 1)).toEqual(['desk@help.test', 'backup@help.test']);
		expect(received.sendEmail).toBe('news@sender.test');
		expect(received.senderEmail).toBe('bounce@transport.test');
		const data = (await (await request('/api/email/list?accountId=1&allReceive=1&type=0&size=10&full=0', { token: await session() })).json()).data;
		expect(data.list[0].replyTo).toBe(received.replyTo);
		expect(getReplyRecipients(data.list[0], 1)).toEqual(['desk@help.test', 'backup@help.test']);
	});
	it('preserves UTF-8 Reply-To across stream chunk boundaries', async () => {
		const received = await receive(['Reply-To: 回信 <用户@reply.test>'], { splitBytes: true });
		expect(JSON.parse(received.replyTo)).toEqual([{ address: '用户@reply.test', name: '回信' }]);
		expect(getReplyRecipients(received, 1)).toEqual(['用户@reply.test']);
	});
	it.each([{ headers: [] }, { headers: ['Reply-To: invalid-address'] }])('falls back to header From when Reply-To is missing or unusable: %j', async ({ headers }) => {
		const received = await receive(headers);
		expect(received.replyTo).toBe('[]');
		expect(getReplyRecipients(received, 1)).toEqual(['news@sender.test']);
	});
	it('uses usable Reply-To entries and rejects malformed addresses without throwing on legacy values', () => {
		const received = { type: 0, userId: 1, sendEmail: 'news@sender.test',
			replyTo: JSON.stringify([{ address: 'broken' }, { address: 'good@reply.test' }, { address: 'bad\r\nBcc:x@reply.test' }, { address: 'bad\u0001@reply.test' }]) };
		expect(getReplyRecipients(received, 1)).toEqual(['good@reply.test']);
		for (const replyTo of [undefined, null, '', '[]', 'null', 'malformed JSON', '[{"name":"No address"}]']) {
			expect(getReplyRecipients({ ...received, replyTo }, 1)).toEqual(['news@sender.test']);
		}
		expect(getReplyRecipients({ ...received, replyTo: '[]', sendEmail: '' }, 1)).toEqual([]);
	});
	it('keeps original To for own sent mail and honors Reply-To when an admin views another member’s sent mail', () => {
		const sent = { type: 1, userId: 2, sendEmail: 'member@example.test', replyTo: '[{"address":"support@reply.test"}]',
			recipient: '[{"name":"Customer, One","address":"customer@other.test"},{"address":"second@other.test"},{"address":"customer@OTHER.TEST"}]' };
		expect(getReplyRecipients(sent, 2)).toEqual(['customer@other.test', 'second@other.test']);
		expect(getReplyRecipients(sent, 1)).toEqual(['support@reply.test']);
	});
	it('supports quoted local parts and international domains without splitting display names into recipients', () => {
		expect(normalizeMailboxes([{ name: 'Desk, One', address: '"desk,one"@example.test' }, { address: 'user@例子.中国' }]))
			.toEqual([{ name: 'Desk, One', address: '"desk,one"@example.test' }, { name: '', address: 'user@xn--fsqu00a.xn--fiqs8s' }]);
		expect(getReplyRecipients({ type: 0, replyTo: [{ address: 'Case@example.test' }, { address: 'case@EXAMPLE.TEST' }] }, 1))
			.toEqual(['Case@example.test', 'case@example.test']);
	});
});

describe('Administrator sending and sent-mail visibility', () => {
	beforeEach(async () => {
		await env.db.exec(`
INSERT INTO user(user_id,email,password,salt) VALUES(1,'admin@example.test','unused','unused'),(2,'member@example.test','unused','unused');
INSERT INTO account(account_id,user_id,email,name) VALUES(1,1,'admin@example.test','Admin'),(2,2,'member@example.test','Member');
INSERT INTO perm(perm_id,perm_key) VALUES(1,'email:send'),(2,'email:delete');
INSERT INTO role_perm(id,role_id,perm_id) VALUES(1,1,1),(2,1,2);
INSERT INTO email(email_id,user_id,account_id,send_email,name,subject,text,type) VALUES(10,1,1,'admin@example.test','Admin','Admin sent','admin message',1),(11,2,2,'member@example.test','Member','Member sent','member message',1);
`);
	});
	const form = (extra = {}) => ({ accountId: 1, fromEmail: 'unregistered@example.test',
		receiveEmail: ['outside@other.test'], content: '<p>message</p>', text: 'message', subject: 'Custom sender', ...extra });

	it('lists only configured site sending domains for administrators without exposing keys', async () => {
		bindings.domain = ['example.test', 'receiving.test'];
		bindings.RESEND_TOKENS = JSON.stringify({ 'example.test': 'fixture-key', 'outside.test': 'outside-key' });
		const response = await request('/api/email/senderDomains', { token: await session() });
		expect((await response.json()).data).toEqual(['example.test']);
		expect((await request('/api/email/senderDomains', { token: await session(2, 'member@example.test') })).status).toBe(403);
		expect((await request('/api/email/senderDomains')).status).toBe(401);
	});
	it('sends an unregistered address through the CF channel and retains administrator and attachment ownership', async () => {
		bindings.email = { send: vi.fn().mockResolvedValue({ messageId: 'cf-custom' }) };
		const response = await request('/api/email/send', { token: await session(), body: form({ accountId: 2,
			attachments: [{ content: btoa('attachment'), filename: 'note.txt', type: 'text/plain' }] }) });
		const body = await response.json();
		expect(body.code).toBe(200);
		expect(bindings.email.send.mock.calls[0][0].from.email).toBe('unregistered@example.test');
		const saved = body.data[0];
		expect(saved).toMatchObject({ userId: 1, accountId: 1, sendEmail: 'unregistered@example.test' });
		expect(saved.attList[0]).toMatchObject({ userId: 1, accountId: 1, emailId: saved.emailId });
		expect(await env.db.prepare('SELECT count(*) AS n FROM account').first()).toEqual({ n: 2 });
		expect((await request('/' + saved.attList[0].key, { token: await session() })).status).toBe(200);
		expect((await request('/' + saved.attList[0].key, { token: await session(2, 'member@example.test') })).status).toBe(404);
	});
	it('uses the selected Resend domain and actual From without registering a mailbox', async () => {
		bindings.RESEND_TOKENS = JSON.stringify({ 'example.test': 'fixture-key' });
		const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ id: 'resend-custom' }), { headers: { 'Content-Type': 'application/json' } }));
		try {
			const response = await request('/api/email/send', { token: await session(), body: form({ name: 'Notice' }) });
			expect((await response.json()).data[0]).toMatchObject({ sendEmail: 'unregistered@example.test', userId: 1, accountId: 1 });
			expect(JSON.parse(fetch.mock.calls[0][1].body).from).toBe('Notice <unregistered@example.test>');
			expect(await env.db.prepare('SELECT count(*) AS n FROM account').first()).toEqual({ n: 2 });
		} finally { fetch.mockRestore(); }
	});
	it('rejects member custom senders even with a valid owned account', async () => {
		bindings.email = { send: vi.fn() };
		const response = await request('/api/email/send', { token: await session(2, 'member@example.test'), body: form({ accountId: 2 }) });
		expect(response.status).toBe(403);
		expect(bindings.email.send).not.toHaveBeenCalled();
	});
	it.each(['.bad@example.test', 'bad..dots@example.test', 'a\r\nBcc:x@example.test', 'a'.repeat(65) + '@example.test', ''])('rejects malformed custom address %j before sending', async fromEmail => {
		bindings.email = { send: vi.fn() };
		expect((await request('/api/email/send', { token: await session(), body: form({ fromEmail }) })).status).toBe(400);
		expect(bindings.email.send).not.toHaveBeenCalled();
	});
	it('rejects external sender domains and site domains lacking a sending channel', async () => {
		bindings.email = { send: vi.fn() };
		expect((await request('/api/email/send', { token: await session(), body: form({ fromEmail: 'notice@gmail.com' }) })).status).toBe(403);
		expect(bindings.email.send).not.toHaveBeenCalled();
		delete bindings.email;
		expect((await request('/api/email/send', { token: await session(), body: form() })).status).toBe(503);
	});
	it('keeps the original sender ownership check when no custom sender is requested', async () => {
		const body = form({ accountId: 2 });
		delete body.fromEmail;
		const response = await request('/api/email/send', { token: await session(), body });
		expect((await response.json()).message).toContain('发件人邮箱非当前用户所有');
	});
	it('shows all members in administrator sent mail with pagination, search and full details', async () => {
		const token = await session();
		const query = '/api/email/list?type=1&accountId=1&allReceive=0&size=1';
		const first = (await (await request(query + '&full=0', { token })).json()).data;
		expect(first.total).toBe(2);
		expect(first.list[0]).toMatchObject({ emailId: 11, userId: 2, userEmail: 'member@example.test', sendEmail: 'member@example.test' });
		expect(first.list[0]).not.toHaveProperty('content');
		const next = (await (await request(query + '&full=1&emailId=11', { token })).json()).data;
		expect(next.total).toBe(2);
		expect(next.list[0]).toMatchObject({ emailId: 10, text: 'admin message' });
		const search = (await (await request(query + '&full=1&searchType=senderAddress&text=member', { token })).json()).data;
		expect(search.total).toBe(1);
		expect(search.list.map(item => item.emailId)).toEqual([11]);
	});
	it('does not widen member sent mail or administrator inbox scope', async () => {
		const member = await session(2, 'member@example.test');
		const result = (await (await request('/api/email/list?type=1&accountId=1&allReceive=1&allSenders=1&size=50&full=1', { token: member })).json()).data;
		expect(result.list.map(item => item.emailId)).toEqual([11]);
		const inbox = (await (await request('/api/email/list?type=0&accountId=1&allReceive=1&size=50&full=1', { token: await session() })).json()).data;
		expect(inbox.list).toEqual([]);
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
