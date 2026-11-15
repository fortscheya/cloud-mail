const encoder = new TextEncoder();
// Cloudflare Workers WebCrypto accepts at most 100,000 PBKDF2 iterations.
// Version the stored hash so future cost/algorithm migrations remain possible.
const ITERATIONS = 100000;
const PREFIX = `pbkdf2-sha256$${ITERATIONS}$`;

export function validNewPassword(value) {
	return typeof value === 'string' && value.length >= 12 && value.length <= 128;
}

function equal(a, b) {
	if (a.length !== b.length) return false;
	let difference = 0;
	for (let i = 0; i < a.length; i++) difference |= a.charCodeAt(i) ^ b.charCodeAt(i);
	return difference === 0;
}

const saltHashUtils = {

	generateSalt(length = 16) {
		const array = new Uint8Array(length);
		crypto.getRandomValues(array);
		return btoa(String.fromCharCode(...array));
	},


	async hashPassword(password) {
		const salt = this.generateSalt();
		const hash = await this.genHashPassword(password, salt);
		return { salt, hash };
	},

	async genHashPassword(password, salt) {
		if (typeof password !== 'string' || password.length === 0 || password.length > 256) {
			throw new TypeError('Invalid password length');
		}
		const key = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
		const bits = await crypto.subtle.deriveBits({
			name: 'PBKDF2', hash: 'SHA-256', iterations: ITERATIONS,
			salt: Uint8Array.from(atob(salt), char => char.charCodeAt(0)),
		}, key, 256);
		return PREFIX + btoa(String.fromCharCode(...new Uint8Array(bits)));
	},

	async verifyPassword(inputPassword, salt, storedHash) {
		if (typeof inputPassword !== 'string' || !inputPassword || inputPassword.length > 256 || typeof storedHash !== 'string') return false;
		if (storedHash.startsWith(PREFIX)) {
			return equal(await this.genHashPassword(inputPassword, salt), storedHash);
		}
		// Read-only legacy support; successful password logins upgrade this record.
		if (!/^[A-Za-z0-9+/]{43}=$/.test(storedHash)) return false;
		const digest = await crypto.subtle.digest('SHA-256', encoder.encode(salt + inputPassword));
		return equal(btoa(String.fromCharCode(...new Uint8Array(digest))), storedHash);
	},
	needsRehash(storedHash) {
		return !storedHash?.startsWith(PREFIX);
	},

	genRandomPwd(length = 20) {
		const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
		let result = '';
		while (result.length < length) {
			const bytes = crypto.getRandomValues(new Uint8Array(length));
			for (const byte of bytes) {
				if (byte < 248 && result.length < length) result += chars[byte % chars.length];
			}
		}
		return result;
	}
};

export default saltHashUtils;
