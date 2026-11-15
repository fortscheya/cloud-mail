import { setCookie, deleteCookie } from 'hono/cookie';
import constant from '../const/constant';

export const ASSET_COOKIE = '__Host-cloudmail-assets';

export async function sessionHash(token) {
	const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token));
	return btoa(String.fromCharCode(...new Uint8Array(digest)));
}

export function safeUser(user) {
	const { password, salt, ...safe } = user;
	return safe;
}

export function setAssetSession(c, jwt) {
	setCookie(c, ASSET_COOKIE, jwt, {
		httpOnly: true, secure: true, sameSite: 'Strict', path: '/',
		maxAge: constant.TOKEN_EXPIRE,
	});
}

export function clearAssetSession(c) {
	deleteCookie(c, ASSET_COOKIE, { secure: true, path: '/' });
}
