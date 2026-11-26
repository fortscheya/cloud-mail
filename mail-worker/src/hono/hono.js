import { Hono } from 'hono';
const app = new Hono();

import result from '../model/result';
import { cors } from 'hono/cors';

app.use('*', cors());

app.onError((err, c) => {
	if (err.name === 'BizError') {
		console.log(err.message);
	} else {
		// Never return SQL statements, bindings or provider errors to the caller.
		// Keep code locations for production diagnosis without logging the error
		// message, request values, query strings or credentials.
		const locations = String(err.stack || '').split('\n').slice(1)
			.map(line => line.match(/\b[\w-]+\.(?:m?js|ts):\d+:\d+\b/)?.[0])
			.filter(Boolean).slice(0, 6);
		console.error('Unhandled application error', err.name, { locations, mailSendStage: c.get('mailSendStage') });
		return c.json(result.fail('Internal server error', 500), 500);
	}

	const status = [400, 401, 403, 404, 429, 503].includes(err.code) ? err.code : 200;
	return c.json(result.fail(err.message, err.code), status);
});

export default app;


