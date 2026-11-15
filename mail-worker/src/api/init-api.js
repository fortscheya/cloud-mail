import app from '../hono/hono';

// Existing deployment is initialized. Never use a credential as a URL parameter.
app.get('/init/:secret', (c) => c.notFound());
