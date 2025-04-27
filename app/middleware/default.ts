import { Context } from 'hono';
import { Hono } from 'hono';
// import { etag } from 'hono/etag';
import { cors } from 'hono/cors';
import { secureHeaders } from 'hono/secure-headers';

const app = new Hono();

// Security headers
app.use(
  '*',
  secureHeaders({
    xXssProtection: '1; mode=block',
  })
);

// Cors mode
app.use('*', cors());

// Cache code
// app.use('*', etag());

app.use('*', async (c: Context, next) => {
  // X-Response-Time header
  const start = Date.now();
  await next();
  const ms = Date.now() - start;

  c.header('X-Response-Time', `${ms}ms`);
});

export default app;
