import { describe, it, expect } from 'bun:test';
import { Hono, Context } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { ZodError } from 'zod';
import { check_json } from '@middleware/json';
import { resJSON, formatZodErrors } from '@app/helpers/function';
import { logger } from '@app/config/logging';

const app = new Hono();
const appNode = process.env.APP_ENV || 'development';

// Custom Not Found Message
app.notFound((c: Context) => {
  const resData = resJSON({ statusCode: 404, message: 'Page not found' });

  return c.json(resData, resData.status as 404);
});

// Error handling
app.onError(async (err, c: Context) => {
  const resData = resJSON({
    statusCode: 500,
    message: err?.message,
  });

  if (err instanceof HTTPException) {
    resData.status = err?.status;
  } else if (err instanceof ZodError) {
    resData.status = 400;
    resData.message = formatZodErrors(err?.errors);
  }

  if (appNode == 'production' && resData.status === 500) {
    logger.error(`${c.req.method} ${c.req.path} => ${err?.message}`);
    resData.message = 'Internal server error';
  }

  return c.json(resData, resData.status as 500);
});

app.post('/test-json', check_json, async (c: Context) => {
  const body = await c.req.json();

  return c.json({ received: body });
});

describe('Middleware check_json', () => {
  it('should pass when valid JSON is sent', async () => {
    const res = await app.request('/test-json', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'test', password: '1234' }),
    });

    const data = await res.json();

    expect(res.status).toBe(200);
    expect(data.received.username).toBe('test');
  });

  it('should return 400 on empty body', async () => {
    const res = await app.request('/test-json', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });

    const data = await res.json();

    expect(res.status).toBe(400);
    expect(data.message).toBe('Invalid or empty JSON body');
  });

  it('should return 400 on invalid JSON', async () => {
    const res = await app.request('/test-json', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{ invalid json }',
    });

    const data = await res.json();

    expect(res.status).toBe(400);
    expect(data.message).toBe('Invalid or empty JSON body');
  });
});
