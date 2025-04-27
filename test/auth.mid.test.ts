import { Context, Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { describe, it, expect, beforeAll, afterAll } from 'bun:test';
import { ZodError } from 'zod';
import { prismaClient } from '@app/config/database';
import bcrypt from 'bcryptjs';
import { sign } from 'hono/jwt';
import {
  APP_JWT_EXP,
  APP_JWT_SECRET,
  APP_SECRET_KEY,
} from '@app/config/setting';
import { is_admin, is_admin_or_key, is_login } from '@app/middleware/auth';
import { resJSON, formatZodErrors } from '@app/helpers/function';
import { logger } from '@app/config/logging';

const app = new Hono();

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

  if (process.env.APP_ENV == 'production' && resData.status === 500) {
    logger.error(`${c.req.method} ${c.req.path} => ${err?.message}`);
    resData.message = 'Internal server error';
  }

  return c.json(resData, resData.status as 500);
});

app.get('/auth/test-middleware-is-login', is_login, (c: Context) => {
  return c.json({ message: 'Middleware passed', user: c.get('userData') });
});

app.get('/auth/test-middleware-is-admin', is_admin, (c: Context) => {
  return c.json({ message: 'Middleware passed', user: c.get('userData') });
});

app.get(
  '/auth/test-middleware-is-admin-or-key',
  is_admin_or_key,
  (c: Context) => {
    return c.json({ message: 'Middleware passed', user: c.get('userData') });
  }
);

describe('Middleware is_login', () => {
  const username = 'user_test_middleware_is_login';
  const password = 'pass_test_middleware_is_login';
  let token: string;
  let userId: number;

  beforeAll(async () => {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await prismaClient.user.create({
      data: {
        username,
        password: hashedPassword,
        role: 'member',
        is_active: true,
      },
    });
    userId = user.id;

    token = await sign(
      {
        id: user.id,
        username: user.username,
        role: user.role,
        is_active: user.is_active,
        iat: Math.floor(Date.now() / 1000),
        exp: APP_JWT_EXP,
      },
      APP_JWT_SECRET,
      'HS256'
    );

    await prismaClient.auth.create({
      data: {
        user_id: user.id,
        token,
        ip_address: '127.0.0.1',
        user_agent: 'test-agent',
      },
    });
  });

  afterAll(async () => {
    await prismaClient.user.deleteMany({
      where: {
        username: {
          in: [
            username,
            'user_test_user_not_found_is_login',
            'user_test_token_no_active_is_login',
          ],
        },
      },
    });
  });

  it('should pass middleware and return user data', async () => {
    const res = await app.request('/auth/test-middleware-is-login', {
      method: 'GET',
      headers: { Authorization: `Bearer ${token}` },
    });

    const data = await res.json();

    expect(res.status).toBe(200);
    expect(data?.message).toBe('Middleware passed');
    expect(data?.user?.username).toBe(username);
  });

  it('should fail if token is missing', async () => {
    const res = await app.request('/auth/test-middleware-is-login', {
      method: 'GET',
    });

    const data = await res.json();

    expect(res.status).toBe(401);
    expect(data.message).toBe('Invalid token');
  });

  it('should fail if token is invalid', async () => {
    const res = await app.request('/auth/test-middleware-is-login', {
      method: 'GET',
      headers: { Authorization: 'Bearer wrongtoken' },
    });

    const data = await res.json();

    expect(res.status).toBe(401);
    expect(data.message).toBe('Invalid JWT token');
  });

  it('should fail if user not found', async () => {
    const tokenTest = await sign(
      {
        id: 999999999999,
        username: 'user_test_user_not_found_is_login',
        role: 'member',
        is_active: true,
        iat: Math.floor(Date.now() / 1000),
        exp: APP_JWT_EXP,
      },
      APP_JWT_SECRET,
      'HS256'
    );

    const res = await app.request('/auth/test-middleware-is-login', {
      method: 'GET',
      headers: { Authorization: `Bearer ${tokenTest}` },
    });

    const data = await res.json();

    expect(res.status).toBe(401);
    expect(data.message).toBe('User not found');
  });

  it('should fail if token is no longer active', async () => {
    const userTokenNoActive = await prismaClient.user.create({
      data: {
        username: 'user_test_token_no_active_is_login',
        password: await bcrypt.hash(password, 10),
        role: 'member',
        is_active: true,
      },
    });

    const newToken = await sign(
      {
        id: userTokenNoActive.id,
        username: userTokenNoActive.username,
        role: userTokenNoActive.role,
        is_active: userTokenNoActive.is_active,
        iat: Math.floor(Date.now() / 1000),
        exp: APP_JWT_EXP,
      },
      APP_JWT_SECRET,
      'HS256'
    );

    await prismaClient.auth.create({
      data: {
        user_id: userTokenNoActive.id,
        is_active: false,
        token: newToken,
      },
    });

    const res = await app.request('/auth/test-middleware-is-login', {
      method: 'GET',
      headers: { Authorization: `Bearer ${newToken}` },
    });

    const data = await res.json();

    expect(res.status).toBe(401);
    expect(data.message).toBe('Token is no longer active');
  });

  it('should fail if user is banned', async () => {
    await prismaClient.user.update({
      where: { id: userId },
      data: { role: 'banned' },
    });

    await prismaClient.auth.updateMany({
      where: { token },
      data: { is_active: true },
    });

    const res = await app.request('/auth/test-middleware-is-login', {
      method: 'GET',
      headers: { Authorization: `Bearer ${token}` },
    });

    const data = await res.json();

    expect(res.status).toBe(403);
    expect(data.message).toBe('User already banned');
  });

  it('should fail if user is not active', async () => {
    await prismaClient.user.update({
      where: { id: userId },
      data: { role: 'member', is_active: false },
    });

    const res = await app.request('/auth/test-middleware-is-login', {
      method: 'GET',
      headers: { Authorization: `Bearer ${token}` },
    });

    const data = await res.json();

    expect(res.status).toBe(401);
    expect(data.message).toBe('User not active');
  });
});

describe('Middleware is_admin', () => {
  const username = 'user_test_middleware_is_admin';
  const password = 'pass_test_middleware_is_admin';
  let token: string;
  let userId: number;

  beforeAll(async () => {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await prismaClient.user.create({
      data: {
        username,
        password: hashedPassword,
        role: 'admin',
        is_active: true,
      },
    });
    userId = user.id;

    token = await sign(
      {
        id: user.id,
        username: user.username,
        role: user.role,
        is_active: user.is_active,
        iat: Math.floor(Date.now() / 1000),
        exp: APP_JWT_EXP,
      },
      APP_JWT_SECRET,
      'HS256'
    );

    await prismaClient.auth.create({
      data: {
        user_id: user.id,
        token,
        ip_address: '127.0.0.1',
        user_agent: 'test-agent',
      },
    });
  });

  afterAll(async () => {
    await prismaClient.user.deleteMany({
      where: {
        username: {
          in: [
            username,
            'user_test_user_not_found_is_admin',
            'user_test_token_no_active_is_admin',
          ],
        },
      },
    });
  });

  it('should pass middleware and return user data', async () => {
    const res = await app.request('/auth/test-middleware-is-admin', {
      method: 'GET',
      headers: { Authorization: `Bearer ${token}` },
    });

    const data = await res.json();

    expect(res.status).toBe(200);
    expect(data?.message).toBe('Middleware passed');
    expect(data?.user?.username).toBe(username);
  });

  it('should fail if token is missing', async () => {
    const res = await app.request('/auth/test-middleware-is-admin', {
      method: 'GET',
    });

    const data = await res.json();

    expect(res.status).toBe(401);
    expect(data.message).toBe('Invalid token');
  });

  it('should fail if token is invalid', async () => {
    const res = await app.request('/auth/test-middleware-is-admin', {
      method: 'GET',
      headers: { Authorization: 'Bearer wrongtoken' },
    });

    const data = await res.json();

    expect(res.status).toBe(401);
    expect(data.message).toBe('Invalid JWT token');
  });

  it('should fail if user not found', async () => {
    const tokenTest = await sign(
      {
        id: 999999999999,
        username: 'user_test_user_not_found_is_admin',
        role: 'member',
        is_active: true,
        iat: Math.floor(Date.now() / 1000),
        exp: APP_JWT_EXP,
      },
      APP_JWT_SECRET,
      'HS256'
    );

    const res = await app.request('/auth/test-middleware-is-admin', {
      method: 'GET',
      headers: { Authorization: `Bearer ${tokenTest}` },
    });

    const data = await res.json();

    expect(res.status).toBe(401);
    expect(data.message).toBe('User not found');
  });

  it('should fail if token is no longer active', async () => {
    const userTokenNoActive = await prismaClient.user.create({
      data: {
        username: 'user_test_token_no_active_is_admin',
        password: await bcrypt.hash(password, 10),
        role: 'admin',
        is_active: true,
      },
    });

    const newToken = await sign(
      {
        id: userTokenNoActive.id,
        username: userTokenNoActive.username,
        role: userTokenNoActive.role,
        is_active: userTokenNoActive.is_active,
        iat: Math.floor(Date.now() / 1000),
        exp: APP_JWT_EXP,
      },
      APP_JWT_SECRET,
      'HS256'
    );

    await prismaClient.auth.create({
      data: {
        user_id: userTokenNoActive.id,
        is_active: false,
        token: newToken,
      },
    });

    const res = await app.request('/auth/test-middleware-is-admin', {
      method: 'GET',
      headers: { Authorization: `Bearer ${newToken}` },
    });

    const data = await res.json();

    expect(res.status).toBe(401);
    expect(data.message).toBe('Token is no longer active');
  });

  it('should fail if user is banned', async () => {
    await prismaClient.user.update({
      where: { id: userId },
      data: { role: 'banned' },
    });

    await prismaClient.auth.updateMany({
      where: { token },
      data: { is_active: true },
    });

    const res = await app.request('/auth/test-middleware-is-admin', {
      method: 'GET',
      headers: { Authorization: `Bearer ${token}` },
    });

    const data = await res.json();

    expect(res.status).toBe(403);
    expect(data.message).toBe('User already banned');
  });

  it('should fail if user is not active', async () => {
    await prismaClient.user.update({
      where: { id: userId },
      data: { role: 'member', is_active: false },
    });

    const res = await app.request('/auth/test-middleware-is-admin', {
      method: 'GET',
      headers: { Authorization: `Bearer ${token}` },
    });

    const data = await res.json();

    expect(res.status).toBe(401);
    expect(data.message).toBe('User not active');
  });

  it('should fail if user is role not admin', async () => {
    await prismaClient.user.update({
      where: { id: userId },
      data: { role: 'member', is_active: true },
    });

    const res = await app.request('/auth/test-middleware-is-admin', {
      method: 'GET',
      headers: { Authorization: `Bearer ${token}` },
    });

    const data = await res.json();

    expect(res.status).toBe(403);
    expect(data.message).toBe('Only admin can access this endpoint');
  });
});

describe('Middleware is_admin_or_key', () => {
  const username = 'user_test_middleware_is_admin_or_key';
  const password = 'pass_test_middleware_is_admin_or_key';
  let token: string;
  let userId: number;

  beforeAll(async () => {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await prismaClient.user.create({
      data: {
        username,
        password: hashedPassword,
        role: 'admin',
        is_active: true,
      },
    });
    userId = user.id;

    token = await sign(
      {
        id: user.id,
        username: user.username,
        role: user.role,
        is_active: user.is_active,
        iat: Math.floor(Date.now() / 1000),
        exp: APP_JWT_EXP,
      },
      APP_JWT_SECRET,
      'HS256'
    );

    await prismaClient.auth.create({
      data: {
        user_id: user.id,
        token,
        ip_address: '127.0.0.1',
        user_agent: 'test-agent',
      },
    });
  });

  afterAll(async () => {
    await prismaClient.user.deleteMany({
      where: {
        username: {
          in: [
            username,
            'user_test_user_not_found_is_admin_or_key',
            'user_test_token_no_active_is_admin_or_key',
          ],
        },
      },
    });
  });

  it('should pass middleware with key', async () => {
    const res = await app.request('/auth/test-middleware-is-admin-or-key', {
      method: 'GET',
      headers: { Authorization: APP_SECRET_KEY },
    });

    const data = await res.json();

    expect(res.status).toBe(200);
    expect(data?.message).toBe('Middleware passed');
  });

  it('should pass middleware and return user data with token', async () => {
    const res = await app.request('/auth/test-middleware-is-admin-or-key', {
      method: 'GET',
      headers: { Authorization: `Bearer ${token}` },
    });

    const data = await res.json();

    expect(res.status).toBe(200);
    expect(data?.message).toBe('Middleware passed');
    expect(data?.user?.username).toBe(username);
  });

  it('should fail if token is missing', async () => {
    const res = await app.request('/auth/test-middleware-is-admin-or-key', {
      method: 'GET',
    });

    const data = await res.json();

    expect(res.status).toBe(401);
    expect(data.message).toBe('Invalid token');
  });

  it('should fail if token is invalid', async () => {
    const res = await app.request('/auth/test-middleware-is-admin-or-key', {
      method: 'GET',
      headers: { Authorization: 'Bearer wrongtoken' },
    });

    const data = await res.json();

    expect(res.status).toBe(401);
    expect(data.message).toBe('Invalid JWT token');
  });

  it('should fail if user not found', async () => {
    const tokenTest = await sign(
      {
        id: 999999999999,
        username: 'user_test_user_not_found_is_admin_or_key',
        role: 'member',
        is_active: true,
        iat: Math.floor(Date.now() / 1000),
        exp: APP_JWT_EXP,
      },
      APP_JWT_SECRET,
      'HS256'
    );

    const res = await app.request('/auth/test-middleware-is-admin-or-key', {
      method: 'GET',
      headers: { Authorization: `Bearer ${tokenTest}` },
    });

    const data = await res.json();

    expect(res.status).toBe(401);
    expect(data.message).toBe('User not found');
  });

  it('should fail if token is no longer active', async () => {
    const userTokenNoActive = await prismaClient.user.create({
      data: {
        username: 'user_test_token_no_active_is_admin_or_key',
        password: await bcrypt.hash(password, 10),
        role: 'admin',
        is_active: true,
      },
    });

    const newToken = await sign(
      {
        id: userTokenNoActive.id,
        username: userTokenNoActive.username,
        role: userTokenNoActive.role,
        is_active: userTokenNoActive.is_active,
        iat: Math.floor(Date.now() / 1000),
        exp: APP_JWT_EXP,
      },
      APP_JWT_SECRET,
      'HS256'
    );

    await prismaClient.auth.create({
      data: {
        user_id: userTokenNoActive.id,
        is_active: false,
        token: newToken,
      },
    });

    const res = await app.request('/auth/test-middleware-is-admin-or-key', {
      method: 'GET',
      headers: { Authorization: `Bearer ${newToken}` },
    });

    const data = await res.json();

    expect(res.status).toBe(401);
    expect(data.message).toBe('Token is no longer active');
  });

  it('should fail if user is banned', async () => {
    await prismaClient.user.update({
      where: { id: userId },
      data: { role: 'banned' },
    });

    await prismaClient.auth.updateMany({
      where: { token },
      data: { is_active: true },
    });

    const res = await app.request('/auth/test-middleware-is-admin-or-key', {
      method: 'GET',
      headers: { Authorization: `Bearer ${token}` },
    });

    const data = await res.json();

    expect(res.status).toBe(403);
    expect(data.message).toBe('User already banned');
  });

  it('should fail if user is not active', async () => {
    await prismaClient.user.update({
      where: { id: userId },
      data: { role: 'member', is_active: false },
    });

    const res = await app.request('/auth/test-middleware-is-admin-or-key', {
      method: 'GET',
      headers: { Authorization: `Bearer ${token}` },
    });

    const data = await res.json();

    expect(res.status).toBe(401);
    expect(data.message).toBe('User not active');
  });

  it('should fail if user is role not admin', async () => {
    await prismaClient.user.update({
      where: { id: userId },
      data: { role: 'member', is_active: true },
    });

    const res = await app.request('/auth/test-middleware-is-admin-or-key', {
      method: 'GET',
      headers: { Authorization: `Bearer ${token}` },
    });

    const data = await res.json();

    expect(res.status).toBe(403);
    expect(data.message).toBe('Only admin can access this endpoint');
  });
});
