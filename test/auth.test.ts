import { describe, it, expect, beforeAll, afterAll } from 'bun:test';
import { prismaClient } from '@app/config/database';
import bcrypt from 'bcryptjs';
import { sign } from 'hono/jwt';
import { app } from '../index';
import { APP_JWT_EXP, APP_JWT_SECRET } from '@app/config/setting';
import { hashId } from '@app/helpers/hashids';

describe('POST /auth/register', () => {
  let testAppId: number;

  beforeAll(async () => {
    // Create test app
    const testApp = await prismaClient.app.create({
      data: {
        name: 'test_app_register',
        url: 'https://register.test',
      },
    });
    testAppId = testApp.id;
  });

  afterAll(async () => {
    await prismaClient.user.deleteMany({
      where: {
        username: {
          in: [
            'newuser_test',
            'newuser_withapp',
            'duplicate_user',
            'mixedcaseuser',
          ],
        },
      },
    });
    await prismaClient.app.deleteMany({
      where: { name: 'test_app_register' },
    });
  });

  it('should register new user without app_id successfully', async () => {
    const res = await app.request('/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'newuser_test',
        password: 'Password123!',
      }),
    });

    const result = await res.json();

    expect(res.status).toBe(200);

    expect(result.data.username).toBe('newuser_test');
    expect(result.data.role).toBe('member');
    expect(result.data.is_active).toBe(false);

    // Verify no app connection
    const connections = await prismaClient.userApp.findMany({
      where: { user_id: result.data.id },
    });
    expect(connections.length).toBe(0);
  });

  it('should register new user with app successfully', async () => {
    const encodedAppId = hashId.encode(testAppId);

    const res = await app.request('/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'newuser_withapp',
        password: 'Password123!',
        app_id: encodedAppId,
      }),
    });

    const result = await res.json();

    expect(res.status).toBe(200);
    expect(result.data.username).toBe('newuser_withapp');

    // Verify app connection exists
    const connection = await prismaClient.userApp.findFirst({
      where: {
        user_id: result.data.id,
        app_id: testAppId,
      },
    });
    expect(connection).not.toBeNull();
  });

  it('should fail with duplicate username', async () => {
    // First registration
    await app.request('/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'duplicate_user',
        password: 'Password123!',
      }),
    });

    // Try duplicate
    const res = await app.request('/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'duplicate_user',
        password: 'Password123!',
      }),
    });

    const result = await res.json();

    expect(res.status).toBe(400);
    expect(result.message).toBe('Username already exist');
  });

  it('should fail with invalid app_id', async () => {
    const res = await app.request('/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'user_invalid_app',
        password: 'Password123!',
        app_id: 'invalid_app_id',
      }),
    });

    const result = await res.json();

    expect(res.status).toBe(400);
    expect(result.message?.app_id).toBe('Invalid app_id format');
  });

  it('should fail with short username', async () => {
    const res = await app.request('/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'ab', // < 3 chars
        password: 'Password123!',
      }),
    });

    const result = await res.json();

    expect(res.status).toBe(400);
    expect(result.message?.username).toBe(
      'Username must be at least 3 characters'
    );
  });

  it('should fail with short password', async () => {
    const res = await app.request('/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'user_short_pass',
        password: '12', // < 3 chars
      }),
    });

    const result = await res.json();

    expect(res.status).toBe(400);
    expect(result.message?.password).toBe(
      'Password must be at least 3 characters'
    );
  });

  it('should lowercase username', async () => {
    const res = await app.request('/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'MixedCaseUser',
        password: 'Password123!',
      }),
    });

    const result = await res.json();

    expect(result.data.username).toBe('mixedcaseuser');
  });
});

describe('POST /auth/login', () => {
  let testUser: any;
  let testAppId: number;
  const testPassword = 'Password123!';

  beforeAll(async () => {
    // Create test app
    const testApp = await prismaClient.app.create({
      data: {
        name: 'test_app_login',
        url: 'https://login.test',
      },
    });
    testAppId = testApp.id;

    // Create test user
    testUser = await prismaClient.user.create({
      data: {
        username: 'testuser_login',
        password: await bcrypt.hash(testPassword, 10),
        role: 'member',
        is_active: true,
      },
    });

    // Create inactive user
    await prismaClient.user.create({
      data: {
        username: 'inactive_user',
        password: await bcrypt.hash(testPassword, 10),
        role: 'member',
        is_active: false,
      },
    });

    // Create banned user
    await prismaClient.user.create({
      data: {
        username: 'banned_user',
        password: await bcrypt.hash(testPassword, 10),
        role: 'banned',
        is_active: true,
      },
    });
  });

  afterAll(async () => {
    await prismaClient.user.deleteMany({
      where: {
        username: {
          in: ['testuser_login', 'inactive_user', 'banned_user'],
        },
      },
    });
    await prismaClient.app.deleteMany({
      where: { name: 'test_app_login' },
    });
  });

  it('should login successfully without app_id', async () => {
    const res = await app.request('/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'testuser_login',
        password: testPassword,
      }),
    });

    const result = await res.json();

    expect(res.status).toBe(200);
    expect(result.data.token).toBeDefined();

    // Verify auth record created
    const authRecord = await prismaClient.auth.findFirst({
      where: { user_id: testUser.id },
    });
    expect(authRecord).not.toBeNull();
  });

  it('should login successfully with valid app_id', async () => {
    const encodedAppId = hashId.encode(testAppId);

    const res = await app.request('/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'testuser_login',
        password: testPassword,
        app_id: encodedAppId,
      }),
    });

    const result = await res.json();

    expect(res.status).toBe(200);
    expect(result.data.token).toBeDefined();
  });

  it('should fail with invalid credentials', async () => {
    const res = await app.request('/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'testuser_login',
        password: 'wrong_password',
      }),
    });

    const result = await res.json();

    expect(res.status).toBe(400);
    expect(result.message).toBe('Invalid username or password');
  });

  it('should fail with non-existent user', async () => {
    const res = await app.request('/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'nonexistent_user',
        password: testPassword,
      }),
    });

    const result = await res.json();

    expect(res.status).toBe(400);
    expect(result.message).toBe('Invalid username or password');
  });

  it('should fail with banned user', async () => {
    const res = await app.request('/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'banned_user',
        password: testPassword,
      }),
    });

    const result = await res.json();

    expect(res.status).toBe(403);
    expect(result.message).toBe('User already banned');
  });

  it('should fail with inactive user', async () => {
    const res = await app.request('/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'inactive_user',
        password: testPassword,
      }),
    });

    const result = await res.json();

    expect(res.status).toBe(401);
    expect(result.message).toBe('User not active');
  });

  it('should fail with invalid app_id format', async () => {
    const res = await app.request('/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: 'testuser_login',
        password: testPassword,
        app_id: 'invalid_app_id',
      }),
    });

    const result = await res.json();

    expect(res.status).toBe(400);
    expect(result.message?.app_id).toBe('Invalid app_id format');
  });

  it('should include IP and User-Agent in auth record', async () => {
    const res = await app.request('/auth/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Real-IP': '192.168.1.1',
        'User-Agent': 'Test Agent',
      },
      body: JSON.stringify({
        username: 'testuser_login',
        password: testPassword,
      }),
    });

    const authRecord = await prismaClient.auth.findFirst({
      where: { user_id: testUser.id },
      orderBy: { id: 'desc' },
    });

    expect(authRecord?.ip_address).toBe('192.168.1.1');
    expect(authRecord?.user_agent).toBe('Test Agent');
  });
});

describe('GET /auth/logout', () => {
  const username = 'user_test_logout';
  const password = 'pass_test_logout';
  let token: string;

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

    const payload = {
      id: user.id,
      username: user.username,
      role: user.role,
      is_active: user.is_active,
      iat: Math.floor(Date.now() / 1000),
      exp: APP_JWT_EXP,
    };

    token = await sign(payload, APP_JWT_SECRET, 'HS256');

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
      where: { username },
    });
  });

  it('should logout successfully', async () => {
    const res = await app.request('/auth/logout', {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    const data = await res.json();

    expect(res.status).toBe(200);
    expect(data.message).toBe('Logout successful');
  });

  it('should fail if token is invalid', async () => {
    const res = await app.request('/auth/logout', {
      headers: {
        Authorization: 'Bearer invalidtoken',
      },
    });

    const data = await res.json();

    expect(res.status).toBe(400);
    expect(data.message).toBe('Token not available');
  });

  it('should fail if token is missing', async () => {
    const res = await app.request('/auth/logout');

    const data = await res.json();

    expect(res.status).toBe(401);
    expect(data.message).toBe('Invalid token');
  });
});

describe('GET /auth/verify', () => {
  const username = 'user_test_verify';
  const password = 'pass_test_verify';
  let token: string;

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

    const payload = {
      id: user.id,
      username: user.username,
      role: user.role,
      is_active: user.is_active,
      iat: Math.floor(Date.now() / 1000),
      exp: APP_JWT_EXP,
    };

    token = await sign(payload, APP_JWT_SECRET, 'HS256');

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
      where: { username },
    });
  });

  it('should verify and return user data', async () => {
    const res = await app.request('/auth/verify', {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    const data = await res.json();

    expect(res.status).toBe(200);
    expect(data?.data?.username).toBe(username);
    expect(data?.data?.role).toBe('member');
  });

  it('should fail if token is invalid', async () => {
    const res = await app.request('/auth/verify', {
      method: 'GET',
      headers: {
        Authorization: 'Bearer invalidtoken',
      },
    });

    const data = await res.json();

    expect(res.status).toBe(401);
    expect(data.message).toBe('Invalid JWT token');
  });

  it('should fail if token is missing', async () => {
    const res = await app.request('/auth/verify', {
      method: 'GET',
    });

    const data = await res.json();

    expect(res.status).toBe(401);
    expect(data.message).toBe('Invalid token');
  });
});
