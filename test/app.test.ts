import { describe, it, expect, beforeAll, afterAll } from 'bun:test';
import { sign } from 'hono/jwt';
import { app } from '../index';
import { prismaClient } from '@app/config/database';
import { APP_JWT_SECRET, APP_JWT_EXP } from '@app/config/setting';

describe('GET /app/:id?', () => {
  let token = '';
  let admin: any;
  let testApp: any;

  beforeAll(async () => {
    admin = await prismaClient.user.create({
      data: {
        username: 'user_test_get_app',
        password: 'pass_test_get_app',
        role: 'admin',
        is_active: true,
      },
    });

    testApp = await prismaClient.app.create({
      data: {
        name: 'Test App',
        url: 'https://test.app',
      },
    });

    await prismaClient.userApp.create({
      data: {
        user_id: admin.id,
        app_id: testApp.id,
      },
    });

    token = await sign(
      {
        id: admin.id,
        role: admin.role,
        is_active: true,
        iat: Math.floor(Date.now() / 1000),
        exp: APP_JWT_EXP,
      },
      APP_JWT_SECRET,
      'HS256'
    );

    await prismaClient.auth.create({
      data: {
        user_id: admin.id,
        token: token,
      },
    });
  });

  afterAll(async () => {
    await prismaClient.user.delete({ where: { id: admin.id } });
    await prismaClient.app.deleteMany({
      where: {
        id: testApp.id,
      },
    });
  });

  it('should get list of apps with paging', async () => {
    const res = await app.request('/app', {
      headers: { Authorization: `Bearer ${token}` },
    });

    const result = await res.json();

    expect(res.status).toBe(200);
    expect(result.data.apps).toBeDefined();
  });

  it('should return app list with user list', async () => {
    const response = await app.request('/app?limit=1&offset=0', {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    const result = await response.json();

    expect(response.status).toBe(200);
    expect(result.data.apps).toBeDefined();
    expect(result.data.apps.length).toBeGreaterThan(0);
  });

  it('should get one app with user if take_user=true', async () => {
    const res = await app.request(`/app/${testApp.id}?take_user=true`, {
      headers: { Authorization: `Bearer ${token}` },
    });

    const result = await res.json();

    expect(res.status).toBe(200);
    expect(result.data.users).toBeDefined();
  });

  it('should return 400 if app not found', async () => {
    const res = await app.request(`/app/99999999999`, {
      headers: { Authorization: `Bearer ${token}` },
    });

    const result = await res.json();

    expect(res.status).toBe(400);
    expect(result.message).toBe('App not found');
  });

  it('should return 400 if id is invalid', async () => {
    const res = await app.request(`/app/abc`, {
      headers: { Authorization: `Bearer ${token}` },
    });

    const json = await res.json();

    expect(res.status).toBe(400);
    expect(json.message).toBe('App not found');
  });
});

describe('POST /app', () => {
  let token = '';
  let adminUserId = 0;

  beforeAll(async () => {
    const adminUser = await prismaClient.user.create({
      data: {
        username: 'user_test_createApp',
        password: 'pass_test_createApp',
        role: 'admin',
        is_active: true,
      },
    });

    adminUserId = adminUser.id;

    token = await sign(
      {
        id: adminUser.id,
        role: adminUser.role,
        is_active: true,
        iat: Math.floor(Date.now() / 1000),
        exp: APP_JWT_EXP,
      },
      APP_JWT_SECRET,
      'HS256'
    );

    await prismaClient.auth.create({
      data: {
        user_id: adminUser.id,
        token: token,
      },
    });
  });

  afterAll(async () => {
    await prismaClient.user.delete({ where: { id: adminUserId } });
    await prismaClient.app.deleteMany({ where: { name: 'Test App Create' } });
  });

  it('should create new app successfully', async () => {
    const res = await app.request('/app', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        name: 'Test App Create',
        url: 'https://app.test',
      }),
    });

    const result = await res.json();

    expect(res.status).toBe(200);
    expect(result.data.name).toBe('Test App Create');
  });

  it('should fail if invalid url', async () => {
    const res = await app.request('/app', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        name: 'Test App Create',
        url: 'invalid url',
      }),
    });

    const result = await res.json();

    expect(res.status).toBe(400);
    expect(result.message?.url).toBe('Url must be valid');
  });

  it('should fail if app with same name exists', async () => {
    // Insert manually to trigger conflict
    await prismaClient.app.create({
      data: {
        name: 'Test App Create',
        url: 'https://test.app',
      },
    });

    const res = await app.request('/app', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        name: 'Test App Create',
        url: 'https://app.test',
      }),
    });

    const result = await res.json();
    expect(res.status).toBe(400);
    expect(result.message).toBe('App is already exist');
  });
});

describe('PUT /app/:id', () => {
  let token = '';
  let adminUserId = 0;
  let testAppId = 0;

  beforeAll(async () => {
    // Create admin user
    const adminUser = await prismaClient.user.create({
      data: {
        username: 'user_test_updateApp',
        password: 'pass_test_updateApp',
        role: 'admin',
        is_active: true,
      },
    });

    adminUserId = adminUser.id;

    // Create test app
    const testApp = await prismaClient.app.create({
      data: {
        name: 'Test App Before Update',
        url: 'https://before.update',
      },
    });

    testAppId = testApp.id;

    // Generate token
    token = await sign(
      {
        id: adminUser.id,
        role: adminUser.role,
        is_active: true,
        iat: Math.floor(Date.now() / 1000),
        exp: APP_JWT_EXP,
      },
      APP_JWT_SECRET,
      'HS256'
    );

    // Create auth record
    await prismaClient.auth.create({
      data: {
        user_id: adminUser.id,
        token: token,
      },
    });
  });

  afterAll(async () => {
    await prismaClient.user.delete({ where: { id: adminUserId } });
    await prismaClient.app.delete({ where: { id: testAppId } });
  });

  it('should update app successfully', async () => {
    const res = await app.request(`/app/${testAppId}`, {
      method: 'PUT',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        name: 'Test App Updated',
        url: 'https://updated.app',
      }),
    });

    const result = await res.json();

    expect(res.status).toBe(200);
    expect(result.data.name).toBe('Test App Updated');
    expect(result.data.url).toBe('https://updated.app');
  });

  it('should fail with invalid ID', async () => {
    const res = await app.request('/app/invalid_id', {
      method: 'PUT',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        name: 'Test App Updated',
        url: 'https://updated.app',
      }),
    });

    const result = await res.json();

    expect(res.status).toBe(400);
    expect(result.message).toBe('App not found');
  });

  it('should fail with non-existent app ID', async () => {
    const nonExistentId = 999999;
    const res = await app.request(`/app/${nonExistentId}`, {
      method: 'PUT',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        name: 'Test App Updated',
        url: 'https://updated.app',
      }),
    });

    const result = await res.json();

    expect(res.status).toBe(400);
    expect(result.message).toBe('App not found');
  });

  it('should fail with invalid URL format', async () => {
    const res = await app.request(`/app/${testAppId}`, {
      method: 'PUT',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        name: 'Test App Updated',
        url: 'invalid-url',
      }),
    });

    const result = await res.json();

    expect(res.status).toBe(400);
    expect(result.message?.url).toBe('Url must be valid');
  });

  it('should allow partial update (name only)', async () => {
    const res = await app.request(`/app/${testAppId}`, {
      method: 'PUT',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        name: 'Partial Update Test',
      }),
    });

    const result = await res.json();

    expect(res.status).toBe(200);
    expect(result.data.name).toBe('Partial Update Test');
  });

  it('should allow partial update (url only)', async () => {
    const res = await app.request(`/app/${testAppId}`, {
      method: 'PUT',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        url: 'https://partial.update',
      }),
    });

    const result = await res.json();

    expect(res.status).toBe(200);
    expect(result.data.url).toBe('https://partial.update');
  });
});

describe('DELETE /app/:id', () => {
  let token = '';
  let adminUserId = 0;
  let testAppId = 0;

  beforeAll(async () => {
    // Create admin user
    const adminUser = await prismaClient.user.create({
      data: {
        username: 'user_test_deleteApp',
        password: 'pass_test_deleteApp',
        role: 'admin',
        is_active: true,
      },
    });

    adminUserId = adminUser.id;

    // Create test app
    const testApp = await prismaClient.app.create({
      data: {
        name: 'Test App To Delete',
        url: 'https://to.delete',
      },
    });

    testAppId = testApp.id;

    // Generate token
    token = await sign(
      {
        id: adminUser.id,
        role: adminUser.role,
        is_active: true,
        iat: Math.floor(Date.now() / 1000),
        exp: APP_JWT_EXP,
      },
      APP_JWT_SECRET,
      'HS256'
    );

    // Create auth record
    await prismaClient.auth.create({
      data: {
        user_id: adminUser.id,
        token: token,
      },
    });
  });

  afterAll(async () => {
    await prismaClient.user.delete({ where: { id: adminUserId } });
  });

  it('should delete app successfully', async () => {
    const res = await app.request(`/app/${testAppId}`, {
      method: 'DELETE',
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    const result = await res.json();

    expect(res.status).toBe(200);
    expect(result.message).toBe('Deleted app successfully');

    // Verify app is really deleted
    const deletedApp = await prismaClient.app.findUnique({
      where: { id: testAppId },
    });
    expect(deletedApp).toBeNull();
  });

  it('should fail with invalid ID format', async () => {
    const res = await app.request('/app/invalid_id', {
      method: 'DELETE',
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    const result = await res.json();

    expect(res.status).toBe(400);
    expect(result.message).toBe('App not found');
  });

  it('should fail with non-existent app ID', async () => {
    const nonExistentId = 999999;
    const res = await app.request(`/app/${nonExistentId}`, {
      method: 'DELETE',
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    const result = await res.json();

    expect(res.status).toBe(400);
    expect(result.message).toBe('App not found');
  });
});

describe('GET /app/connect', () => {
  let adminToken = '';
  let testUserId = 0;
  let testAppId = 0;

  beforeAll(async () => {
    // Create admin user
    const adminUser = await prismaClient.user.create({
      data: {
        username: 'admin_test_connect',
        password: 'admin_pass',
        role: 'admin',
        is_active: true,
      },
    });

    // Create test user
    const testUser = await prismaClient.user.create({
      data: {
        username: 'user_test_connect',
        password: 'user_pass',
        role: 'member',
      },
    });
    testUserId = testUser.id;

    // Create test app
    const testApp = await prismaClient.app.create({
      data: {
        name: 'app_test_connect',
        url: 'https://connect.test',
      },
    });
    testAppId = testApp.id;

    // Generate admin token
    adminToken = await sign(
      {
        id: adminUser.id,
        role: adminUser.role,
        is_active: true,
        iat: Math.floor(Date.now() / 1000),
        exp: APP_JWT_EXP,
      },
      APP_JWT_SECRET,
      'HS256'
    );

    // Create auth record for admin
    await prismaClient.auth.create({
      data: {
        user_id: adminUser.id,
        token: adminToken,
      },
    });
  });

  afterAll(async () => {
    await prismaClient.user.deleteMany({
      where: {
        username: {
          in: ['admin_test_connect', 'user_test_connect'],
        },
      },
    });
    await prismaClient.app.deleteMany({
      where: {
        name: 'app_test_connect',
      },
    });
  });

  it('should connect user to app successfully', async () => {
    const res = await app.request(
      `/app/connect?user_id=${testUserId}&app_id=${testAppId}`,
      {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${adminToken}`,
        },
      }
    );

    const result = await res.json();

    expect(res.status).toBe(200);
    expect(result.data.user_id).toBe(testUserId);
    expect(result.data.app_id).toBe(testAppId);
  });

  it('should fail with duplicate connection', async () => {
    // Try duplicate connection, first connect in abave
    const res = await app.request(
      `/app/connect?user_id=${testUserId}&app_id=${testAppId}`,
      {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${adminToken}`,
        },
      }
    );

    const result = await res.json();

    expect(res.status).toBe(400);
    expect(result.message).toBe('This user is already connected to the app');
  });

  it('should fail with non-existent user ID', async () => {
    const res = await app.request(
      `/app/connect?user_id=9999999999999&app_id=${testAppId}`,
      {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${adminToken}`,
        },
      }
    );

    const result = await res.json();

    expect(res.status).toBe(400);
    expect(result.message).toBe('User or App not found');
  });

  it('should fail with non-existent app ID', async () => {
    const res = await app.request(
      `/app/connect?user_id=${testUserId}&app_id=99999999999999`,
      {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${adminToken}`,
        },
      }
    );

    const result = await res.json();

    expect(res.status).toBe(400);
    expect(result.message).toBe('User or App not found');
  });

  it('should fail with invalid user ID format', async () => {
    const res = await app.request('/app/connect?user_id=invalid&app_id=1', {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${adminToken}`,
      },
    });

    const result = await res.json();

    expect(res.status).toBe(400);
    expect(result.message?.user_id).toBe('Query user_id must be a number');
  });

  it('should fail with invalid app ID format', async () => {
    const res = await app.request('/app/connect?user_id=1&app_id=invalid', {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${adminToken}`,
      },
    });

    const result = await res.json();

    expect(res.status).toBe(400);
    expect(result.message?.app_id).toBe('Query app_id must be a number');
  });

  it('should fail with missing parameters', async () => {
    const res1 = await app.request('/app/connect?app_id=1', {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${adminToken}`,
      },
    });

    const res2 = await app.request('/app/connect?user_id=1', {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${adminToken}`,
      },
    });

    expect(res1.status).toBe(400);
    expect(res2.status).toBe(400);
  });
});
