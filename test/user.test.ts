import { describe, it, expect, beforeAll, afterAll } from 'bun:test';
import { sign } from 'hono/jwt';
import bcrypt from 'bcryptjs';
import { app } from '../index';
import { prismaClient } from '@app/config/database';
import {
  APP_JWT_SECRET,
  APP_JWT_EXP,
  APP_SECRET_KEY,
} from '@app/config/setting';

describe('GET /user/:id?', () => {
  let token = '';
  let adminUserId = 0;
  let testUsers: any[] = [];

  beforeAll(async () => {
    // Create admin user
    const adminUser = await prismaClient.user.create({
      data: {
        username: 'admin_test_getUser',
        password: 'pass_test_getUser',
        role: 'admin',
        is_active: true,
      },
    });

    adminUserId = adminUser.id;

    // Create test users
    testUsers = await Promise.all([
      prismaClient.user.create({
        data: {
          username: 'user1_test_get',
          password: 'pass1_test_get',
          role: 'member',
          is_active: true,
        },
      }),
      prismaClient.user.create({
        data: {
          username: 'user2_test_get',
          password: 'pass2_test_get',
          role: 'member',
          is_active: false,
        },
      }),
    ]);

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
    await prismaClient.user.deleteMany({
      where: {
        id: {
          in: [adminUserId, ...testUsers.map((u) => u.id)],
        },
      },
    });
  });

  it('should get single user by ID', async () => {
    const res = await app.request(`/user/${testUsers[0].id}`, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    const result = await res.json();

    expect(res.status).toBe(200);
    expect(result.data.id).toBe(testUsers[0].id);
    expect(result.data.username).toBe('user1_test_get');
    expect(result.data.auths).toBeDefined();
  });

  it('should fail with invalid user ID format', async () => {
    const res = await app.request('/user/invalid_id', {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    const result = await res.json();

    expect(res.status).toBe(400);
    expect(result.message).toBe('User not found');
  });

  it('should fail with non-existent user ID', async () => {
    const nonExistentId = 999999;
    const res = await app.request(`/user/${nonExistentId}`, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    const result = await res.json();

    expect(res.status).toBe(400);
    expect(result.message).toBe('User not found');
  });

  it('should get all users with pagination', async () => {
    const res = await app.request('/user?limit=1&offset=0', {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    const result = await res.json();

    expect(res.status).toBe(200);
    expect(result.data.users.length).toBe(1);
    expect(result.data.paging.total_users).toBeGreaterThanOrEqual(3); // admin + 2 test users
    expect(result.data.paging.current_page).toBe(1);
    expect(result.data.users[0].password).toBeUndefined(); // Omit password
  });

  it('should use default pagination if not provided', async () => {
    const res = await app.request('/user', {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    const result = await res.json();

    expect(res.status).toBe(200);
    expect(result.data.users.length).toBeGreaterThanOrEqual(3);
    expect(result.data.paging.current_page).toBe(1);
  });
});

describe('POST /user', () => {
  let token = '';
  let adminUserId = 0;

  beforeAll(async () => {
    // Create admin user
    const adminUser = await prismaClient.user.create({
      data: {
        username: 'admin_test_createUser',
        password: 'pass_test_createUser',
        role: 'admin',
        is_active: true,
      },
    });

    adminUserId = adminUser.id;

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
    await prismaClient.user.deleteMany({
      where: {
        OR: [
          { id: adminUserId },
          { username: 'new_user_test' },
          { username: 'new_admin_test' },
          { username: 'duplicate_user_test' },
        ],
      },
    });
  });

  it('should create new member user successfully', async () => {
    const res = await app.request('/user', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        username: 'new_user_test',
        password: 'password123',
        role: 'member',
      }),
    });

    const result = await res.json();

    expect(res.status).toBe(200);
    expect(result.data.username).toBe('new_user_test');
    expect(result.data.role).toBe('member');
    expect(result.data.is_active).toBe(false); // default value
  });

  it('should create new admin user successfully', async () => {
    const res = await app.request('/user', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        username: 'new_admin_test',
        password: 'password123',
        role: 'admin',
        is_active: true,
      }),
    });

    const result = await res.json();

    expect(res.status).toBe(200);
    expect(result.data.username).toBe('new_admin_test');
    expect(result.data.role).toBe('admin');
    expect(result.data.is_active).toBe(true);
  });

  it('should fail with duplicate username', async () => {
    // First create
    await app.request('/user', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        username: 'duplicate_user_test',
        password: 'password123',
      }),
    });

    // Try duplicate
    const res = await app.request('/user', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        username: 'duplicate_user_test',
        password: 'password123',
      }),
    });

    const result = await res.json();
    expect(res.status).toBe(400);
    expect(result.message).toBe('Username is already exist');
  });

  it('should fail with invalid username format', async () => {
    const res = await app.request('/user', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        username: 'ab', // too short
        password: 'password123',
      }),
    });

    const result = await res.json();

    expect(res.status).toBe(400);
    expect(result.message?.username).toBe(
      'Username must be at least 3 characters'
    );
  });

  it('should fail with invalid password format', async () => {
    const res = await app.request('/user', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        username: 'valid_username',
        password: '12', // too short
      }),
    });

    const result = await res.json();

    expect(res.status).toBe(400);
    expect(result.message?.password).toBe(
      'Password must be at least 3 characters'
    );
  });

  it('should fail with invalid role', async () => {
    const res = await app.request('/user', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        username: 'user_invalid_role',
        password: 'password123',
        role: 'invalid_role', // invalid
      }),
    });

    const result = await res.json();

    expect(res.status).toBe(400);
    expect(result.message?.role).toBeDefined();
  });
});

describe('PUT /user/:id', () => {
  let token = '';
  let adminUserId = 0;
  let testUserId = 0;

  beforeAll(async () => {
    // Create admin user
    const adminUser = await prismaClient.user.create({
      data: {
        username: 'admin_test_updateUser',
        password: 'pass_test_updateUser',
        role: 'admin',
        is_active: true,
      },
    });

    adminUserId = adminUser.id;

    // Create test user
    const testUser = await prismaClient.user.create({
      data: {
        username: 'user_to_update',
        password: 'original_pass',
        role: 'member',
        is_active: false,
      },
    });

    testUserId = testUser.id;

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
    await prismaClient.user.deleteMany({
      where: {
        id: {
          in: [adminUserId, testUserId],
        },
      },
    });
  });

  it('should update username successfully', async () => {
    const res = await app.request(`/user/${testUserId}`, {
      method: 'PUT',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        username: 'updated_username',
      }),
    });

    const result = await res.json();

    expect(res.status).toBe(200);
    expect(result.data.username).toBe('updated_username');
    expect(result.data.role).toBe('member'); // Tetap sama
  });

  it('should update password successfully', async () => {
    const res = await app.request(`/user/${testUserId}`, {
      method: 'PUT',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        password: 'new_password_123',
      }),
    });

    const result = await res.json();

    expect(res.status).toBe(200);
    expect(result.data).toBeDefined();

    // Verify password changed
    const updatedUser = await prismaClient.user.findUnique({
      where: { id: testUserId },
    });
    const isMatch = await bcrypt.compare(
      'new_password_123',
      updatedUser?.password || ''
    );
    expect(isMatch).toBe(true);
  });

  it('should update role and status successfully', async () => {
    const res = await app.request(`/user/${testUserId}`, {
      method: 'PUT',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        role: 'admin',
        is_active: true,
      }),
    });

    const result = await res.json();

    expect(res.status).toBe(200);
    expect(result.data.role).toBe('admin');
    expect(result.data.is_active).toBe(true);
  });

  it('should fail with invalid user ID', async () => {
    const res = await app.request('/user/invalid_id', {
      method: 'PUT',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        username: 'new_username',
      }),
    });

    const result = await res.json();

    expect(res.status).toBe(400);
    expect(result.message).toBe('User not found');
  });

  it('should fail with non-existent user ID', async () => {
    const res = await app.request('/user/9999999999999', {
      method: 'PUT',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        username: 'new_username',
      }),
    });

    const result = await res.json();

    expect(res.status).toBe(400);
    expect(result.message).toBe('User not found');
  });

  it('should fail with invalid username format', async () => {
    const res = await app.request(`/user/${testUserId}`, {
      method: 'PUT',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        username: 'ab', // to short
      }),
    });

    const result = await res.json();

    expect(res.status).toBe(400);
    expect(result.message?.username).toBe(
      'Username must be at least 3 characters'
    );
  });

  it('should fail with invalid role', async () => {
    const res = await app.request(`/user/${testUserId}`, {
      method: 'PUT',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        role: 'invalid_role',
      }),
    });

    const result = await res.json();

    expect(res.status).toBe(400);
    expect(result.message.role).toBeDefined();
  });
});

describe('DELETE /user/:id', () => {
  let token = '';
  let adminUserId = 0;
  let testUserId = 0;

  beforeAll(async () => {
    // Create admin user
    const adminUser = await prismaClient.user.create({
      data: {
        username: 'admin_test_deleteUser',
        password: 'pass_test_deleteUser',
        role: 'admin',
        is_active: true,
      },
    });

    adminUserId = adminUser.id;

    // Create test user
    const testUser = await prismaClient.user.create({
      data: {
        username: 'user_to_delete',
        password: 'password123',
        role: 'member',
      },
    });

    testUserId = testUser.id;

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
    await prismaClient.user.deleteMany({
      where: {
        id: adminUserId, // Hapus admin saja, user test sudah didelete di test case
      },
    });
  });

  it('should delete user successfully', async () => {
    const res = await app.request(`/user/${testUserId}`, {
      method: 'DELETE',
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    const result = await res.json();

    expect(res.status).toBe(200);
    expect(result.message).toBe('Deleted user successfully');

    // Verify user is deleted
    const deletedUser = await prismaClient.user.findUnique({
      where: { id: testUserId },
    });
    expect(deletedUser).toBeNull();
  });

  it('should fail with invalid user ID format', async () => {
    const res = await app.request('/user/invalid_id', {
      method: 'DELETE',
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    const result = await res.json();

    expect(res.status).toBe(400);
    expect(result.message).toBe('User not found');
  });

  it('should fail with non-existent user ID', async () => {
    const res = await app.request('/user/999999', {
      method: 'DELETE',
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    const result = await res.json();

    expect(res.status).toBe(400);
    expect(result.message).toBe('User not found');
  });

  it('should cascade delete related auth records', async () => {
    // Create new user with auth record
    const user = await prismaClient.user.create({
      data: {
        username: 'user_with_auth',
        password: 'password123',
      },
    });

    await prismaClient.auth.create({
      data: {
        user_id: user.id,
        token: 'test_token',
      },
    });

    // Delete user
    await app.request(`/user/${user.id}`, {
      method: 'DELETE',
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    // Verify auth record is also deleted
    const authRecord = await prismaClient.auth.findFirst({
      where: { user_id: user.id },
    });
    expect(authRecord).toBeNull();
  });
});

describe('POST /user/activate', () => {
  let adminToken = '';
  let appSecret = APP_SECRET_KEY;
  let testUserId = 0;

  beforeAll(async () => {
    // Create test user
    const testUser = await prismaClient.user.create({
      data: {
        username: 'user_to_activate',
        password: 'password123',
        role: 'member',
        is_active: false,
      },
    });
    testUserId = testUser.id;

    // Create admin user
    const adminUser = await prismaClient.user.create({
      data: {
        username: 'admin_test_activation',
        password: 'admin_pass',
        role: 'admin',
        is_active: true,
      },
    });

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
          in: ['user_to_activate', 'admin_test_activation'],
        },
      },
    });
  });

  it('should activate user successfully (via admin)', async () => {
    const res = await app.request('/user/activate', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${adminToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        id: testUserId,
        is_active: true,
      }),
    });

    const result = await res.json();

    expect(res.status).toBe(200);
    expect(result.message).toBe('User successfully activated');
    expect(result.data.is_active).toBe(true);
  });

  it('should deactivate user successfully (via secret key)', async () => {
    const res = await app.request('/user/activate', {
      method: 'POST',
      headers: {
        Authorization: appSecret,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        id: testUserId,
        is_active: false,
      }),
    });

    const result = await res.json();

    expect(res.status).toBe(200);
    expect(result.message).toBe('User successfully deactivated');
    expect(result.data.is_active).toBe(false);
  });

  it('should fail with invalid user ID', async () => {
    const res = await app.request('/user/activate', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${adminToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        id: 'invalid_id',
        is_active: true,
      }),
    });

    const result = await res.json();

    expect(res.status).toBe(400);
    expect(result.message.id).toBe('Id must be a number');
  });

  it('should fail with non-existent user ID', async () => {
    const res = await app.request('/user/activate', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${adminToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        id: 999999999,
        is_active: true,
      }),
    });

    const result = await res.json();

    expect(res.status).toBe(400);
    expect(result.message).toBe('User not found');
  });

  it('should fail when is_active is not provided', async () => {
    const res = await app.request('/user/activate', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${adminToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        id: testUserId,
      }),
    });

    const result = await res.json();

    expect(res.status).toBe(400);
    expect(result.message?.is_active).toBe('is_active is required');
  });

  it('should fail with unauthorized access (no token/api key)', async () => {
    const res = await app.request('/user/activate', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        id: testUserId,
        is_active: true,
      }),
    });

    expect(res.status).toBe(401);
  });
});
