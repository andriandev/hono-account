import { Context, Next } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { verify } from 'hono/jwt';
import { customJwtErrorMessage } from '@app/helpers/function';
import { APP_JWT_SECRET, APP_SECRET_KEY } from '@app/config/setting';
import { prismaClient } from '@app/config/database';

async function getUserFromToken(token: string) {
  try {
    const decoded = await verify(token, APP_JWT_SECRET, 'HS256');

    const userDB = await prismaClient.user.findFirst({
      where: { id: decoded.id },
      omit: { password: true },
      include: {
        auths: {
          where: { token, user_id: decoded.id },
          omit: { id: true },
        },
      },
    });

    return { user: decoded, userDB: userDB };
  } catch (err) {
    if (err.name.includes('Jwt')) {
      await handleJwtExpired(token, err);
      throw new HTTPException(401, { message: customJwtErrorMessage(err) });
    } else {
      throw new HTTPException(500, { message: err.message });
    }
  }
}

function validateUserStatus(user: any, userDB: any) {
  if (!userDB) throw new HTTPException(401, { message: 'User not found' });
  if (!userDB?.auths[0]?.is_active)
    throw new HTTPException(401, { message: 'Token is no longer active' });
  if (user.role === 'banned' || userDB.role === 'banned')
    throw new HTTPException(403, { message: 'User already banned' });
  if (!user.is_active || !userDB.is_active)
    throw new HTTPException(401, { message: 'User not active' });
}

function validateAdmin(user: any, userDB: any) {
  if (user.role !== 'admin' || userDB.role !== 'admin') {
    throw new HTTPException(403, {
      message: 'Only admin can access this endpoint',
    });
  }
}

async function handleJwtExpired(token: string, err: any) {
  if (err.name === 'JwtTokenExpired') {
    await prismaClient.auth.updateMany({
      where: { token },
      data: { is_active: false },
    });
  }
}

export async function is_login(c: Context, next: Next) {
  const authHeader = c.req.header('Authorization');

  if (!authHeader?.startsWith('Bearer '))
    throw new HTTPException(401, { message: 'Invalid token' });

  const token = authHeader.split(' ')[1];

  const { user, userDB } = await getUserFromToken(token);
  validateUserStatus(user, userDB);

  c.set('userData', userDB);

  await next();
}

export async function is_admin(c: Context, next: Next) {
  const authHeader = c.req.header('Authorization');

  if (!authHeader?.startsWith('Bearer '))
    throw new HTTPException(401, { message: 'Invalid token' });

  const token = authHeader.split(' ')[1];

  const { user, userDB } = await getUserFromToken(token);
  validateUserStatus(user, userDB);
  validateAdmin(user, userDB);

  c.set('userData', userDB);

  await next();
}

export async function is_admin_or_key(c: Context, next: Next) {
  const authHeader = c.req.header('Authorization');

  if (!authHeader) throw new HTTPException(401, { message: 'Invalid token' });

  let token = authHeader.startsWith('Bearer ')
    ? authHeader.split(' ')[1]
    : authHeader;

  if (token === APP_SECRET_KEY) return await next();

  if (!authHeader.startsWith('Bearer '))
    throw new HTTPException(401, { message: 'Invalid token' });

  const { user, userDB } = await getUserFromToken(token);
  validateUserStatus(user, userDB);
  validateAdmin(user, userDB);

  c.set('userData', userDB);

  await next();
}
