import { Context } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { sign } from 'hono/jwt';
import bcrypt from 'bcryptjs';
import { resJSON } from '@helpers/function';
import { UserValidation } from '@app/validation/user';
import { prismaClient } from '@app/config/database';
import { APP_JWT_EXP, APP_JWT_SECRET } from '@app/config/setting';
import { hashId } from '@app/helpers/hashids';

export async function Register(c: Context) {
  let request = c.get('jsonData');

  request = UserValidation.REGISTER.parse(request);

  const appId: any = request.app_id ? hashId.decode(request.app_id)[0] : null;

  const userCheck = await prismaClient.user.count({
    where: {
      username: request.username,
    },
  });

  if (userCheck != 0) {
    throw new HTTPException(400, {
      message: 'Username already exist',
    });
  }

  const password = await bcrypt.hash(request.password, 10);

  const user = await prismaClient.user.create({
    data: {
      username: request.username.toLowerCase(),
      password: password,
      role: 'member',
      is_active: false,
    },
  });

  if (appId) {
    await prismaClient.userApp.create({
      data: {
        user: {
          connect: {
            id: user.id,
          },
        },
        app: {
          connect: {
            id: Number(appId),
          },
        },
      },
    });
  }

  const resData = resJSON({
    data: user,
  });

  return c.json(resData, resData.status as 200);
}

export async function Login(c: Context) {
  let request = c.get('jsonData');

  request = UserValidation.LOGIN.parse(request);

  const appId: any = request.app_id ? hashId.decode(request.app_id)[0] : null;

  const user = await prismaClient.user.findFirst({
    where: {
      username: request.username,
    },
  });

  if (!user) {
    throw new HTTPException(400, {
      message: 'Invalid username or password',
    });
  }

  const comparePass = await bcrypt.compare(request.password, user.password);

  if (!comparePass) {
    throw new HTTPException(400, {
      message: 'Invalid username or password',
    });
  }

  if (user.role == 'banned') {
    throw new HTTPException(403, {
      message: 'User already banned',
    });
  }

  if (!user.is_active) {
    throw new HTTPException(401, {
      message: 'User not active',
    });
  }

  const jwtPayload = {
    id: user.id,
    username: user.username,
    role: user.role,
    app_id: appId ? hashId.encode(appId) : null,
    is_active: user.is_active,
    iat: Math.floor(Date.now() / 1000),
    exp: APP_JWT_EXP,
  };
  const jwtToken = await sign(jwtPayload, APP_JWT_SECRET, 'HS256');

  const ipAddress =
    c.req.header('x-real-ip') || c.req.header('x-forwarded-for') || '';
  const userAgent = c.req.header('user-agent') || '';

  await prismaClient.auth.create({
    data: {
      user: {
        connect: { id: user.id },
      },
      ip_address: ipAddress,
      user_agent: userAgent,
      token: jwtToken,
    },
  });

  const resData = resJSON({
    data: { token: jwtToken },
  });

  return c.json(resData, resData.status as 200);
}

export async function Logout(c: Context) {
  const authHeader = c.req.header('Authorization');

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    throw new HTTPException(401, {
      message: 'Invalid token',
    });
  }

  const token = authHeader.split(' ')[1];

  const data = await prismaClient.auth.updateMany({
    where: { token: token },
    data: { is_active: false },
  });

  if (data.count === 0) {
    throw new HTTPException(400, {
      message: 'Token not available',
    });
  }

  const resData = resJSON({
    message: 'Logout successful',
  });

  return c.json(resData, resData.status as 200);
}

export async function Verify(c: Context) {
  const user = c.get('userData');

  const resData = resJSON({
    data: user,
  });

  return c.json(resData, resData.status as 200);
}
