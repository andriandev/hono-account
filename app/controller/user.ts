import { Context } from 'hono';
import { HTTPException } from 'hono/http-exception';
import bcrypt from 'bcryptjs';
import { UserValidation } from '@app/validation/user';
import { prismaClient } from '@app/config/database';
import { resJSON } from '@app/helpers/function';
import { hashId } from '@app/helpers/hashids';

export async function GetUser(c: Context) {
  const idUser: any = c.req.param('id');
  const rawQuery = c.req.query();
  const query = UserValidation.GET.parse(rawQuery);
  const userData = c.get('userData');
  let data: any = {};

  if (idUser) {
    if (isNaN(idUser)) {
      throw new HTTPException(400, {
        message: 'User not found',
      });
    }

    const user = await prismaClient.user.findFirst({
      where: {
        id: Number(idUser),
      },
      omit: { password: true },
      include: {
        auths: { omit: { user_id: true }, orderBy: { id: 'desc' } },
        apps: {
          select: {
            app: {
              select: {
                id: true,
                name: true,
                url: true,
              },
            },
          },
        },
      },
    });

    if (!user) {
      throw new HTTPException(400, {
        message: 'User not found',
      });
    }

    if (userData.role !== 'admin' && userData.id !== user.id) {
      throw new HTTPException(403, {
        message: 'Access forbidden',
      });
    }

    const formattedUser = {
      ...user,
      apps:
        user?.apps.map(({ app }) => ({
          id: app.id,
          hash_id: hashId.encode(app.id),
          name: app.name,
          url: app.url,
        })) ?? [],
    };

    data = formattedUser;
  } else {
    const limit = query.limit ? Number(query.limit) : 10;
    const offset = query.offset ? Number(query.offset) : 0;

    const [users, totalUsers] = await Promise.all([
      prismaClient.user.findMany({
        skip: offset,
        take: limit,
        omit: {
          password: true,
        },
      }),
      prismaClient.user.count(),
    ]);

    const totalPages = Math.ceil(totalUsers / limit);
    const currentPage = Math.floor(offset / limit) + 1;

    data.users = users;
    data.paging = {
      total_users: totalUsers,
      total_pages: totalPages,
      current_page: currentPage,
    };
  }

  const resData = resJSON({
    data: data,
  });

  return c.json(resData, resData.status as 200);
}

export async function CreateUser(c: Context) {
  let request = c.get('jsonData');

  request = UserValidation.CREATE.parse(request);

  const checkUsername = await prismaClient.user.findFirst({
    where: {
      username: request.username,
    },
  });

  if (checkUsername) {
    throw new HTTPException(400, {
      message: 'Username is already exist',
    });
  }

  request.password = await bcrypt.hash(request.password, 10);

  const user = await prismaClient.user.create({
    data: request,
  });

  const resData = resJSON({
    data: user,
  });

  return c.json(resData, resData.status as 200);
}

export async function UpdateUser(c: Context) {
  const idUser: any = c.req.param('id');
  let request = c.get('jsonData');
  const userData = c.get('userData');

  if (isNaN(idUser)) {
    throw new HTTPException(400, {
      message: 'User not found',
    });
  }

  request = UserValidation.UPDATE.parse(request);

  const user = await prismaClient.user.findFirst({
    where: {
      id: Number(idUser),
    },
  });

  if (!user) {
    throw new HTTPException(400, {
      message: 'User not found',
    });
  }

  if (userData.role !== 'admin' && userData.id !== user.id) {
    throw new HTTPException(403, {
      message: 'Access forbidden',
    });
  }

  if (userData.role !== 'admin') {
    request.role = 'member';
  }

  if (request.password) {
    request.password = await bcrypt.hash(request?.password, 10);
  }

  const newData = await prismaClient.user.update({
    where: {
      id: Number(idUser),
    },
    data: request,
  });

  const resData = resJSON({
    data: newData,
  });

  return c.json(resData, resData.status as 200);
}

export async function DeleteUser(c: Context) {
  const idUser: any = c.req.param('id');

  if (isNaN(idUser)) {
    throw new HTTPException(400, {
      message: 'User not found',
    });
  }

  try {
    await prismaClient.user.delete({
      where: {
        id: Number(idUser),
      },
    });

    const resData = resJSON({
      message: 'Deleted user successfully',
    });

    return c.json(resData, resData.status as 200);
  } catch (err) {
    if (err.code === 'P2025') {
      // Record to delete not found
      throw new HTTPException(400, {
        message: 'User not found',
      });
    }

    // Handle another error
    throw err;
  }
}

export async function UserActivation(c: Context) {
  let request = c.get('jsonData');

  request = UserValidation.ACTIVATE.parse(request);

  try {
    const user = await prismaClient.user.update({
      where: {
        id: Number(request.id),
      },
      data: {
        is_active: request.is_active,
      },
    });

    const message = user.is_active
      ? 'User successfully activated'
      : 'User successfully deactivated';

    const resData = resJSON({
      message: message,
      data: user,
    });

    return c.json(resData, resData.status as 200);
  } catch (err) {
    // Prisma error code P2025 (record not found)
    if (err.code === 'P2025') {
      const resData = resJSON({
        status: 400,
        message: 'User not found',
      });
      return c.json(resData, resData.status as 400);
    }

    // Handle another error
    throw err;
  }
}
