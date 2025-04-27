import { Context } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { prismaClient } from '@app/config/database';
import { AppValidation } from '@app/validation/app';
import { resJSON } from '@app/helpers/function';
import { hashId } from '@app/helpers/hashids';

export async function GetApp(c: Context) {
  const idApp: any = c.req.param('id');
  const rawQuery = c.req.query();
  const query = AppValidation.GET.parse(rawQuery);
  let data: any = {};

  if (idApp) {
    if (isNaN(idApp)) {
      throw new HTTPException(400, {
        message: 'App not found',
      });
    }

    const app = await prismaClient.app.findFirst({
      where: {
        id: Number(idApp),
      },
      include: query.take_user
        ? {
            users: {
              include: {
                user: {
                  omit: { password: true, created_at: true, updated_at: true },
                },
              },
            },
          }
        : undefined,
    });

    if (!app) {
      throw new HTTPException(400, {
        message: 'App not found',
      });
    }

    const { id, ...rest } = app;
    const orderedResponse = {
      id,
      hash_id: hashId.encode(id),
      ...rest,
    };

    data = orderedResponse;
  } else {
    const limit = query.limit ? Number(query.limit) : 10;
    const offset = query.offset ? Number(query.offset) : 0;

    const [apps, totalApps] = await Promise.all([
      prismaClient.app.findMany({
        skip: offset,
        take: limit,
      }),
      prismaClient.app.count(),
    ]);

    const transformedApps = apps.map((app) => {
      const { id, ...rest } = app;
      if (!app.id) return null;
      return {
        id,
        hash_id: hashId.encode(id),
        ...rest,
      };
    });

    const totalPages = Math.ceil(totalApps / limit);
    const currentPage = Math.floor(offset / limit) + 1;

    data.apps = transformedApps;
    data.paging = {
      total_apps: totalApps,
      total_pages: totalPages,
      current_page: currentPage,
    };
  }

  const resData = resJSON({
    data: data,
  });

  return c.json(resData, resData.status as 200);
}

export async function CreateApp(c: Context) {
  let request = c.get('jsonData');

  request = AppValidation.CREATE.parse(request);

  const checkApp = await prismaClient.app.findFirst({
    where: {
      name: request.name,
    },
  });

  if (checkApp) {
    throw new HTTPException(400, {
      message: 'App is already exist',
    });
  }

  const app = await prismaClient.app.create({
    data: request,
  });

  const resData = resJSON({
    data: app,
  });

  return c.json(resData, resData.status as 200);
}

export async function UpdateApp(c: Context) {
  const idApp: any = c.req.param('id');
  let request = c.get('jsonData');

  if (isNaN(idApp)) {
    throw new HTTPException(400, {
      message: 'App not found',
    });
  }

  request = AppValidation.UPDATE.parse(request);

  const app = await prismaClient.app.findFirst({
    where: {
      id: Number(idApp),
    },
  });

  if (!app) {
    throw new HTTPException(400, {
      message: 'App not found',
    });
  }

  const newData = await prismaClient.app.update({
    where: {
      id: Number(idApp),
    },
    data: request,
  });

  const resData = resJSON({
    data: newData,
  });

  return c.json(resData, resData.status as 200);
}

export async function DeleteApp(c: Context) {
  const idApp: any = c.req.param('id');

  if (isNaN(idApp)) {
    throw new HTTPException(400, {
      message: 'App not found',
    });
  }

  try {
    await prismaClient.app.delete({
      where: {
        id: Number(idApp),
      },
    });

    const resData = resJSON({
      message: 'Deleted app successfully',
    });

    return c.json(resData, resData.status as 200);
  } catch (err) {
    if (err.code === 'P2025') {
      // Record to delete not found
      throw new HTTPException(400, {
        message: 'App not found',
      });
    }

    // Handle another error
    throw err;
  }
}

export async function ConnectUserApp(c: Context) {
  try {
    const query = c.req.query();

    const request = AppValidation.CONNECT.parse(query);

    const data = await prismaClient.userApp.create({
      data: {
        user: { connect: { id: request.user_id } },
        app: { connect: { id: request.app_id } },
      },
    });

    const resData = resJSON({
      data: data,
    });

    return c.json(resData, resData.status as 200);
  } catch (err) {
    if (err.code === 'P2025') {
      // Record to connect not found
      throw new HTTPException(400, {
        message: 'User or App not found',
      });
    }

    // Duplikat relasi
    if (err.code === 'P2002') {
      throw new HTTPException(400, {
        message: 'This user is already connected to the app',
      });
    }

    // Handle another error
    throw err;
  }
}
