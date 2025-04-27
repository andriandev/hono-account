import { Hono, Context } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { ZodError } from 'zod';
import middleware from '@middleware/default';
import routes from '@router/routes';
import { resJSON, formatZodErrors } from '@helpers/function';
import { logger } from '@config/logging';

// Config
export const app = new Hono(); // Export for testing function
const appPort = process.env.APP_PORT || 3001;
const appNode = process.env.APP_ENV || 'development';

// Middleware
app.route('/', middleware);

// Routes
app.route('/', routes);

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

// Run serve
const appOptions = {
  fetch: app.fetch,
  port: appPort,
};

export default appOptions;
