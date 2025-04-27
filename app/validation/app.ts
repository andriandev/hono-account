import { z } from 'zod';

export class AppValidation {
  static GET = z.object({
    limit: z.coerce
      .number({
        invalid_type_error: 'Limit must be a number',
      })
      .min(1)
      .optional(),
    offset: z.coerce
      .number({
        invalid_type_error: 'Offset must be a number',
      })
      .min(0)
      .optional(),
    take_user: z.coerce
      .boolean({
        invalid_type_error: 'Query take_user must be a boolean (true or false)',
      })
      .optional()
      .default(false),
  });

  static CREATE = z.object({
    name: z
      .string({
        required_error: 'Name app is required',
      })
      .min(1, 'Name app must be at least 1 characters')
      .max(100, 'Name app max 100 characters'),
    url: z
      .string({
        required_error: 'Url app is required',
      })
      .url('Url must be valid')
      .max(100, 'Url max 100 characters'),
  });

  static UPDATE = z.object({
    name: z
      .string({
        required_error: 'Name app is required',
      })
      .min(1, 'Name app must be at least 1 characters')
      .max(100, 'Name app max 100 characters')
      .optional(),
    url: z
      .string({
        required_error: 'Url app is required',
      })
      .url('Url must be valid')
      .max(100, 'Url max 100 characters')
      .optional(),
  });

  static CONNECT = z.object({
    user_id: z.coerce
      .number({
        invalid_type_error: 'Query user_id must be a number',
      })
      .min(1, 'Query user_id min 1 characters'),
    app_id: z.coerce
      .number({
        invalid_type_error: 'Query app_id must be a number',
      })
      .min(1, 'Query app_id min 1 characters'),
  });
}
