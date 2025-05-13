import { z } from 'zod';

export class DatabaseValidation {
  static BACKUP = z.object({
    username: z.string({
      required_error: 'Username is required',
    }),
    password: z.string({
      required_error: 'Password is required',
    }),
    database: z.string({
      required_error: 'Database name is required',
    }),
  });

  static RESTORE = z.object({
    username: z.string().min(1),
    password: z.string(),
    database: z.string().min(1),
    filename: z.string().endsWith('.sql'),
  });
}
