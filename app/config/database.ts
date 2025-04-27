import { PrismaClient, Prisma } from '@prisma/client';
import { logger } from '@config/logging';

export const prismaClient = new PrismaClient({
  log: [
    { emit: 'event', level: 'query' },
    { emit: 'event', level: 'error' },
    { emit: 'event', level: 'info' },
    { emit: 'event', level: 'warn' },
  ],
});

prismaClient.$on('query', (e: Prisma.QueryEvent) => {
  logger.info({
    message: 'Prisma Query',
    query: e.query,
    params: e.params,
    duration: e.duration,
  });
});

prismaClient.$on('error', (e: Prisma.LogEvent) => {
  logger.error({
    message: e.message,
    target: e.target,
  });
});

prismaClient.$on('info', (e: Prisma.LogEvent) => {
  logger.info({
    message: e.message,
    target: e.target,
  });
});

prismaClient.$on('warn', (e: Prisma.LogEvent) => {
  logger.warn({
    message: e.message,
    target: e.target,
  });
});
