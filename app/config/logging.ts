import winston, { format, transports, Logger } from 'winston';

const isProduction = process.env.APP_ENV === 'production';

export const logger: Logger = winston.createLogger({
  level: isProduction ? 'warn' : 'info',
  format: isProduction
    ? format.json()
    : format.combine(format.colorize(), format.simple()),
  transports: [new transports.Console()],
});
