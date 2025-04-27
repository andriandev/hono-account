export const APP_SECRET_KEY = process.env.APP_SECRET_KEY;
export const APP_JWT_EXP: number =
  Number(process.env.APP_SECRET_KEY) ||
  Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 30; // 60 * 60 * 24 * 30 = 30 days
export const APP_JWT_SECRET: string =
  process.env.APP_JWT_SECRET ||
  'KSBCbbcjshdbcjKSJNCjkn327423897KJDSBCVhbsiouer327828';
