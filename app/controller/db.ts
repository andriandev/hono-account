import fs from 'fs';
import path from 'path';
import { Context } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { resJSON, formatDateTime } from '@app/helpers/function';
import { DatabaseValidation } from '@app/validation/db';
import { logging } from '@app/config/logging';

type DatabaseList = Record<
  string,
  Array<{
    name: string;
    timestamp: number;
    datetime: string;
    status: 'done' | 'pending';
  }>
>;

export async function GetBackup(c: Context) {
  const folderPath = path.join(process.cwd(), 'backups');

  if (!fs.existsSync(folderPath)) {
    fs.mkdirSync(folderPath);
  }

  const files = fs.readdirSync(folderPath);

  // Map database name ke array file
  const grouped: DatabaseList = {};

  files
    .filter((name) => name.endsWith('.sql'))
    .forEach((name) => {
      const match = name.match(/^backup-(.+)-(\d+)\.sql$/);
      if (!match) return;

      const [, db, timestampStr] = match;
      const timestamp = Number(timestampStr);

      const donePath = path.join(
        folderPath,
        `backup-${db}-${timestamp}.sql.done`
      );
      const status = fs.existsSync(donePath) ? 'done' : 'pending';

      if (!grouped[db]) grouped[db] = [];

      grouped[db].push({
        name,
        timestamp,
        datetime: formatDateTime(timestamp),
        status,
      });
    });

  // Urutkan masing-masing grup dari terbaru ke terlama
  for (const db in grouped) {
    grouped[db].sort((a, b) => b.timestamp - a.timestamp);
  }

  const resData = resJSON({
    data: grouped,
  });

  return c.json(resData, resData.status as 200);
}

export async function CreateBackup(c: Context) {
  const rawRequest = c.get('jsonData');

  const request = DatabaseValidation.BACKUP.parse(rawRequest);

  const { username, password, database } = request;

  const folderPath = path.join(process.cwd(), 'backups');

  // Buat folder jika belum ada
  if (!fs.existsSync(folderPath)) {
    fs.mkdirSync(folderPath, { recursive: true });
  }

  const timestamp = Date.now();
  const filename = `backup-${database}-${timestamp}.sql`;
  const filepath = path.join(folderPath, filename);
  const doneFlag = filepath + '.done';

  try {
    // Jalankan mysqldump di background
    const proc = Bun.spawn(
      [
        'mysqldump',
        '--column-statistics=0',
        '-u',
        username,
        `-p${password}`,
        database,
      ],
      {
        stdout: Bun.file(filepath),
        stderr: 'pipe',
      }
    );

    // Tunggu di background, lalu buat file .done jika sukses
    proc.exited.then(async (exitCode) => {
      if (exitCode === 0) {
        fs.writeFileSync(doneFlag, '');
        logging.info(`Created ${filename}`);
      } else {
        const err = await new Response(proc.stderr).text();
        logging.error('Backup failed:', err || 'Unknown error');

        // Hapus file jika gagal
        if (fs.existsSync(filepath)) fs.unlinkSync(filepath);
        if (fs.existsSync(doneFlag)) fs.unlinkSync(doneFlag);
      }
    });

    // Langsung respon sukses meskipun backup belum selesai
    const resData = resJSON({
      message: 'Backup running in background',
    });

    return c.json(resData, resData.status as 200);
  } catch (error: any) {
    const resData = resJSON({
      statusCode: 500,
      message: error.message,
    });

    return c.json(resData, resData.status as 500);
  }
}

export async function DeleteBackup(c: Context) {
  const folderPath = path.join(process.cwd(), 'backups');

  try {
    if (fs.existsSync(folderPath)) {
      fs.rmSync(folderPath, { recursive: true, force: true });
    }

    fs.mkdirSync(folderPath);

    const resData = resJSON({ message: 'All backup files deleted' });
    return c.json(resData, resData.status as 200);
  } catch (error: any) {
    const message = error.message || 'Failed to delete backup folder';

    logging.error(message);
    throw new HTTPException(500, {
      message: message,
    });
  }
}

export async function DownloadBackup(c: Context) {
  const filename = c.req.param('filename');

  const filePath = path.join(process.cwd(), 'backups', filename);

  // Cek apakah file ada
  if (!fs.existsSync(filePath)) {
    throw new HTTPException(404, { message: 'File not found' });
  }

  // Kirim file sebagai download dengan c.body
  const fileBuffer = fs.readFileSync(filePath);

  logging.info(`Download ${filename}`);

  return c.body(fileBuffer, 200, {
    'Content-Type': 'application/octet-stream',
    'Content-Disposition': `attachment; filename="${filename}"`,
  });
}

export async function RestoreBackup(c: Context) {
  const rawRequest = c.get('jsonData');

  const request = DatabaseValidation.RESTORE.parse(rawRequest);

  const { username, password, database, filename } = request;

  const folderPath = path.join(process.cwd(), 'backups');
  const filepath = path.join(folderPath, filename);

  // Cek apakah file ada
  if (!fs.existsSync(filepath)) {
    const resData = resJSON({
      statusCode: 400,
      message: 'File backup tidak ditemukan',
    });

    return c.json(resData, resData.status as 400);
  }

  try {
    const proc = Bun.spawn(
      ['mysql', '-u', username, `-p${password}`, database],
      {
        stdin: Bun.file(filepath),
        stderr: 'pipe',
      }
    );

    proc.exited.then(async (exitCode) => {
      if (exitCode === 0) {
        logging.info(`Restore ${filename}`);
      } else {
        const err = await new Response(proc.stderr).text();
        logging.error(`Restore failed: ${err || 'Unknown error'}`);
      }
    });

    const resData = resJSON({
      message: 'Restore running in background',
    });

    return c.json(resData, resData.status as 200);
  } catch (error: any) {
    const resData = resJSON({
      statusCode: 500,
      message: error.message,
    });

    return c.json(resData, resData.status as 500);
  }
}

export async function UploadBackup(c: Context) {
  const formData = await c.req.formData();
  const file = formData.get('file');

  if (!(file instanceof File)) {
    const resData = resJSON({
      statusCode: 400,
      message: 'Invalid file',
    });

    return c.json(resData, resData.status as 400);
  }

  const folderPath = path.join(process.cwd(), 'backups');

  if (!fs.existsSync(folderPath)) {
    fs.mkdirSync(folderPath, { recursive: true });
  }

  const filename = file.name;
  const filepath = path.join(folderPath, filename);
  const doneFlag = filepath + '.done';

  if (fs.existsSync(filepath)) {
    const resData = resJSON({
      statusCode: 400,
      message: 'File already exists',
    });

    return c.json(resData, resData.status as 400);
  }

  try {
    const buffer = Buffer.from(await file.arrayBuffer());
    fs.writeFileSync(filepath, buffer);
    fs.writeFileSync(doneFlag, '');

    logging.info(`Upload ${file.name}`);

    const resData = resJSON({
      message: 'Backup file uploaded successfully',
      data: { filename },
    });

    return c.json(resData, resData.status as 200);
  } catch (error: any) {
    const resData = resJSON({
      statusCode: 500,
      message: error.message,
    });

    return c.json(resData, resData.status as 500);
  }
}
