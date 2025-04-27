import { Hono } from 'hono';
import { serveStatic } from 'hono/bun';
import { Register, Login, Logout, Verify } from '@controller/auth';
import {
  GetUser,
  CreateUser,
  UpdateUser,
  DeleteUser,
  UserActivation,
} from '@app/controller/user';
import {
  GetApp,
  CreateApp,
  UpdateApp,
  DeleteApp,
  ConnectUserApp,
} from '@app/controller/app';
('@app/controller/link');
import { is_admin, is_login, is_admin_or_key } from '@app/middleware/auth';
import { check_json } from '@app/middleware/json';

const app = new Hono();

app.use('/favicon.ico', serveStatic({ path: './favicon.ico' }));

app.post('/auth/register', check_json, Register);
app.post('/auth/login', check_json, Login);
app.get('/auth/logout', Logout);
app.get('/auth/verify', is_login, Verify);

app.get('/user/:id?', is_admin, GetUser);
app.post('/user', check_json, is_admin, CreateUser);
app.put('/user/:id', check_json, is_admin, UpdateUser);
app.delete('/user/:id', is_admin, DeleteUser);
app.post('/user/activate', check_json, is_admin_or_key, UserActivation);

app.get('/app/connect', is_admin, ConnectUserApp);
app.get('/app/:id?', is_admin, GetApp);
app.post('/app', check_json, is_admin, CreateApp);
app.put('/app/:id', check_json, is_admin, UpdateApp);
app.delete('/app/:id', is_admin, DeleteApp);

export default app;
