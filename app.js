const Koa = require('koa');
const Router = require('koa-router');
const session = require('koa-session');
const bodyParser = require('koa-bodyparser');
const fs = require('fs');

const app = new Koa();
const router = new Router();
const PORT = process.env.PORT || 3000;

const config = JSON.parse(fs.readFileSync('./config.json', 'utf8'));

app.keys = config.keys;

app.use(session(config.session, app));
app.use(bodyParser());

router.get('/auth', async (ctx) => {
  ctx.type = 'html';
  ctx.body = fs.readFileSync('./auth.html', 'utf8');
  if (ctx.query.originalUrl) {
    const originalUrl = ctx.query.originalUrl;
    if (originalUrl.startsWith('/')) {
      ctx.session.originalUrl = originalUrl;
    } else {
      console.warn('Invalid URL attempt:', originalUrl);
      ctx.session.originalUrl = '/';
    }
  }
});

router.get('/auth/verify', async (ctx) => {
  if (ctx.session.authenticated) {
    const requestedUrl = ctx.get('X-Original-URI');
    const isAllowed = ctx.session.scopes.some(scope => requestedUrl.startsWith(scope));

    if (isAllowed) {
      ctx.status = 200;
      ctx.body = 'Access granted.';
    } else {
      ctx.status = 403;
      ctx.body = 'Access denied: The token does not have permission for this scope.';
    }
  } else {
    ctx.status = 401;
    ctx.body = 'Authentication required.';
  }
});

router.post('/auth', async (ctx) => {
  const { token } = ctx.request.body;
  const allowedScopes = config.tokens[token];

  if (!allowedScopes) {
    ctx.status = 401;
    ctx.body = 'Authentication failed: Invalid token.';
    return;
  }
  ctx.session.authenticated = true;
  ctx.session.scopes = allowedScopes;

  if (ctx.session.originalUrl && ctx.session.originalUrl.startsWith('/')) {
    ctx.redirect(ctx.session.originalUrl);
    ctx.session.originalUrl = null;
  } else {
    ctx.redirect('/');
  }
});

app.use(router.routes()).use(router.allowedMethods());

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
