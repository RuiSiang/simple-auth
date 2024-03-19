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
});

router.post('/auth', async (ctx) => {
  if (ctx.session.authenticated) {
    const requestedUrl = ctx.get('X-Original-URI');
    const isAllowed = ctx.session.scopes.some(scope => requestedUrl.startsWith(scope));

    if (isAllowed) {
      ctx.body = 'Access granted.';
    } else {
      ctx.status = 403;
      ctx.body = 'Access denied: The token does not have permission for this scope.';
    }
    return;
  }

  const { token } = ctx.request.body;
  const allowedScopes = config.tokens[token];

  if (!allowedScopes) {
    ctx.status = 401;
    ctx.body = 'Authentication failed: Invalid token.';
    return;
  }

  const requestedUrl = ctx.get('X-Original-URI');
  const isAllowed = allowedScopes.some(scope => requestedUrl.startsWith(scope));

  if (isAllowed) {
    ctx.session.authenticated = true;
    ctx.session.scopes = allowedScopes;
    ctx.body = 'Authenticated successfully.';
  } else {
    ctx.status = 403;
    ctx.body = 'Access denied: The token does not have permission for this scope.';
  }
});

app.use(router.routes()).use(router.allowedMethods());

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
