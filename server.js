require('dotenv').config()

const app = require('./app');
const port = 3000;
require('./database');
require('./redis/blocklist-access-token');
require('./redis/allowlist-refresh-tokens');

const routes = require('./rotas');
routes(app);

app.listen(port);
