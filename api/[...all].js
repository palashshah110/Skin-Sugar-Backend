const serverless = require("serverless-http");
const app = require("./index"); // reuse your Express app

module.exports = serverless(app);
