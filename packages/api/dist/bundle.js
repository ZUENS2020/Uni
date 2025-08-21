// packages/api/index.js
var express = require("express");
var cors = require("cors");
var app = express();
var port = 3001;
app.use(cors());
app.use(express.json());
app.get("/ping", (req, res) => {
  res.json({ message: "pong" });
});
app.listen(port, () => {
  console.log(`Server listening at http://localhost:${port}`);
});
