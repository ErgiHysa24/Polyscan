const { exec } = require("child_process");
const express = require("express");
const app = express();

app.get("/run", (req, res) => {
  exec("ls " + req.query.dir, (err, out) => res.send(out)); // command injection
});

app.get("/calc", (req, res) => {
  res.send(String(eval(req.query.expr))); // eval of user input
});

app.get("/", (req, res) => {
  res.send("<h1>" + req.query.name + "</h1>"); // reflected XSS
});

app.listen(3000);
