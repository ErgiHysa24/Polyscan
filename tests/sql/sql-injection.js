const db = require("./db");

function concat(name) {
  // ruleid: polyscan-sql-javascript
  db.query("SELECT * FROM users WHERE name = '" + name + "'");
}

function template(name) {
  // ruleid: polyscan-sql-javascript
  db.query(`SELECT * FROM users WHERE name = '${name}'`);
}

function viaVariable(name) {
  const q = "DELETE FROM users WHERE name = '" + name + "'";
  // ruleid: polyscan-sql-javascript
  db.execute(q);
}

function parameterized(name) {
  // ok: polyscan-sql-javascript
  db.query("SELECT * FROM users WHERE name = ?", [name]);
}

function constantOnly() {
  // ok: polyscan-sql-javascript
  db.query("SELECT * FROM users");
}

function notSql(a, b) {
  // ok: polyscan-sql-javascript
  console.log("total: " + a + b);
}
