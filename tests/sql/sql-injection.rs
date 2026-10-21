fn format_then_execute(conn: &Connection, name: &str) {
    // ruleid: polyscan-sql-rust
    let q = format!("SELECT * FROM users WHERE name = '{}'", name);
    conn.execute(&q, []).unwrap();
}

fn with_params_macro(conn: &Connection, name: &str) {
    // ruleid: polyscan-sql-rust
    let q = format!("SELECT * FROM users WHERE name = '{}'", name);
    conn.execute(&q, params![name]).unwrap();
}

fn passed_by_value(conn: &Connection, name: &str) {
    // ruleid: polyscan-sql-rust
    let q = format!("UPDATE users SET admin = 1 WHERE name = '{}'", name);
    conn.execute(q, []).unwrap();
}

fn format_inline(client: &mut Client, name: &str) {
    // ruleid: polyscan-sql-rust
    client.query(&format!("DELETE FROM users WHERE name = '{}'", name), &[]).unwrap();
}

async fn sqlx_style(pool: &Pool, name: &str) {
    // ruleid: polyscan-sql-rust
    let q = format!("SELECT * FROM users WHERE name = '{}'", name);
    sqlx::query(&q).fetch_all(pool).await.unwrap();
}

fn bound(conn: &Connection, name: &str) {
    // ok: polyscan-sql-rust
    conn.execute("SELECT * FROM users WHERE name = ?1", [name]).unwrap();
}

fn constant_only(conn: &Connection) {
    // ok: polyscan-sql-rust
    conn.execute("SELECT * FROM users", []).unwrap();
}

fn not_sql(a: &str) {
    // ok: polyscan-sql-rust
    println!("{}", format!("total: {}", a));
}
