use std::process::Command;

fn main() {
    let arg = std::env::args().nth(1).unwrap_or_default();
    // command built from user input, run through a shell
    let _ = Command::new("sh").arg("-c").arg(format!("ls {}", arg)).status();

    let v = vec![1u8, 2, 3];
    let x = unsafe { *v.as_ptr().add(5) }; // out of bounds read
    println!("{}", x);
}

#[allow(dead_code)]
fn find_user(conn: &rusqlite::Connection, name: &str) {
    let q = format!("SELECT * FROM users WHERE name = '{}'", name); // SQL injection
    conn.execute(&q, []).unwrap();
}
