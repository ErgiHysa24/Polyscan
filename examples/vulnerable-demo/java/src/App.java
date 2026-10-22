import java.io.IOException;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class App {
    static ResultSet find(Connection db, String name) throws SQLException {
        Statement st = db.createStatement();
        return st.executeQuery("SELECT * FROM users WHERE name = '" + name + "'"); // SQL injection
    }

    static void run(String arg) throws IOException {
        Runtime.getRuntime().exec("sh -c " + arg); // command injection
    }
}
