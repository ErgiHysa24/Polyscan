import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;

class Demo {
    void concat(Connection db, String name) throws SQLException {
        Statement st = db.createStatement();
        // ruleid: polyscan-sql-java
        st.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
    }

    void format(Connection db, String name) throws SQLException {
        Statement st = db.createStatement();
        // ruleid: polyscan-sql-java
        st.executeUpdate(String.format("DELETE FROM users WHERE name = '%s'", name));
    }

    void viaVariable(Connection db, String name) throws SQLException {
        String q = "SELECT * FROM users WHERE name = '" + name + "'";
        // ruleid: polyscan-sql-java
        db.prepareStatement(q);
    }

    void parameterized(Connection db, String name) throws SQLException {
        // ok: polyscan-sql-java
        PreparedStatement ps = db.prepareStatement("SELECT * FROM users WHERE name = ?");
        ps.setString(1, name);
        ps.executeQuery();
    }

    void constantOnly(Statement st) throws SQLException {
        // ok: polyscan-sql-java
        st.executeQuery("SELECT * FROM users");
    }
}
