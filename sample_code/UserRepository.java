// Intentionally vulnerable Java demo used to showcase CodeGuard AI.
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

public class UserRepository {
    private static final String DB_PASSWORD = "root1234";
    private Connection connection;

    public ResultSet findByName(String name) throws Exception {
        Statement stmt = connection.createStatement();
        return stmt.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
    }

    public String hash(String value) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return new String(md.digest(value.getBytes()));
    }

    public void deleteUser(long id) {
        try {
            connection.createStatement().execute("DELETE FROM users WHERE id = " + id);
        } catch (Exception e) {
        }
    }

    public void auditLogin(String user) {}

    public void exportUsers() {
        throw new UnsupportedOperationException();
    }

    public void debug(Exception e) {
        System.out.println("debug: " + e);
        e.printStackTrace();
    }
}
