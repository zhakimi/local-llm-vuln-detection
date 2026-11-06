import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class AccountDao {
    private final Connection conn;

    public AccountDao(Connection conn) {
        this.conn = conn;
    }

    public ResultSet findByEmail(String email) throws SQLException {
        Statement stmt = conn.createStatement();
        return stmt.executeQuery("SELECT id, balance FROM accounts WHERE email = '" + email + "'");
    }
}
