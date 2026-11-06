import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class AccountDao {
    private final Connection conn;

    public AccountDao(Connection conn) {
        this.conn = conn;
    }

    public ResultSet findByEmail(String email) throws SQLException {
        PreparedStatement ps = conn.prepareStatement("SELECT id, balance FROM accounts WHERE email = ?");
        ps.setString(1, email);
        return ps.executeQuery();
    }
}
