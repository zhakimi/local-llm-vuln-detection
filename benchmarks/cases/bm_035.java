import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class Database {
    private static final String URL = "jdbc:postgresql://db.internal:5432/payroll";

    public static Connection open() throws SQLException {
        return DriverManager.getConnection(URL, "payroll_admin", "Pa55w0rd-Payroll!");
    }
}
