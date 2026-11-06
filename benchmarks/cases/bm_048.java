import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import javax.servlet.http.HttpServletRequest;

public class DnsTool {
    public String lookup(HttpServletRequest request) throws IOException {
        String host = request.getParameter("host");
        Process p = Runtime.getRuntime().exec(new String[] {"/bin/sh", "-c", "nslookup " + host});
        try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = r.readLine()) != null) {
                sb.append(line).append('\n');
            }
            return sb.toString();
        }
    }
}
