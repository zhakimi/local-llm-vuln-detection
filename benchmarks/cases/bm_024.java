import java.io.IOException;
import java.io.ObjectInputStream;
import javax.servlet.http.HttpServletRequest;

public class SessionImporter {
    public Object importSession(HttpServletRequest request) throws IOException, ClassNotFoundException {
        try (ObjectInputStream in = new ObjectInputStream(request.getInputStream())) {
            return in.readObject();
        }
    }
}
