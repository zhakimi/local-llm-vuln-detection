import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import javax.servlet.http.HttpServletRequest;

public class InvoiceController {
    private static final Path INVOICE_DIR = Paths.get("/data/invoices").toAbsolutePath().normalize();

    public byte[] download(HttpServletRequest request) throws IOException {
        String name = request.getParameter("file");
        Path invoice = INVOICE_DIR.resolve(name).normalize();
        if (!invoice.startsWith(INVOICE_DIR)) {
            throw new SecurityException("invalid path");
        }
        return Files.readAllBytes(invoice);
    }
}
