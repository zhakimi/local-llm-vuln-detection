import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import javax.servlet.http.HttpServletRequest;

public class InvoiceController {
    private static final String INVOICE_DIR = "/data/invoices";

    public byte[] download(HttpServletRequest request) throws IOException {
        String name = request.getParameter("file");
        File invoice = new File(INVOICE_DIR, name);
        return Files.readAllBytes(invoice.toPath());
    }
}
