import java.net.URL;
import javax.net.ssl.HttpsURLConnection;

public final class HttpsProbe {
    private HttpsProbe() {}

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            throw new IllegalArgumentException("expected exactly one HTTPS URL");
        }
        URL url = new URL(args[0]);
        if (!"https".equalsIgnoreCase(url.getProtocol())) {
            throw new IllegalArgumentException("probe URL must use HTTPS");
        }

        HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
        connection.setConnectTimeout(10_000);
        connection.setReadTimeout(10_000);
        connection.setInstanceFollowRedirects(false);
        connection.setRequestMethod("GET");
        connection.setRequestProperty("User-Agent", "traffic-e2e-java-truststore-preflight");
        connection.setRequestProperty("X-Traffic-E2E-Probe-Origin", "source");
        int status = connection.getResponseCode();
        connection.disconnect();
        if (status < 100) {
            throw new IllegalStateException("invalid HTTPS response status: " + status);
        }
    }
}
