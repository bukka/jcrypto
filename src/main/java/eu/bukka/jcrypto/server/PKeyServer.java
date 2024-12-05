package eu.bukka.jcrypto.server;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import eu.bukka.jcrypto.options.PKeyOptions;
import eu.bukka.jcrypto.pkey.KeyAgreementEnvelope;
import eu.bukka.jcrypto.pkey.KeyGeneratorEnvelope;
import eu.bukka.jcrypto.pkey.SignatureEnvelope;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.Executors;

public class PKeyServer {

    private final HttpServer server;
    private final KeyAgreementEnvelope keyAgreementEnvelope;
    private final KeyGeneratorEnvelope keyGeneratorEnvelope;
    private final SignatureEnvelope signatureEnvelope;

    public PKeyServer(PKeyOptions options, int port) throws Exception {
        this.keyAgreementEnvelope = new KeyAgreementEnvelope(options);
        this.keyGeneratorEnvelope = new KeyGeneratorEnvelope(options);
        this.signatureEnvelope = new SignatureEnvelope(options);

        this.server = HttpServer.create(new InetSocketAddress(port), 0);
        this.server.createContext("/pkey/sign", this::handleSign);
        this.server.createContext("/pkey/verify", this::handleVerify);
        this.server.createContext("/pkey/derive", this::handleDerive);
        this.server.createContext("/pkey/generate", this::handleGenerate);

        this.server.setExecutor(Executors.newFixedThreadPool(4));
    }

    public void start() {
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.out.println("Shutting down server...");
            server.stop(0);
            synchronized (this) {
                this.notify();
            }
        }));

        this.server.start();
        System.out.println("PKeyServer running...");

        synchronized (this) {
            try {
                this.wait();
            } catch (InterruptedException e) {
                System.out.println("Server interrupted, shutting down...");
                Thread.currentThread().interrupt();
            }
        }
    }


    private void handleSign(HttpExchange exchange) throws IOException {
        if (!"POST".equals(exchange.getRequestMethod())) {
            sendResponse(exchange, 405, "Method Not Allowed");
            return;
        }
        try {
            byte[] data = exchange.getRequestBody().readAllBytes();
            byte[] signature = signatureEnvelope.sign(data);
            String hexSignature = bytesToHex(signature);
            sendResponse(exchange, 200, hexSignature);
        } catch (Exception e) {
            sendResponse(exchange, 500, e.getMessage());
        }
    }

    private void handleVerify(HttpExchange exchange) throws IOException {
        if (!"POST".equals(exchange.getRequestMethod())) {
            sendResponse(exchange, 405, "Method Not Allowed");
            return;
        }
        try {
            byte[] data = exchange.getRequestBody().readAllBytes();

            Map<String, String> queryParams = parseQueryParams(exchange.getRequestURI());
            if (!queryParams.containsKey("signature")) {
                sendResponse(exchange, 400, "Missing query parameter: signature");
                return;
            }
            byte[] signature = hexToBytes(queryParams.get("signature"));

            boolean isValid = signatureEnvelope.verify(data, signature);
            sendResponse(exchange, 200, isValid ? "Valid signature" : "Invalid signature");
        } catch (Exception e) {
            sendResponse(exchange, 500, e.getMessage());
        }
    }

    private void handleDerive(HttpExchange exchange) throws IOException {
        if (!"POST".equals(exchange.getRequestMethod())) {
            sendResponse(exchange, 405, "Method Not Allowed");
            return;
        }
        try {
            byte[] pubKeyBytes = exchange.getRequestBody().readAllBytes();
            byte[] sharedSecret = keyAgreementEnvelope.derive(pubKeyBytes);
            String hexSecret = bytesToHex(sharedSecret);
            sendResponse(exchange, 200, hexSecret);
        } catch (Exception e) {
            sendResponse(exchange, 500, e.getMessage());
        }
    }

    private void handleGenerate(HttpExchange exchange) throws IOException {
        if (!"POST".equals(exchange.getRequestMethod())) {
            sendResponse(exchange, 405, "Method Not Allowed");
            return;
        }
        try {
            String keyName = parseQueryParams(exchange.getRequestURI()).get("keyName");
            byte[] publicKeyEncodedData = keyGeneratorEnvelope.generate(keyName);

            // Convert to PEM format
            String pemPublicKey = toPem("PUBLIC KEY", Base64.getEncoder().encodeToString(publicKeyEncodedData));
            sendResponse(exchange, 200, pemPublicKey);
        } catch (Exception e) {
            sendResponse(exchange, 500, e.getMessage());
        }
    }

    private Map<String, String> parseQueryParams(java.net.URI uri) {
        String query = uri.getQuery();
        return query == null ? Map.of() : Map.of(query.split("=")[0], query.split("=")[1]);
    }

    private void sendResponse(HttpExchange exchange, int statusCode, String message) throws IOException {
        exchange.sendResponseHeaders(statusCode, message.getBytes().length);
        exchange.getResponseBody().write(message.getBytes());
        exchange.close();
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] bytes = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            bytes[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return bytes;
    }

    private String toPem(String type, String base64Content) {
        return "-----BEGIN " + type + "-----\n" +
                base64Content.replaceAll("(.{64})", "$1\n") +
                "\n-----END " + type + "-----\n";
    }
}
