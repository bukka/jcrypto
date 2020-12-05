package eu.bukka.cipher;

import eu.bukka.options.CipherOptions;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.Security;

import static org.mockito.Mockito.*;

class CipherEnvelopeTest {

    @BeforeAll
    static void setUp() {
        Security.addProvider(new BouncyCastleProvider());
    }

    private byte[] bytes(String hex) {
        return new BigInteger(hex, 16).toByteArray();
    }

    @Test
    void encrypt() throws Exception {
        String key = "2b7e151628aed2a6abf7158809cf4f3c";
        byte[] input = bytes("6bc1bee22e409f96e93d7e117393172a");
        byte[] output = bytes("3ad77bb40d7a3660a89ecaf32466ef97");

        CipherOptions options = mock(CipherOptions.class);
        when(options.getAlgorithm()).thenReturn("AES-128-ECB");
        when(options.getInputData()).thenReturn(input);
        when(options.getKey()).thenReturn(key);

        CipherEnvelope envelope = new CipherEnvelope(options);
        envelope.encrypt();

        verify(options).writeOutputData(eq(output));
    }

    @Test
    void decrypt() {
    }
}