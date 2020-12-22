package eu.bukka.jcrypto.cipher;

import eu.bukka.jcrypto.options.CipherOptions;
import eu.bukka.jcrypto.test.CommonTest;
import org.junit.jupiter.api.Test;

import static org.mockito.Mockito.*;

class CipherEnvelopeTest extends CommonTest {
    @Test
    void encryptUsingAES128ECB() throws Exception {
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
    void encryptUsingAES128CBC() throws Exception {
        String key = "2b7e151628aed2a6abf7158809cf4f3c";
        String iv = "000102030405060708090A0B0C0D0E0F";
        byte[] input = bytes("6bc1bee22e409f96e93d7e117393172a");
        byte[] output = bytes("7649abac8119b246cee98e9b12e9197d");

        CipherOptions options = mock(CipherOptions.class);
        when(options.getAlgorithm()).thenReturn("AES-128-CBC");
        when(options.getInputData()).thenReturn(input);
        when(options.getKey()).thenReturn(key);
        when(options.getIv()).thenReturn(iv);

        CipherEnvelope envelope = new CipherEnvelope(options);
        envelope.encrypt();

        verify(options).writeOutputData(eq(output));
    }

    @Test
    void decrypt() {
    }
}