package eu.bukka.jcrypto.cipher;

import eu.bukka.jcrypto.options.CipherOptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.security.InvalidParameterException;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class CipherAlgorithmTest {

    @Test
    void transform() {
        CipherAlgorithm algorithm = new CipherAlgorithm("AES", "CBC", "NoPadding", 128);
        assertEquals("AES/CBC/NoPadding", algorithm.transform());
    }

    @Test
    void getKeySize() {
        CipherAlgorithm algorithm = new CipherAlgorithm("AES", "CBC", "NoPadding", 256);
        assertEquals(256, algorithm.getKeySize());
    }

    @Test
    void getCipher() {
        CipherAlgorithm algorithm = new CipherAlgorithm("AES", "CBC");
        assertEquals("AES", algorithm.getCipher());
    }

    @Test
    void isStreamMode() {
        assertFalse(new CipherAlgorithm("AES", "CBC").isStreamMode());
        assertTrue(new CipherAlgorithm("AES", "CTR").isStreamMode());
    }


    @Test
    void hasIv() {
        assertTrue(new CipherAlgorithm("AES", "CBC").hasIv(), "The CBC mode has IV");
        assertFalse(new CipherAlgorithm("AES", "ECB").hasIv(), "The ECB mode does not have IV");
    }

    @Test
    void throwIfPaddingSetForStreamMode() {
        Exception exception = assertThrows(InvalidParameterException.class, () -> {
            new CipherAlgorithm("AES", "CTR", "PKCS5Padding", 256);
        });
        assertEquals("Padding cannot be used for stream mode", exception.getMessage());
    }

    @Test
    void throwIfEmptyAlgorithm() {
        Exception exception = assertThrows(InvalidParameterException.class, () -> {
            CipherOptions options = mock(CipherOptions.class);
            when(options.getAlgorithm()).thenReturn("");
            CipherAlgorithm.fromOptions(options);
        });
        assertEquals("Algorithm cannot be an empty string", exception.getMessage());
    }

    @Test
    void throwIfInvalidAlgorithm() {
        Exception exception = assertThrows(InvalidParameterException.class, () -> {
            CipherOptions options = mock(CipherOptions.class);
            when(options.getAlgorithm()).thenReturn("A/B/C/D");
            CipherAlgorithm.fromOptions(options);
        });
        assertEquals("Invalid algorithm A/B/C/D", exception.getMessage());
    }

    @ParameterizedTest
    @MethodSource("cipherAlgorithmProvider")
    void fromOptions(String algorithm, String padding, String cipher, int keySize) {
        CipherOptions options = mock(CipherOptions.class);
        when(options.getAlgorithm()).thenReturn(algorithm);
        when(options.getPadding()).thenReturn(padding);

        CipherAlgorithm cipherAlgorithm = CipherAlgorithm.fromOptions(options);

        assertEquals(cipher, cipherAlgorithm.transform());
        assertEquals(keySize, cipherAlgorithm.getKeySize());
    }

    static Stream<Arguments> cipherAlgorithmProvider() {
        return Stream.of(
                Arguments.of("AES128_CCM", "NoPadding", "AES/CCM/NoPadding", 128),
                Arguments.of("AES256_CCM", "PKCS5Padding", "AES/CCM/PKCS5Padding", 256),
                Arguments.of("AES-128-GCM", "NoPadding", "AES/GCM/NoPadding", 128),
                Arguments.of("aes-256-gcm", "PKCS5Padding", "AES/GCM/PKCS5Padding", 256),
                Arguments.of("AES128_CBC", "NoPadding", "AES/CBC/NoPadding", 128),
                Arguments.of("AES-256-CBC", "PKCS5Padding", "AES/CBC/PKCS5Padding", 256),
                Arguments.of("AES-128-CTR", "NoPadding", "AES/CTR/NoPadding", 128),
                Arguments.of("aes-256-ctr", "NoPadding", "AES/CTR/NoPadding", 256),
                Arguments.of("AES-128-CFB", "NoPadding", "AES/CFB/NoPadding", 128),
                Arguments.of("aes256_cfb", "NoPadding", "AES/CFB/NoPadding", 256),
                Arguments.of("AES-128-OFB", "NoPadding", "AES/OFB/NoPadding", 128),
                Arguments.of("AES/GCM/PKCS5Padding", "NoPadding", "AES/GCM/PKCS5Padding", 0),
                Arguments.of("AES/CBC/NoPadding", "NoPadding", "AES/CBC/NoPadding", 0),
                Arguments.of("AES/CCM", "PKCS5Padding", "AES/CCM/PKCS5Padding", 0),
                Arguments.of("ChaCha7539", "NoPadding", "ChaCha7539", 0)
        );
    }
}