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
        assertTrue(new CipherAlgorithm("AES", "CRT").isStreamMode());
    }


    @Test
    void hasIv() {
        assertTrue(new CipherAlgorithm("AES", "CBC").hasIv(), "The CBC mode has IV");
        assertFalse(new CipherAlgorithm("AES", "ECB").hasIv(), "The ECB mode does not have IV");
    }

    @Test
    void throwIfPaddingSetForStreamMode() {
        Exception exception = assertThrows(InvalidParameterException.class, () -> {
            new CipherAlgorithm("AES", "CRT", "PKCS5Padding", 256);
        });
        assertEquals("Padding is not used for stream mode", exception.getMessage());
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
                Arguments.of("AES-128-CRT", "NoPadding", "AES/CRT/NoPadding", 128),
                Arguments.of("aes-256-crt", "NoPadding", "AES/CRT/NoPadding", 256),
                Arguments.of("AES-128-CFB", "NoPadding", "AES/CFB/NoPadding", 128),
                Arguments.of("aes256_cfb", "NoPadding", "AES/CFB/NoPadding", 256),
                Arguments.of("AES-128-OFB", "NoPadding", "AES/OFB/NoPadding", 128),
                Arguments.of("AES256_ofb", "NoPadding", "AES/OFB/NoPadding", 256)
        );
    }
}