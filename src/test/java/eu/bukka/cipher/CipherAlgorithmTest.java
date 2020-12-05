package eu.bukka.cipher;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class CipherAlgorithmTest {

    @Test
    void transform() {
        CipherAlgorithm algorithm = new CipherAlgorithm("AES", "CBC", "NoPadding", 128);
        assertEquals("AES/CBC/NoPadding", algorithm.transform());
    }

    @Test
    void getCipher() {
        CipherAlgorithm algorithm = new CipherAlgorithm("AES", "CBC");
        assertEquals("AES", algorithm.getCipher());
    }

    @Test
    void hasIv() {
        assertTrue(new CipherAlgorithm("AES", "CBC").hasIv(), "The CBC mode has IV");
        assertFalse(new CipherAlgorithm("AES", "ECB").hasIv(), "The ECB mode does not have IV");
    }
}