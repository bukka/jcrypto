package eu.bukka.cipher;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;

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
}