package eu.bukka.jcrypto.test;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;

import java.math.BigInteger;
import java.security.Security;

public class CommonTest {

    @BeforeAll
    static void setUp() {
        Security.addProvider(new BouncyCastleProvider());
    }

    protected byte[] bytes(String hex) {
        return new BigInteger(hex, 16).toByteArray();
    }
}
