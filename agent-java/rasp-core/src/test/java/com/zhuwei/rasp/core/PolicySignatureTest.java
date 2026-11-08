package com.zhuwei.rasp.core;

import com.zhuwei.rasp.core.policy.ConfigManager;
import com.zhuwei.rasp.core.policy.PolicyVerifier;
import com.zhuwei.rasp.core.policy.RuntimeConfig;
import com.zhuwei.rasp.core.util.Json;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PolicySignatureTest {

    @TempDir
    File home;
    KeyPair kp;
    PolicyVerifier verifier;

    @BeforeEach
    void setUp() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        kp = g.generateKeyPair();
        verifier = PolicyVerifier.fromSettings(Base64.getEncoder().encodeToString(kp.getPublic().getEncoded()), "");
        ConfigManager.init(home, verifier, "key-1");
    }

    private Map<String, Object> envelope(String payload, KeyPair signer) throws Exception {
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initSign(signer.getPrivate());
        s.update(payload.getBytes(StandardCharsets.UTF_8));
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("alg", "ES256");
        m.put("key_id", "test");
        m.put("payload", payload);
        m.put("signature", Base64.getEncoder().encodeToString(s.sign()));
        return m;
    }

    private static String policy(String mode, long issuedAt, String appKey) {
        return "{\"app_key\":\"" + appKey + "\",\"issued_at\":" + issuedAt + ",\"mode\":\"" + mode
                + "\",\"version\":\"v" + issuedAt + "\",\"note\":\"<中文&>\"}";
    }

    @Test
    void validSignatureIsAppliedAndCached() throws Exception {
        assertTrue(ConfigManager.update(envelope(policy("block", 100, "key-1"), kp)));
        assertEquals(RuntimeConfig.Mode.BLOCK, ConfigManager.current().mode);
        // the cache holds the signed envelope and is verified again on the next start
        ConfigManager.init(home, verifier, "key-1");
        assertEquals("v100", ConfigManager.current().version);
    }

    @Test
    void tamperedPayloadIsRejected() throws Exception {
        Map<String, Object> env = envelope(policy("block", 100, "key-1"), kp);
        env.put("payload", policy("off", 100, "key-1"));
        long before = ConfigManager.rejectedCount();
        assertFalse(ConfigManager.update(env));
        assertEquals(before + 1, ConfigManager.rejectedCount());
        assertEquals("local", ConfigManager.current().version);
    }

    @Test
    void otherKeyUnsignedAndForeignAppAreRejected() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        assertFalse(ConfigManager.update(envelope(policy("off", 100, "key-1"), g.generateKeyPair())));
        assertFalse(ConfigManager.update(Json.parseObject(policy("off", 100, "key-1"))));
        assertFalse(ConfigManager.update(envelope(policy("off", 100, "other-app"), kp)));
        assertEquals("local", ConfigManager.current().version);
    }

    @Test
    void olderIssuedAtIsRejected() throws Exception {
        Map<String, Object> old = envelope(policy("off", 100, "key-1"), kp);
        assertTrue(ConfigManager.update(envelope(policy("block", 200, "key-1"), kp)));
        assertFalse(ConfigManager.update(old));
        assertEquals(RuntimeConfig.Mode.BLOCK, ConfigManager.current().mode);
    }

    @Test
    void tamperedCacheFallsBackToLocalPolicy() throws Exception {
        assertTrue(ConfigManager.update(envelope(policy("block", 100, "key-1"), kp)));
        File cache = new File(home, "cache/config.json");
        String s = new String(Files.readAllBytes(cache.toPath()), StandardCharsets.UTF_8);
        Files.write(cache.toPath(), s.replace("block", "off").getBytes(StandardCharsets.UTF_8));
        new File(home, "conf").mkdirs();
        Files.write(new File(home, "conf/policy.json").toPath(), "{\"mode\":\"monitor\",\"version\":\"file\"}".getBytes(StandardCharsets.UTF_8));
        ConfigManager.init(home, verifier, "key-1");
        assertEquals("file", ConfigManager.current().version);
    }

    @Test
    void withoutKeyUnsignedConfigsStillWorkUnlessRequired() throws Exception {
        ConfigManager.init(home, PolicyVerifier.fromSettings("", ""), "key-1");
        assertTrue(ConfigManager.update(Json.parseObject(policy("block", 1, "key-1"))));
        ConfigManager.init(home, PolicyVerifier.fromSettings("", "true"), "key-1");
        assertFalse(ConfigManager.update(Json.parseObject(policy("block", 2, "key-1"))));
    }

    @Test
    void anyOfSeveralPinnedKeysVerifies() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair next = g.generateKeyPair();
        String both = Base64.getEncoder().encodeToString(kp.getPublic().getEncoded()) + ","
                + Base64.getEncoder().encodeToString(next.getPublic().getEncoded());
        ConfigManager.init(home, PolicyVerifier.fromSettings(both, ""), "key-1");
        assertTrue(ConfigManager.update(envelope(policy("block", 1, "key-1"), kp)));
        assertTrue(ConfigManager.update(envelope(policy("block", 2, "key-1"), next)));
    }

    @Test
    void pemKeyIsAccepted() throws Exception {
        String pem = "-----BEGIN PUBLIC KEY-----\n" + Base64.getMimeEncoder().encodeToString(kp.getPublic().getEncoded())
                + "\n-----END PUBLIC KEY-----\n";
        PolicyVerifier v = PolicyVerifier.fromSettings(pem, null);
        assertTrue(v.hasKey() && v.required());
        assertThrows(PolicyVerifier.Rejected.class, () -> v.open(Json.parseObject("{\"mode\":\"off\"}")));
    }
}
