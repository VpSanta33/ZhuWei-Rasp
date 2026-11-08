package com.zhuwei.rasp.core.policy;

import com.zhuwei.rasp.core.util.Json;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Verifies the signed policy envelope delivered by the server:
 * {@code {"alg":"ES256","key_id":"..","payload":"<policy JSON>","signature":"<base64 DER>"}}.
 *
 * <p>The public key is pinned locally ({@code policy.public_key}, base64 SPKI or PEM; several keys may be
 * given comma-separated so the server key can be rotated without a flag day). When a key is
 * configured, unsigned or badly signed configs are rejected; without a key the agent still accepts
 * configs (for upgrades from unsigned servers) unless {@code policy.require_signature=true}.</p>
 */
public final class PolicyVerifier {

    /** Thrown when a config must not be applied. */
    public static final class Rejected extends Exception {
        public Rejected(String msg) {
            super(msg);
        }
    }

    private final List<PublicKey> keys;
    private final boolean required;

    public PolicyVerifier(List<PublicKey> keys, boolean required) {
        this.keys = keys == null ? Collections.<PublicKey>emptyList() : keys;
        this.required = required;
    }

    /** Accept-anything verifier for standalone mode and tests. */
    public static PolicyVerifier none() {
        return new PolicyVerifier(null, false);
    }

    /**
     * @param publicKey      base64 SPKI DER or a PEM "PUBLIC KEY" block; empty for none
     * @param requireSetting "true"/"false", or null/empty for the default (required iff a key is set)
     */
    public static PolicyVerifier fromSettings(String publicKey, String requireSetting) throws Exception {
        List<PublicKey> ks = new ArrayList<>();
        if (publicKey != null) {
            for (String one : publicKey.split(",")) {
                String b64 = one.replace("-----BEGIN PUBLIC KEY-----", "")
                        .replace("-----END PUBLIC KEY-----", "").replaceAll("\\s", "");
                if (!b64.isEmpty()) {
                    ks.add(KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(b64))));
                }
            }
        }
        boolean req = requireSetting == null || requireSetting.trim().isEmpty()
                ? !ks.isEmpty() : Boolean.parseBoolean(requireSetting.trim());
        return new PolicyVerifier(ks, req);
    }

    public boolean hasKey() {
        return !keys.isEmpty();
    }

    public boolean required() {
        return required;
    }

    /**
     * Returns the policy map carried by {@code data}: the verified payload of a signed envelope, or
     * {@code data} itself for a legacy unsigned config when signatures are not required.
     */
    public Map<String, Object> open(Map<String, Object> data) throws Rejected {
        Object payload = data.get("payload");
        if (!(payload instanceof String)) {
            if (required) {
                throw new Rejected("config is not signed");
            }
            return data;
        }
        String p = (String) payload;
        if (hasKey()) {
            if (!"ES256".equals(Json.str(data, "alg", ""))) {
                throw new Rejected("unsupported signature algorithm " + Json.str(data, "alg", "?"));
            }
            if (!verify(p.getBytes(StandardCharsets.UTF_8), Json.str(data, "signature", ""))) {
                throw new Rejected("bad signature (key_id=" + Json.str(data, "key_id", "?") + ")");
            }
        } else if (required) {
            throw new Rejected("policy.require_signature=true but policy.public_key is not set");
        }
        try {
            return Json.parseObject(p);
        } catch (RuntimeException e) {
            throw new Rejected("payload is not a JSON object");
        }
    }

    private boolean verify(byte[] payload, String sigB64) {
        byte[] sig;
        try {
            sig = Base64.getDecoder().decode(sigB64);
        } catch (IllegalArgumentException e) {
            return false;
        }
        for (PublicKey k : keys) {
            try {
                Signature s = Signature.getInstance("SHA256withECDSA");
                s.initVerify(k);
                s.update(payload);
                if (s.verify(sig)) {
                    return true;
                }
            } catch (Exception ignore) {
                // try the next pinned key
            }
        }
        return false;
    }
}
