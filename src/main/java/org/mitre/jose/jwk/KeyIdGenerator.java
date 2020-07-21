package org.mitre.jose.jwk;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;
import java.util.function.BiFunction;

import com.google.common.hash.Hashing;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;

/**
 * @author jricher
 *
 */
// KeyID generator functions
public class KeyIdGenerator {
	public static KeyIdGenerator TIMESTAMP = new KeyIdGenerator("timestamp", (use, pubKey) -> {
		return Optional.ofNullable(use).map(KeyUse::getValue).map(s -> s + "-").orElse("")
			+ Instant.now().getEpochSecond();
	});

	public static KeyIdGenerator DATE = new KeyIdGenerator("date", (use, pubKey) -> {
		return Optional.ofNullable(use).map(KeyUse::getValue).map(s -> s + "-").orElse("")
			+ Instant.now().truncatedTo(ChronoUnit.SECONDS).toString();
	});

	public static KeyIdGenerator SHA256 = new KeyIdGenerator("sha256", (use, pubKey) -> {
		byte[] bytes = Hashing.sha256().hashBytes(pubKey).asBytes();
		return Base64URL.encode(bytes).toString();
	});

	public static KeyIdGenerator SHA1 = new KeyIdGenerator("sha1", (use, pubKey) -> {
		byte[] bytes = Hashing.sha1().hashBytes(pubKey).asBytes();
		return Base64.encode(bytes).toString();
	});

	public static KeyIdGenerator NONE = new KeyIdGenerator("none", (use, pubKey) -> {
		return null;
	});

	private final String name;
	private final BiFunction<KeyUse, byte[], String> fn;

	public KeyIdGenerator(String name, BiFunction<KeyUse, byte[], String> fn) {
		this.name = name;
		this.fn = fn;
	}

	public String generate(KeyUse keyUse, byte[] pubKey) {
		return this.fn.apply(keyUse, pubKey);
	}

	public String getName() {
		return this.name;
	}

	public static List<KeyIdGenerator> values() {
		return List.of(DATE, TIMESTAMP, SHA256, SHA1, NONE);
	}

	public static KeyIdGenerator get(String name) {
		return values().stream()
			.filter(g -> g.getName().equals(name))
			.findFirst()
			.orElse(TIMESTAMP);
	}

	public static KeyIdGenerator specified(String kid) {
		return new KeyIdGenerator(null, (u, p) -> kid);
	}
}

