/*
 * Copyright 2019 The MITRE Corporation and
 *   the MIT Kerberos and Internet Trust Consortium
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.mitre.jose.jwk;


import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.math.BigInteger;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionGroup;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;

/**
 * Small Helper App to generate Json Web Keys
 */
public class Launcher {

	private static Options options;

	private static List<Curve> ecCurves = Arrays.asList(
		Curve.P_256, Curve.SECP256K1, Curve.P_384, Curve.P_521);

	private static List<Curve> okpCurves = Arrays.asList(
		Curve.Ed25519, Curve.Ed448, Curve.X25519, Curve.X448);

	private static List<KeyType> keyTypes = Arrays.asList(
		KeyType.RSA, KeyType.OCT, KeyType.EC, KeyType.OKP);

	public static void main(String[] args) {

		Security.addProvider(new BouncyCastleProvider());

		options = new Options();

		configureCommandLineOptions(options);

		CommandLineParser parser = new DefaultParser();
		try {
			CommandLine cmd = parser.parse(options, args);

			String kty = cmd.getOptionValue("t");
			String size = cmd.getOptionValue("s");
			String use = cmd.getOptionValue("u");
			String alg = cmd.getOptionValue("a");
			String crv = cmd.getOptionValue("c");
			boolean keySet = cmd.hasOption("S");
			boolean pubKey = cmd.hasOption("p");
			String outFile = cmd.getOptionValue("o");
			String pubOutFile = cmd.getOptionValue("P");
			boolean printX509 = cmd.hasOption("x");

			// process the Key ID
			String kid = cmd.getOptionValue("i");
			KeyIdGenerator generator;
			if (Strings.isNullOrEmpty(kid)) {
				// no explicit key ID is specified, see if we should use a generator
				if (cmd.hasOption("i") || cmd.hasOption("I")) {
					// Either -I is set, -i is set (but an empty value is passed), either way it's a blank key ID
					generator = KeyIdGenerator.NONE;
				} else {
					generator = KeyIdGenerator.get(cmd.getOptionValue("g"));
				}
			} else {
				generator = KeyIdGenerator.specified(kid);

			}

			// check for required fields
			if (kty == null) {
				throw printUsageAndExit("Key type must be supplied.");
			}

			// parse out the important bits

			KeyType keyType = KeyType.parse(kty);

			KeyUse keyUse = validateKeyUse(use);

			Algorithm keyAlg = null;
			if (!Strings.isNullOrEmpty(alg)) {
				keyAlg = JWSAlgorithm.parse(alg);
			}

			JWK jwk = makeKey(size, generator, crv, keyType, keyUse, keyAlg);

			outputKey(keySet, pubKey, outFile, pubOutFile, printX509, jwk);
		} catch (NumberFormatException e) {
			throw printUsageAndExit("Invalid key size: " + e.getMessage());
		} catch (ParseException e) {
			throw printUsageAndExit("Failed to parse arguments: " + e.getMessage());
		} catch (java.text.ParseException e) {
			throw printUsageAndExit("Could not parse existing KeySet: " + e.getMessage());
		} catch (IOException e) {
			throw printUsageAndExit("Could not read existing KeySet: " + e.getMessage());
		}
	}

	private static void configureCommandLineOptions(Options options) {
		options.addOption("t", "type", true, "Key Type, one of: " +
			keyTypes.stream()
		.map(KeyType::getValue)
		.collect(Collectors.joining(", ")));

		options.addOption("s", "size", true,
			"Key Size in bits, required for " + KeyType.RSA.getValue() + " and " + KeyType.OCT.getValue() + " key types. Must be an integer divisible by 8");
		options.addOption("c", "curve", true,
			"Key Curve, required for " + KeyType.EC.getValue() + " or " + KeyType.OKP.getValue() + " key type. Must be one of "
				+ ecCurves.stream()
				.map(Curve::getName)
				.collect(Collectors.joining(", "))
				+ " for EC keys or one of "
				+ okpCurves.stream()
				.map(Curve::getName)
				.collect(Collectors.joining(", "))
				+ " for OKP keys.");

		options.addOption("u", "usage", true, "Usage, one of: enc, sig (optional)");
		options.addOption("a", "algorithm", true, "Algorithm (optional)");

		OptionGroup idGroup = new OptionGroup();
		idGroup.addOption(new Option("i", "id", true, "Key ID (optional), one will be generated if not defined"));
		idGroup.addOption(new Option("I", "noGenerateId", false, "<deprecated> Don't generate a Key ID. (Deprecated, use '-g none' instead.)"));
		idGroup.addOption(new Option("g", "idGenerator", true, "Key ID generation method (optional). Can be one of: "
			+ KeyIdGenerator.values().stream()
			.map(KeyIdGenerator::getName)
			.collect(Collectors.joining(", "))
			+ ". If omitted, generator method defaults to '" + KeyIdGenerator.TIMESTAMP.getName() + "'."));
		options.addOptionGroup(idGroup);

		options.addOption("p", "showPubKey", false, "Display public key separately (if applicable)");
		options.addOption("S", "keySet", false, "Wrap the generated key in a KeySet");

		options.addOption("x", "x509", false, "Display keys in X509 PEM format");

		options.addOption("o", "output", true, "Write output to file. Will append to existing KeySet if -S is used. "
			+ "Key material will not be displayed to console.");
		options.addOption("P", "pubKeyOutput", true, "Write public key to separate file. Will append to existing KeySet if -S is used. "
			+ "Key material will not be displayed to console. '-o/--output' must be declared as well.");
	}

	private static KeyUse validateKeyUse(String use) {
		try {
			return KeyUse.parse(use);
		} catch (java.text.ParseException e) {
			throw printUsageAndExit("Invalid key usage, must be 'sig' or 'enc', got " + use);
		}
	}

	private static JWK makeKey(String size, KeyIdGenerator kid, String crv, KeyType keyType, KeyUse keyUse, Algorithm keyAlg) {
		JWK jwk;
		if (keyType.equals(KeyType.RSA)) {
			jwk = makeRsaKey(kid, size, keyType, keyUse, keyAlg);
		} else if (keyType.equals(KeyType.OCT)) {
			jwk = makeOctKey(kid, size, keyType, keyUse, keyAlg);
		} else if (keyType.equals(KeyType.EC)) {
			jwk = makeEcKey(kid, crv, keyType, keyUse, keyAlg);
		} else if (keyType.equals(KeyType.OKP)) {
			jwk = makeOkpKey(kid, crv, keyType, keyUse, keyAlg);
		} else {
			throw printUsageAndExit("Unknown key type: " + keyType);
		}
		return jwk;
	}

	private static JWK makeOkpKey(KeyIdGenerator kid, String crv, KeyType keyType, KeyUse keyUse, Algorithm keyAlg) {
		if (Strings.isNullOrEmpty(crv)) {
			throw printUsageAndExit("Curve is required for key type " + keyType);
		}
		Curve keyCurve = Curve.parse(crv);

		if (!okpCurves.contains(keyCurve)) {
			throw printUsageAndExit("Curve " + crv + " is not valid for key type " + keyType);
		}

		return OKPKeyMaker.make(keyCurve, keyUse, keyAlg, kid);
	}

	private static JWK makeEcKey(KeyIdGenerator kid, String crv, KeyType keyType, KeyUse keyUse, Algorithm keyAlg) {
		if (Strings.isNullOrEmpty(crv)) {
			throw printUsageAndExit("Curve is required for key type " + keyType);
		}
		Curve keyCurve = Curve.parse(crv);

		if (!ecCurves.contains(keyCurve)) {
			throw printUsageAndExit("Curve " + crv + " is not valid for key type " + keyType);
		}

		return ECKeyMaker.make(keyCurve, keyUse, keyAlg, kid);
	}

	private static JWK makeOctKey(KeyIdGenerator kid, String size, KeyType keyType, KeyUse keyUse, Algorithm keyAlg) {
		if (Strings.isNullOrEmpty(size)) {
			throw printUsageAndExit("Key size (in bits) is required for key type " + keyType);
		}

		// surrounding try/catch catches numberformatexception from this
		Integer keySize = Integer.decode(size);
		if (keySize % 8 != 0) {
			throw printUsageAndExit("Key size (in bits) must be divisible by 8, got " + keySize);
		}

		return OctetSequenceKeyMaker.make(keySize, keyUse, keyAlg, kid);
	}

	private static JWK makeRsaKey(KeyIdGenerator kid, String size, KeyType keyType, KeyUse keyUse, Algorithm keyAlg) {
		if (Strings.isNullOrEmpty(size)) {
			throw printUsageAndExit("Key size (in bits) is required for key type " + keyType);
		}

		// surrounding try/catch catches numberformatexception from this
		Integer keySize = Integer.decode(size);
		if (keySize % 8 != 0) {
			throw printUsageAndExit("Key size (in bits) must be divisible by 8, got " + keySize);
		}

		return RSAKeyMaker.make(keySize, keyUse, keyAlg, kid);
	}

	private static void outputKey(boolean keySet, boolean pubKey, String outFile, String pubOutFile, boolean printX509, JWK jwk) throws IOException, java.text.ParseException {
		// round trip it through GSON to get a prettyprinter
		Gson gson = new GsonBuilder().setPrettyPrinting().create();
		if (outFile == null) {

			System.out.println("Full key:");

			printKey(keySet, jwk, gson);

			if (pubKey) {
				System.out.println(); // spacer

				// also print public key, if possible
				JWK pub = jwk.toPublicJWK();

				if (pub != null) {
					System.out.println("Public key:");
					printKey(keySet, pub, gson);
				} else {
					System.out.println("No public key.");
				}
			}

			if (printX509) {

				try {
					KeyType keyType = jwk.getKeyType();
					if (keyType.equals(KeyType.RSA)) {
						Certificate cert = selfSign(jwk.toRSAKey().toPublicKey(),
							jwk.toRSAKey().toPrivateKey(),
							jwk.getKeyID() != null ? jwk.getKeyID() : jwk.computeThumbprint().toString(),
							"SHA256withRSA"
							);
						writePEMToConsole(
							jwk.toRSAKey().toPublicKey(),
							jwk.toRSAKey().toPrivateKey(),
							cert
							);
					} else if (keyType.equals(KeyType.EC)) {
						Certificate cert = selfSign(jwk.toECKey().toPublicKey(),
							jwk.toECKey().toPrivateKey(),
							jwk.getKeyID() != null ? jwk.getKeyID() : jwk.computeThumbprint().toString(),
							"SHA256withECDSA"
							);
						writePEMToConsole(
							jwk.toECKey().toPublicKey(),
							jwk.toECKey().toPrivateKey(),
							cert);

// Nimbus does not export OKP as JCA keys so we can't use these utilities, but maybe some day
//
//					} else if (keyType.equals(KeyType.OKP)) {
//						Certificate cert = null;
//
//						if (jwk.toOctetKeyPair().getCurve().equals(Curve.Ed25519)) {
//							selfSign(jwk.toOctetKeyPair().toPublicKey(),
//								jwk.toOctetKeyPair().toPrivateKey(),
//								jwk.getKeyID(),
//								"SHA256withECDSA"
//								);
//						}
//						writePEMToConsole(
//							jwk.toOctetKeyPair().toPublicKey(),
//							jwk.toOctetKeyPair().toPrivateKey(),
//							cert);
					} else {
						throw printUsageAndExit("Unknown key type for X509 encoding: " + keyType);
					}
				} catch (JOSEException e) {
					throw printUsageAndExit("Error extracting keypair for X509: " + e.getMessage());
				}
			}

		} else {
			writeKeyToFile(keySet, outFile, pubOutFile, jwk, gson);
		}
	}

	private static void writePEMToConsole(PublicKey publicKey, PrivateKey privateKey, Certificate cert) {
		try {
			System.out.println();
			System.out.println("X509 Formatted Keys:");

			PemWriter pw = new PemWriter(new OutputStreamWriter(System.out));

			if (publicKey != null) {
				pw.writeObject(new PemObject("PUBLIC KEY", publicKey.getEncoded()));
			}

			if (privateKey != null) {
				pw.writeObject(new PemObject("PRIVATE KEY", privateKey.getEncoded()));
			}

			if (cert  != null) {
				pw.writeObject(new PemObject("CERTIFICATE", cert.getEncoded()));
			}

			pw.flush();

			pw.close();
		} catch (IOException | CertificateEncodingException e) {
			throw printUsageAndExit("Error printing X509 format: " + e.getMessage());
		}
	}

	public static Certificate selfSign(PublicKey pub, PrivateKey priv, String subjectDN, String signatureAlgorithm)
	{
		try {
			X500Name dn = new X500Name("CN=" + URLEncoder.encode(subjectDN, Charset.defaultCharset()));

			BigInteger certSerialNumber = BigInteger.valueOf(Instant.now().toEpochMilli());

//			String signatureAlgorithm = "SHA256WithRSA";

			ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm)
				.build(priv);

			Instant startDate = Instant.now();
			Instant endDate = startDate.plus(300, ChronoUnit.DAYS);

			JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
				dn, certSerialNumber, Date.from(startDate), Date.from(endDate),
				dn, pub);

			return new JcaX509CertificateConverter()
				.getCertificate(certBuilder.build(contentSigner));
		} catch (CertificateException | OperatorCreationException e) {
			throw printUsageAndExit("Unable to create certificate: " + e.getMessage());
		}
	}


	private static void writeKeyToFile(boolean keySet, String outFile, String pubOutFile, JWK jwk, Gson gson) throws IOException,
	java.text.ParseException {
		JsonElement json;
		JsonElement pubJson;
		File output = new File(outFile);
		if (keySet) {
			List<JWK> existingKeys = output.exists() ? JWKSet.load(output).getKeys() : Collections.emptyList();
			List<JWK> jwkList = new ArrayList<>(existingKeys);
			jwkList.add(jwk);
			JWKSet jwkSet = new JWKSet(jwkList);
			json = JsonParser.parseString(jwkSet.toJSONObject(false).toJSONString());
			pubJson = JsonParser.parseString(jwkSet.toJSONObject(true).toJSONString());
		} else {
			json = JsonParser.parseString(jwk.toJSONString());
			pubJson = JsonParser.parseString(jwk.toPublicJWK().toJSONString());
		}
		try (Writer os = new BufferedWriter(new FileWriter(output))) {
			os.write(gson.toJson(json));
		}
		if (pubOutFile != null) {
			try (Writer os = new BufferedWriter(new FileWriter(pubOutFile))) {
				os.write(gson.toJson(pubJson));
			}
		}

	}

	private static void printKey(boolean keySet, JWK jwk, Gson gson) {
		if (keySet) {
			JWKSet jwkSet = new JWKSet(jwk);
			JsonElement json = JsonParser.parseString(jwkSet.toJSONObject(false).toJSONString());
			System.out.println(gson.toJson(json));
		} else {
			JsonElement json = JsonParser.parseString(jwk.toJSONString());
			System.out.println(gson.toJson(json));
		}
	}

	// print out a usage message and quit
	// return exception so that we can "throw" this for control flow analysis
	private static IllegalArgumentException printUsageAndExit(String message) {
		if (message != null) {
			System.err.println(message);
		}

		List<String> optionOrder = ImmutableList.of("t", "s", "c", "u", "a", "i", "g", "I", "p", "S", "o", "P", "x");

		HelpFormatter formatter = new HelpFormatter();
		formatter.setOptionComparator(Comparator.comparingInt(o -> optionOrder.indexOf(o.getOpt())));
		formatter.printHelp("java -jar json-web-key-generator.jar -t <keyType> [options]", options);

		// kill the program
		System.exit(1);
		return new IllegalArgumentException("Program was called with invalid arguments");
	}
}
