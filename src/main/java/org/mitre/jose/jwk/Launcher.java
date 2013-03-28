package org.mitre.jose.jwk;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.PosixParser;

import com.google.common.base.Strings;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.Use;
import com.nimbusds.jose.jwk.ECKey.Curve;

/**
 * Hello world!
 *
 */
public class Launcher {
	
	private static Options options;
	
    public static void main(String[] args) {
    	
    	options = new Options();
    	
    	options.addOption("t", true, "Key Type, one of: " + KeyType.RSA + ", " + KeyType.OCT + ", " + KeyType.EC);
    	options.addOption("s", true, "Key Size in bits, required for RSA and OCT key types. Must be an integer divisible by 8");
    	options.addOption("u", true, "Usage, one of: enc, sig (optional)");
    	options.addOption("a", true, "Algorithm (optional)");
    	options.addOption("i", true, "Key ID (optional)");
    	options.addOption("p", false, "Display public key separately");
    	options.addOption("c", true, "Key Curve, required for EC key type. Must be one of " + Curve.P_256 + ", " + Curve.P_384 + ", " + Curve.P_521);

    	//options.addOption("g", false, "Load GUI");
    	
    	CommandLineParser parser = new PosixParser();
    	try {
	        CommandLine cmd = parser.parse(options, args);
	        
	        String kty = cmd.getOptionValue("t");
	        String size = cmd.getOptionValue("s");
	        String use = cmd.getOptionValue("u");
	        String alg = cmd.getOptionValue("a");
	        String kid = cmd.getOptionValue("i");
	        String crv = cmd.getOptionValue("c");

	        // check for required fields
	        if (kty == null) {
	        	printUsageAndExit("Key type must be supplied.");
	        }
	        
	        // parse out the important bits
	        
        	KeyType keyType = KeyType.parse(kty);

        	if (Strings.isNullOrEmpty(kid)) {
        		kid = null;
        	}
        	Use keyUse = null;
        	if (use != null) {
        		if (use.equals("sig")) {
	    			keyUse = Use.SIGNATURE;
	    		} else if (use.equals("enc")) {
	    			keyUse = Use.ENCRYPTION;
	    		} else {
	    			printUsageAndExit("Invalid key usage, must be 'sig' or 'enc', got " + use);
	    		}
        	}
        	
        	Algorithm keyAlg = null;
        	if (!Strings.isNullOrEmpty(alg)) {
        		keyAlg = JWSAlgorithm.parse(alg);
        	}
        	
        	JWK jwk = null;
        	
        	if (keyType.equals(KeyType.RSA)) {
    	        // surrounding try/catch catches numberformatexception from this
    	        Integer keySize = Integer.decode(size);
        		if (keySize % 8 != 0) {
        			printUsageAndExit("Key size (in bits) must be divisible by 8, got " + keySize);
        		}

        		jwk = RSAKeyMaker.make(keySize, keyUse, keyAlg, kid);
        	} else if (keyType.equals(KeyType.OCT)) {
    	        // surrounding try/catch catches numberformatexception from this
    	        Integer keySize = Integer.decode(size);
        		if (keySize % 8 != 0) {
        			printUsageAndExit("Key size (in bits) must be divisible by 8, got " + keySize);
        		}

        		jwk = OctetSequenceKeyMaker.make(keySize, keyUse, keyAlg, kid);
        	} else if (keyType.equals(KeyType.EC)) {
        		try {
	                Curve keyCurve = Curve.parse(crv);
	                jwk = ECKeyMaker.make(keyCurve, keyUse, keyAlg, kid);
                } catch (java.text.ParseException e) {
	                printUsageAndExit("Invalid curve parameter, got: " + crv);
                }
        	} else {
        		printUsageAndExit("Unknown key type: " + keyType);
        	}

        	// if we got here, we can print the key

        	System.out.println("Full key:");

        	// round trip it through GSON to get a prettyprinter
        	Gson gson = new GsonBuilder().setPrettyPrinting().create();
        	
        	JsonElement json = new JsonParser().parse(jwk.toJSONString());        	
        	System.out.println(gson.toJson(json));
        	
        	if (cmd.hasOption("p")) {
        		System.out.println(); // spacer
        		
        		// also print public key, if possible
        		JWK pub = jwk.toPublicJWK();
        		
        		if (pub != null) {
            		System.out.println("Public key:");
	        		JsonElement pubJson = new JsonParser().parse(pub.toJSONString());
	        		System.out.println(gson.toJson(pubJson));
        		} else {
        			System.out.println("No public key.");
        		}
        	}

    	} catch (NumberFormatException e) {
    		printUsageAndExit("Invalid key size: " + e.getMessage());
        } catch (ParseException e) {
        	printUsageAndExit("Failed to parse arguments: " + e.getMessage());
        }
    	
    	
    	
    }
    
    // print out a usage message and quit
    private static void printUsageAndExit(String message) {
    	if (message != null) {
    		System.err.println(message);
    	}
    	
    	HelpFormatter formatter = new HelpFormatter();
    	formatter.printHelp( "java -jar json-web-key-generator.jar -t <keyType> [options]", options );
    	
    	// kill the program
    	System.exit(1);
    }
}
