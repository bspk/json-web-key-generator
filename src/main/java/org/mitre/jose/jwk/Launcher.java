package org.mitre.jose.jwk;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.cli.PosixParser;

import com.google.common.base.Strings;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.Use;

/**
 * Hello world!
 *
 */
public class Launcher {
	
	private static Options options;
	
    public static void main(String[] args) {
    	
    	options = new Options();
    	
    	options.addOption("t", true, "Key Type, one of: " + KeyType.RSA + ", " + KeyType.OCT);
    	options.addOption("s", true, "Key Size in bits, must be an integer, generally divisible by 8");
    	options.addOption("u", true, "Usage, one of: " + Use.ENCRYPTION + ", " + Use.SIGNATURE + ". Defaults to " + Use.SIGNATURE);
    	options.addOption("a", true, "Algorithm.");
    	options.addOption("i", true, "Key ID (optional)");

    	//options.addOption("g", false, "Load GUI");
    	
    	CommandLineParser parser = new PosixParser();
    	try {
	        CommandLine cmd = parser.parse(options, args);
	        
	        String kty = cmd.getOptionValue("t");
	        String size = cmd.getOptionValue("s");
	        String use = cmd.getOptionValue("u");
	        String alg = cmd.getOptionValue("a");
	        String kid = cmd.getOptionValue("i");

	        // check for required fields
	        if (kty == null) {
	        	printUsageAndExit("Key type must be supplied.");
	        }
	        if (size == null) {
	        	printUsageAndExit("Key size must be supplied.");
	        }
	        
	        // parse out the important bits
	        
	        // surrounding try/catch catches numberformatexception from this
	        Integer keySize = Integer.decode(size);

        	KeyType keyType = KeyType.parse(kty);

        	if (Strings.isNullOrEmpty(kid)) {
        		kid = null;
        	}
        	Use keyUse = Use.SIGNATURE;
        	if (use != null) {
        		keyUse = Use.valueOf(use);
        	}
        	
        	Algorithm keyAlg = null;
        	if (!Strings.isNullOrEmpty(alg)) {
        		keyAlg = JWSAlgorithm.parse(alg);
        	}
        	
        	JWK jwk = null;
        	
        	if (keyType.equals(KeyType.RSA)) {
        		if (keySize % 8 != 0) {
        			printUsageAndExit("Key size for RSA must be divisible by 8, got " + keySize);
        		}
        		jwk = RSAKeyMaker.make(keySize, keyUse, keyAlg, kid);
        	} else if (keyType.equals(KeyType.OCT)) {
        		if (keySize % 8 != 0) {
        			printUsageAndExit("Key size for octet sequence must be divisible by 8, got " + keySize);
        		}
        		jwk = OctetSequenceKeyMaker.make(keySize, keyUse, keyAlg, kid);
        	} else if (keyType.equals(KeyType.EC)) {
        		printUsageAndExit("Elliptical Curve Keys are not yet supported.");
        	} else {
        		printUsageAndExit("Unknown key type: " + keyType);
        	}

        	// if we got here, we can print the key
        	System.out.println(jwk.toJSONString());

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
    	formatter.printHelp( "java -jar json-web-key-generator.jar -t <keyType> -s <keySize>", options );
    	
    	// kill the program
    	System.exit(1);
    }
}
