json-web-key-generator
======================

A commandline Java-based generator for JSON Web Keys (JWK) and JSON Private/Shared Keys (JPSKs).

=====================

To compile, run `mvn package`. This will generate a json-web-key-generator-0.3-SNAPSHOT-jar-with-dependencies.jar in the /target directory. 

To generate a key, run `java -jar json-web-key-generator-0.3-SNAPSHOT-jar-with-dependencies.jar -t <keytype>`. Several other arguments are defined which may be required depending on your key type:

```
 -a <arg>   Algorithm (optional)
 -c <arg>   Key Curve, required for EC key type. Must be one of P-256,
            P-384, P-521
 -i <arg>   Key ID (optional)
 -p         Display public key separately
 -s <arg>   Key Size in bits, required for RSA and OCT key types. Must be
            an integer divisible by 8
 -t <arg>   Key Type, one of: RSA, oct, EC
 -u <arg>   Usage, one of: enc, sig (optional)
```
