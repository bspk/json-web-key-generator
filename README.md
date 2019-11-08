json-web-key-generator
======================

A commandline Java-based generator for JSON Web Keys (JWK) and JSON Private/Shared Keys (JPSKs).

=====================

To compile, run `mvn package`. This will generate a `json-web-key-generator-0.5-SNAPSHOT-jar-with-dependencies.jar` in the `/target` directory.

To generate a key, run `java -jar target/json-web-key-generator-0.5-SNAPSHOT-jar-with-dependencies.jar -t <keytype>`. Several other arguments are defined which may be required depending on your key type:

```
 -a <arg>   Algorithm (optional)
 -c <arg>   Key Curve, required for EC key type. Must be one of P-256,
            P-384, P-521
 -i <arg>   Key ID (optional), one will be generated if not defined
 -I         Don't generate a Key ID if none defined
 -o <arg>   Write output to file (will append to existing KeySet if -S is
            used), No Display of Key Material
 -p         Display public key separately
 -s <arg>   Key Size in bits, required for RSA and oct key types. Must be
            an integer divisible by 8
 -S         Wrap the generated key in a KeySet
 -t <arg>   Key Type, one of: RSA, oct, EC
 -u <arg>   Usage, one of: enc, sig (optional)
```
