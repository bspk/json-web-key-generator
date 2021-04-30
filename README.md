# json-web-key-generator
A command-line Java-based generator for JSON Web Keys (JWK) and JSON Private/Shared Keys (JPSKs).

Examples:
```
# Create a new RSA Private and public key and print it to the console as JWK Set
$ docker run --rm ghcr.io/legion2/json-web-key-generator -t RSA -s 4096 -S -p

# Create a new RSA key with the id 'mykeyid' and print it to the console
$ docker run --rm ghcr.io/legion2/json-web-key-generator -t RSA -s 4096 -p -i mykeyid

# Add a new RSA key to an existing JWK Set file
$ docker run --rm -v "${PWD}:/keys" ghcr.io/legion2/json-web-key-generator -t RSA -s 4096 -o /keys/jwks.json -S
```

## Getting Started

To compile, run `mvn package`.
This will generate a `json-web-key-generator.jar` in the `target` directory.

To generate a key, run `java -jar json-web-key-generator.jar -t <keytype>`.
Several other arguments are defined which may be required depending on your key type:

```
usage: java -jar json-web-key-generator.jar -t <keyType> [options]
 -t,--type <arg>           Key Type, one of: RSA, oct, EC, OKP
 -s,--size <arg>           Key Size in bits, required for RSA and oct key
                           types. Must be an integer divisible by 8
 -c,--curve <arg>          Key Curve, required for EC or OKP key type.
                           Must be one of P-256, secp256k1, P-384, P-521
                           for EC keys or one of Ed25519, Ed448, X25519,
                           X448 for OKP keys.
 -u,--usage <arg>          Usage, one of: enc, sig (optional)
 -a,--algorithm <arg>      Algorithm (optional)
 -i,--id <arg>             Key ID (optional), one will be generated if not
                           defined
 -g,--idGenerator <arg>    Key ID generation method (optional). Can be one
                           of: date, timestamp, sha256, sha1, none. If
                           omitted, generator method defaults to
                           'timestamp'.
 -I,--noGenerateId         <deprecated> Don't generate a Key ID.
                           (Deprecated, use '-g none' instead.)
 -p,--showPubKey           Display public key separately (if applicable)
 -S,--keySet               Wrap the generated key in a KeySet
 -o,--output <arg>         Write output to file. Will append to existing
                           KeySet if -S is used. Key material will not be
                           displayed to console.
 -P,--pubKeyOutput <arg>   Write public key to separate file. Will append
                           to existing KeySet if -S is used. Key material
                           will not be displayed to console. '-o/--output'
                           must be declared as well.
 -x,--x509                 Display keys in X509 PEM format
```

## Use Docker
When using the docker image and write to a file you must mount that file in the docker container.
