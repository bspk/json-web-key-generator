# json-web-key-generator

A commandline Java-based generator for JSON Web Keys (JWK) and JSON Private/Shared Keys (JPSKs).

## Standalone run

To compile, run `mvn package`. This will generate a `json-web-key-generator-0.9-SNAPSHOT-jar-with-dependencies.jar` in the `/target` directory.

To generate a key, run `java -jar target/json-web-key-generator-0.9-SNAPSHOT-jar-with-dependencies.jar -t <keytype>`. Several other arguments are defined which may be required depending on your key type:

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

## Docker

### Build with docker 
Example:


```bash
# Optional TAG
#TAG="your/tag:here"
# Example: TAG="<your_docker_id>/json-web-key-generator:latest"
$ docker build -t $TAG .
```

If building from git tags then run the following to store the *tag*, and the *commit*
in the docker image label.

```bash
TAG=$(git describe --abbrev=0 --tags)
REV=$(git log -1 --format=%h)
docker build -t <your_docker_id>/json-web-key-generator:$TAG --build-arg GIT_COMMIT=$REV --build-arg GIT_TAG=$TAG .
docker push <your_docker_id>/json-web-key-generator:$TAG

# or push all the tags
docker push <your_docker_id>/json-web-key-generator --all-tags
```

### Run from docker

Example of running the app  within a docker container to generate a 2048 bit RSA JWK.

```bash
$ docker run --rm <your_docker_id>/json-web-key-generator:latest -t RSA -s 2048
Full key:
{
  "p": "7blCsqibq1iTDOTxpLU9T5WEy5DgbwB65fXFEeU2y58mNUjXBFhDWppuEpJ7iMJtMsOhB60Mmf8ujRNVp8KmVT9eF6MwO7tW7sprq45YncwC8pZIpMqDdKOvB9moHVW9FzPlZimUzJsfgPAQc73SrpOSqwGHvPxfjvfO-kM_7wc",
  "kty": "RSA",
  "q": "uTMQv72suZzTkQg78MlDDNjYSjl_jRrok9pME_j4L94bEpqwftCLAHo9YCDHmMREcJa5X4UCIeG2bAqPx4izluaRQ3mktISMXtnPvLYUkooeWrQtrD7rYwurJeh0n_y_0YMVfH0OUUXxOOu6hljBXoxDhoqzPysJOljDEordNoc",
  "d": "S14hFH5Ri0DrZqY4bArM8ryEjxv35kSLU6sixiCjHkCH0ZW9_tYEINDD9DRhggQtGfpuPsfIPQ0AWX9LmtKnIrOVmscrI_E8dkPvbTPAf_GePFSQaqtYobr4mjdhWHXStRGqSQnRnRpqbjcjs3wRyV42CTgJf8tBM1vTx_Pak5NYCpHWBu9vnN-Pzd60gpPxRZe-HaJbGRMVTNw11Rys--7Vcq-k6iyhYYBQiL3c62zNW6GzucmXxbSs8gQduPArvCKUAbJoMhWdCDvO3JIQTxccUdACs7xe9RDxucMHKbLM0yWUEbL6mS0J93-SypwNvUKbOkrGuc4sybmr2b1X5Q",
  "e": "AQAB",
  "kid": "1655476144",
  "qi": "QMyZMfoUzearQ37ssHP5iB9FHDtZsTkq2Qr_76xMidgk5MJyEwJT90tAK3cC2x_tBRYKKrT9GXQYSHHNX0govfUGzwmlyK0GxX92C_Tr0BQZQzt2JP4BUnBk35REMPTv6aP1ODZ3u7d1_bvIY0bwZSDTVGirIdGYXRwf8XQdYQQ",
  "dp": "J5_1yinoqMr-1-thi_7Z1WYq2HOxtU7zLVmmG7GFTLOefstBa-v6biPHrTjVdppR8WBCezERJKowbDuIz4nWh-ckG_SLmalEeFEtWU9E3iifZSg_u5g2CT8vcbOKHjmoZzGzTzAnKWPCAJADbgd6ErdufyqmIY4_r2kHCxgilAk",
  "dq": "c6HNqFouOSoQ8rH4cuvGwIO38Agceqa9ZmtbKvE9TO3Za3FIF7XvxBmOrrFozhplPQLutRQf87WxJ54kjYntz58gPcf6rXdBCYvnZ8Ur7R7tuuZayfvzDkFf1-hewPGXdqHozXRrdxU7erW8HVvXSEg9dQiuyBb_yP1YtwAbBIs",
  "n": "q_pMqQb2Lr7k1lOm_mXIBSWrn322vAWcnkBk1sVDZtR-n7keDVEOvby_LpM-7Dx-8fUTAU99RD4e4VgHb02bqmuodNfKjDXN9MFBmnhBkFWxxq0xXTj1e6IlQCGeAV2AnlcBmgzXTQ5a8IOBtBwbLkBUx1IbbwpJM6l2LhQmG756SxUjmDy9mHjQp_h0dr3u3TyceXR3GyG3cGeYfMYwaccZpGEQyCVRu1iwIahP6eoqIGGd_8V2W2vR5TU7yN4xiEdU8nGSVYcdGR7Cu22GxT0UXFYbu5o0A2LnLghjxHirw89WMm81ROaBOl5DdJzXyix2EE7snUBunJiyEi2GsQ"
}
```
