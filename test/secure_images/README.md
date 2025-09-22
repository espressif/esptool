# How are the test images generated?

## IV generation

`{len}bit_iv.bin`

```
dd if=/dev/random of={len}bit_iv.bin bs=1 count=32

where len = [256]
```

## Keys Generation

### Encryption Keys

`{len}bit_key.bin`

```
espsecure generate-flash-encryption-key -l {len} {len}bit_key.bin

where len = [256, 512]
```

`ef-flashencryption-key.bin`

```
espsecure generate-flash-encryption-key -l 256 ef-flashencryption-key.bin
```

### Signing Keys

For schemes = [rsa, ecdsa192, ecdsa256, ecdsa384]

`{scheme}_secure_boot_signing_keyX.pem`

```
espsecure generate-signing-key -v 2 --scheme {scheme} {scheme}_secure_boot_signing_keyX.pem
```

`{scheme}_secure_boot_signing_key_v2.pem`

```
espsecure generate-signing-key -v 2 --scheme {scheme} {scheme}_secure_boot_signing_key_v2.pem
```

`{scheme}_secure_boot_signing_pubkeyX.pem`

```
espsecure extract-public-key -v 2 -k {scheme}_secure_boot_signing_keyX.pem {scheme}_secure_boot_signing_pubkeyX.pem
```

`{scheme}_public_key_digest_v2.bin`

```
espsecure digest-sbv2-public-key -k {scheme}_secure_boot_signing_key_v2.pem -o {scheme}_public_key_digest_v2.bin
```

## Binaries Generation

### Bootloader Binaries

Base Bootloader binaries: `bootloader.bin` (ESP32 <v3.0) and `bootloader_unsigned_v2.bin` (ESP32 >=3.0) build with the configuration `CONFIG_SECURE_BOOT_BUILD_SIGNED_BINARIES=y` enabled.

#### Secure Boot V1

`bootloader_digested.bin`

```
espsecure digest-secure-bootloader -k 256bit_key.bin -o bootloader_digested.bin --iv 256bit_iv.bin bootloader.bin
```

`bootloader_signed.bin`

```
espsecure sign-data -v 1 -k ecdsa256_secure_boot_signing_key.pem -o bootloader_signed.bin bootloader.bin
```

#### Secure Boot V2

`bootloader_signed_v2_{scheme}.bin`

```
espsecure sign-data -v 2 -k {scheme}_secure_boot_signing_key.pem -o bootloader_signed_v2_{scheme}.bin bootloader_unsigned_v2.bin
```


`bootloader_multi_signed_v2.bin`

```
espsecure sign-data -v 2 -a -k rsa_secure_boot_signing_key.pem rsa_secure_boot_signing_key2.pem rsa_secure_boot_signing_key3.pem -o bootloader_multi_signed_v2.bin bootloader_unsigned_v2.bin
```

`pre_calculated_bootloader_signature_{scheme}.bin`

Generate signatures using the key `{scheme}_secure_boot_signing_key.pem` and `openssl`: [Secure-Boot V2 Documentation](https://docs.espressif.com/projects/esp-idf/en/latest/security/secure-boot-v2.html#generating-and-verifying-signatures-using-openssl)

### Flash Encryption

`bootloader-encrypted.bin`

```
espsecure encrypt-flash-data -k 256bit_key.bin -a 0x1000 --flash-crypt-conf 0xF -o bootloader-encrypted.bin bootloader.bin
```

`bootloader-encrypted-conf{conf:x}.bin`

```
espsecure encrypt-flash-data -k 256bit_key.bin -a 0x1000 --flash-crypt-conf {conf} -o bootloader-encrypted-conf{conf:x}.bin bootloader.bin

where, conf = [0x0, 0x3, 0x9, 0xC]
```

`bootloader-encrypted-aes-xts.bin`

```
espsecure encrypt-flash-data -k 256bit_key.bin -a 0x1000 -x -o bootloader-encrypted-aes-xts.bin bootloader.bin
```

## Application Binaries

Base Application binaries: `hello-world-signed.bin`

### Flash Encryption

`hello-world-signed-encrypted.bin`

```
espsecure encrypt-flash-data -k ef-flashencryption-key.bin -a 0x20000 --flash-crypt-conf 0xF -o hello-world-signed-encrypted.bin hello-world-signed.bin
```

`hello-world-signed-encrypted-aes-xts.bin`

```
espsecure encrypt-flash-data -k ef-flashencryption-key.bin -a 0x20000 -x -o hello-world-signed-encrypted-aes-xts.bin hello-world-signed.bin
```

`hello-world-signed-encrypted-aes-xts-256.bin`

```
espsecure encrypt-flash-data -k 512bit_key.bin -a 0x10000 -x -o hello-world-signed-encrypted-aes-xts-256.bin hello-world-signed.bin
```
