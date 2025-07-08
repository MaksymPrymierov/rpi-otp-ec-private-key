# rpi-otp-ec-private-key(1)

## NAME

rpi-otp-ec-private-key - Generate ECDSA private key PEM from Raspberry Pi OTP

## SYNOPSIS

**rpi-otp-ec-private-key**

## DESCRIPTION

**rpi-otp-ec-private-key** reads a 32-byte private key from Raspberry Pi OTP (One Time Programmable) memory and outputs a complete ECDSA private key in PEM format.

This tool is related to **rpi-otp-private-key** but generates a complete PEM that can be used directly with OpenSSL tools, rather than just raw bytes.

The generated key uses the SECP256R1 curve (also known as P-256, prime256v1, or NIST P-256).

## USAGE

Generate a private key PEM from OTP:

```bash
rpi-otp-ec-private-key
```

Save the key to a file in tmpfs:

```bash
rpi-otp-ec-private-key > /run/private_key.pem
```

Extract the public key:

```bash
rpi-otp-ec-private-key | openssl pkey -pubout
```

## REQUIREMENTS

The OTP must contain a valid 32-byte SECP256R1 private key value. The key must be non-zero and within the valid range for the curve.

## EXIT STATUS

- **0**: Success
- **1**: Error (OTP read failure, invalid key, or other error)

## SEE ALSO

**openssl**(1), **openssl-pkey**(1), **rpi-otp-private-key**(1)

## AUTHOR

Richard Oliver <richard.oliver@raspberrypi.com>

## COPYRIGHT

Copyright 2025 Raspberry Pi. Licensed under the 3-clause BSD License. 