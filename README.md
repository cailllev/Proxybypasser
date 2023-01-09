# Proxybypasser
## What?
Bypass any proxy content filters and hide file names as well as file contents from blue teams (even if they have a MitM proxy).

## Why?
Because we can, and see above.

## How?
- TL;DR: spoofes content types and sends files as an encrypted blob, even an active MitM cannot read the filenames and filecontents.
- Server and client derive a secret key from a public server_random, client_random and a private "pre_secret". This pre_secret must be known by both server and client and must never be sent. For this use-case this works, because the attacker controls the server and client, but cannot send secrets b.c. of a MitM blue team.
- Encrypts file contents, zips it and hex encodes all. Then sends this blob to the client side with spoofed content-type (the proxy cannot see and guess the real file types). The client side decrypts the blob and downloads the zip containing the original file.
- Encrypts folder and file names to hide critical information like "campaign-4/" or "cobaltstrike-https.exe". Additionally generates a unique download link for each download so that the download links never repeat, even for the same file and same user.

## Why a "pre-secret" instead of a proper key-exchange?
A proper key-exchange could be intercepted, unless the server has a known certificate and signs it's key exchange parameters with this certificate. Too much komplexity compared to a simple pre-secret and hashing. Additionally the pre-secret is easier to change.

# Setup
```
git clone https://github.com/dobin/Proxybypasser
cd Proxybypasser
pip3 install -r requirements.txt
./start_server.sh
```
