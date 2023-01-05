# What
Bypass any proxy content filters and hide file names as well as file contents from blue teams (even if they have a MitM proxy).

# Why
see above

# How
- TL;DR: spoofes content types and sends files as an "invalid" and encrypted base64 blob.
- Encrypts file contents, zips it, base64 encodes it and obfuscates the base64. Then sends this blob to the client side with spoofed content-type (the proxy cannot see and guess the real file types). The client side deobfuscates and decrypts the blob and downloads the zip containing the original file.
- Encrypts folder and file names to hide critical information like "campaign-4/" or "cobaltstrike-https.exe". Additionally generates a unique download link for each download so that the download links never repeat, even for the same file and same user.