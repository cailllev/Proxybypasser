from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Flask, request, jsonify, render_template, redirect, session
from hashlib import pbkdf2_hmac, sha256
from itertools import cycle
from os.path import isdir, isfile, join
from os import listdir
from secrets import token_bytes
import io
import zipfile

app = Flask(__name__)
app.secret_key = token_bytes(32) # 256 bit
login_pw_hash = b"\xe1\xe62f\x1e\x93\x05\x8b\xcb\xbd\xba\xf6:\xdd9\x9f\xf6\t\xe0\x07G\xc1\xbc\xd8\x06\xd1V_&\xd2e\x18"
pre_secret = b"Password > ECDH?"

base_path = "/mnt/public/"
pre_keys = {}
secret_keys = {}
download_ids = {}


def derive_secret_key(client_random, server_random) -> AESGCM:
    c = int(client_random).to_bytes(4, byteorder="big")
    s = int(server_random).to_bytes(4, byteorder="big")
    key_material = pre_secret + c + s
    derived_key = sha256(key_material).digest() # JS only supports sha256 natively... (f JS)
    return AESGCM(derived_key)


def makezip(filename, filedata):
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "a", zipfile.ZIP_DEFLATED, False) as zip_file:
        zip_file.writestr(filename, filedata)
    zip_buffer.seek(0)
    return zip_buffer.read()


def encrypt_aes(data: str, key: AESGCM) -> [str, str]:
    iv = token_bytes(12)
    cipher = key.encrypt(iv, data.encode(), None)
    return iv.hex(), cipher.hex()


def decrypt_aes(cipher: str, iv: str, key: AESGCM) -> str:
    iv = bytes.fromhex(iv)
    cipher = bytes.fromhex(cipher)
    return key.decrypt(iv, cipher, None).decode()


@app.route("/")
def index():
    return redirect("/login")


@app.route("/login", methods=["GET", "POST"])
def login():
    global pre_keys, secret_keys

    if "id" in session and session["id"] in secret_keys:
        return redirect("/download/")

    if request.method == "GET":
        r = int.from_bytes(token_bytes(4), byteorder="big")
        return render_template("login.html", server_random=r)

    pw = request.form.get("password")
    client_random = request.form.get("clientRandom")
    server_random = request.form.get("serverRandom")
    if not pw or not client_random or not server_random:
        return redirect("/login")

    h = pbkdf2_hmac("sha256", pw.encode(), b"p3pery-$4lt", 2<<16)
    if h == login_pw_hash: # create new secret key for each login
        secret_key = derive_secret_key(client_random, server_random)
        session_id = token_bytes(8)
        session["id"] = session_id
        secret_keys[session_id] = secret_key
        print(f"[*] Created new key for {session_id}")
        return redirect("/check")

    return redirect("/login")


@app.route("/check", methods=["GET", "POST"])
def check_keys():
    if "id" not in session or not session["id"] in secret_keys:
        return redirect("/login")
    key = secret_keys[session["id"]]

    if request.method == "GET":
        test_val = token_bytes(32).hex()
        iv, cipher = encrypt_aes(test_val, key)
        return render_template("check.html", iv=iv, test_val=test_val, test_val_enc=cipher)

    iv = request.form.get("iv")
    test_val = request.form.get("testVal")
    test_val_enc = request.form.get("testValEnc")
    if not iv or not test_val or not test_val_enc:
        return redirect("/login")

    if test_val == decrypt_aes(test_val_enc, iv, key):
        return redirect("/download/")

    return redirect("/logout") # wrong pre-secret


@app.route("/logout", methods=["GET"])
def logout():
    if "id" in session and session["id"] in secret_keys:
        secret_keys.pop(session["id"])
    session.clear()
    return redirect("/login")


@app.route("/download/", defaults={"filepath": ""})
@app.route("/download/<path:filepath>")
def download(filepath):
    # secure_filename removes trailing /, but this is required here
    if filepath.startswith("/") or ".." in filepath:
        return "File name must not start with / or contain ..", 400

    if "id" not in session or not session["id"] in secret_keys:
        return redirect("/login")
    key = secret_keys[session["id"]]

    if filepath != "": # non empty file(path) requested
        iv = request.args.get("iv")
        if not iv:
            return "IV missing", 400
        filepath = decrypt_aes(filepath, iv, key)

    p = join(base_path, filepath)
    if isdir(p):
        print(f"[*] Requested contents of {p}")
        files = [join(p, fp) for fp in listdir(p)]
        # appends / for directories
        files = [fp + "/" if isdir(fp) else fp for fp in files]
        # remove base path
        files = [fp.replace(base_path, "") for fp in files]
        files.sort(key = lambda fp: fp.lower())
        files_enc = [] # encrypt again for sending
        for fp in files:
            iv, cipher = encrypt_aes(fp, key)
            files_enc.append({"iv": iv, "name": cipher})
        print(f"[#] Encrypted filepaths in {p}")
        return render_template("filelist.html", filelist=files_enc)

    print(f"[*] Requested download for {p}")
    global download_ids
    file_id = token_bytes(16).hex() # 128 bit
    download_ids[file_id] = p
    print(f"[#] Created id: {file_id} => {p}")
    return redirect(f"/d/{file_id}")


@app.route("/d/<file_id>")
def download_with_random_name(file_id):
    global download_ids
    if "id" not in session or session["id"] not in secret_keys:
        return redirect("/login")
    key = secret_keys[session["id"]]

    if file_id not in download_ids:
        return f"File ID {file_id} no longer valid", 410 # rare "410 gone" use case - wow

    p = download_ids.pop(file_id) # id only valid for one download
    print(f"[#] Got id {file_id} => downloading {p}")

    if not isfile(p):
        return "ID valid but file not found", 404

    with open(p, "rb") as file:
        data = file.read()

    name = p.split("/")[-1]
    data = makezip(name, data)
    filecontent = b64encode(data).decode("utf-8")
    iv, cipher = encrypt_aes(filecontent, key)
    return render_template("download.html", filecontent_enc=cipher, iv=iv)
