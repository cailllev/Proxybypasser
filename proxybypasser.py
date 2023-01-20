from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Flask, request, jsonify, render_template, redirect, session
from hashlib import pbkdf2_hmac, sha256
from io import BytesIO
from itertools import cycle
from os.path import isdir, isfile, join
from os import listdir
from re import search
from secrets import token_bytes
from werkzeug.exceptions import HTTPException
from zipfile import ZipFile, ZIP_DEFLATED, ZIP_STORED

import logging
logging.basicConfig(
        filename="log.txt",
        format="%(asctime)s - %(levelname)s - %(message)s",
        level=logging.INFO
)

# init app and secret key
app = Flask(__name__)
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0 # never cache any responses
app.secret_key = token_bytes(32) # 256 bit
login_pw_hash = "179952e9825ad2f9e53acb7df06fd45aa63f7ca98848c6f24fa11dca1ca0f320"
pre_secret = b"Password > ECDH?"

/mnt/publicsecret_keys = {}
download_ids = {}

av_bypass_size = 50_000 * 1024 # defender doesn't scan downloaded files > 50MB


def derive_secret_key(client_random: str, server_random: str, salt: str) -> AESGCM:
    c = int(client_random).to_bytes(4, byteorder="big")
    s = int(server_random).to_bytes(4, byteorder="big")
    salt = bytes.fromhex(salt)
    key_material = pre_secret + c + s
    derived_key = pbkdf2_hmac("sha256", key_material, salt, 2**20)
    return AESGCM(derived_key)


def makezip(filename, filedata, bypass):
    buffer = BytesIO()
    if not bypass:
        with ZipFile(buffer, "w", compression=ZIP_DEFLATED, allowZip64=False) as zip_file:
            zip_file.writestr(filename, filedata)
    else:
        num_bypass_bytes = av_bypass_size - len(filedata)
        with ZipFile(buffer, "a", compression=ZIP_STORED, allowZip64=False) as zip_file:
            zip_file.writestr(filename, filedata)
            zip_file.writestr("junk.bin", b"A" * num_bypass_bytes)
    buffer.seek(0)
    return buffer.read()


def encrypt_aes(data: str, key: AESGCM) -> [str, str]:
    iv = token_bytes(12)
    cipher = key.encrypt(iv, data.encode(), None)
    return iv.hex(), cipher.hex()


def decrypt_aes(cipher: str, iv: str, key: AESGCM) -> str:
    iv = bytes.fromhex(iv)
    cipher = bytes.fromhex(cipher)
    return key.decrypt(iv, cipher, None).decode()


def search_and_replace_longest_occ(data, to_replace):
    i = longest_occ = start_ind = 0
    while True:
        r = search(f"({to_replace})+", data[i:])
        if not r:
            break
        if (l := r.end() - r.start()) > longest_occ:
            longest_occ = l
            start_ind = r.start() + i
        i += r.end()
    reps = int(longest_occ / len(to_replace))
    return f'"{data[:start_ind]}" + "{to_replace}".repeat({reps}) + "{data[start_ind+longest_occ:]}"'


@app.route("/")
def index():
    return redirect("/login")


@app.route("/login", methods=["GET", "POST"])
def login():
    global secret_keys

    if "id" in session and session["id"] in secret_keys:
        return redirect("/download/")

    if request.method == "GET":
        r = int.from_bytes(token_bytes(4), byteorder="big")
        s = token_bytes(16).hex()
        return render_template("login.html", server_random=r, salt=s)

    pw = request.form.get("password")
    name = request.form.get("name")
    client_random = request.form.get("clientRandom")
    server_random = request.form.get("serverRandom")
    salt = request.form.get("salt")
    if not pw or not client_random or not server_random or not salt:
        return redirect("/login")
    if not name or any(name == existing_name for _, existing_name in secret_keys.values()):
        name = "user-" + str(len(secret_keys)+1)

    h = pbkdf2_hmac("sha256", pw.encode(), b"p3pery-$4lt", 1<<20).hex()
    if h == login_pw_hash: # create new secret key for each login
        secret_key = derive_secret_key(client_random, server_random, salt)
        session_id = token_bytes(8)
        secret_keys[session_id] = secret_key, name
        logging.info(f"[*] Created new key for {name}")
        session["id"] = session_id
        session.permanent = True # do not expire session after closing the browser, expires after 31 days
        return redirect("/check")

    return redirect("/login")


@app.route("/check", methods=["GET", "POST"])
def check_keys():
    if "id" not in session or not session["id"] in secret_keys:
        return redirect("/login")
    key, name = secret_keys[session["id"]]

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

    logging.info(f"[!] Failed login for {name}")
    return redirect("/logout") # wrong pre-secret


@app.route("/logout", methods=["GET"])
def logout():
    if "id" in session and session["id"] in secret_keys:
        _, name = secret_keys.pop(session["id"])
        logging.info(f"[*] Deleting session for {name}")
    session.clear()
    return redirect("/login")


@app.route("/download/", defaults={"filepath": ""})
@app.route("/download/<path:filepath>")
def download(filepath):
    global download_ids
    if "id" not in session or not session["id"] in secret_keys:
        return redirect("/login")
    key, name = secret_keys[session["id"]]
    size_bypass = True if request.args.get("b") else False

    if filepath != "": # non empty file(path) requested
        iv = request.args.get("iv")
        if not iv:
            logging.info("[#] IV missing in request!")
            return redirect("/download/")
        filepath = decrypt_aes(filepath, iv, key)

    # secure_filename removes all /, not working here
    if ".." in filepath:
        return "File name must not contain ..", 400
    while filepath.startswith("/"): # path.join("/a/b", "/c") -> "/c", NOT "/a/b/c"
        filepath = filepath[1:]

    p = join(base_path, filepath)
    if isdir(p):
        logging.info(f"[*] {name} requested contents of {p}")
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
        # add last folder to navigate back
        back = "/".join(filepath.split("/")[:-2]) + "/"
        iv, cipher = encrypt_aes(back, key)
        files_enc.insert(0, {"iv": iv, "name": cipher})
        checked = "checked" if size_bypass else ""
        return render_template("filelist.html", filelist=files_enc, back_cipher=cipher, back_iv=iv, checked=checked)

    logging.info(f"[*] {name} requested download for {p} with bypass = {size_bypass}")
    file_id = token_bytes(16).hex() # 128 bit
    download_ids[file_id] = p
    logging.info(f"[#] Created id: {file_id} => {p}")

    link = f"/d/{file_id}"
    if size_bypass:
        link += "?b=1"
    return redirect(link)


@app.route("/d/<file_id>")
def download_with_random_name(file_id):
    global download_ids
    if "id" not in session or session["id"] not in secret_keys:
        return redirect("/login")
    key, name = secret_keys[session["id"]]

    if file_id not in download_ids:
        return f"File ID {file_id} no longer valid", 410 # rare "410 gone" use case - wow

    p = download_ids.pop(file_id) # id only valid for one download
    if not isfile(p):
        return "ID valid but file not found", 404
    size_bypass = True if request.args.get("b") else False
    logging.info(f"[*] {name} sent id {file_id} => downloading {p} with bypass = {size_bypass}")

    with open(p, "rb") as file:
        data = file.read()

    filename = p.split("/")[-1]
    filepath = p[len(base_path):-len(filename)]
    fp_iv, fp_enc = encrypt_aes(filepath, key)
    data_zipped = makezip(filename, data, size_bypass)
    data_b64 = b64encode(data_zipped).decode("utf-8")

    if size_bypass: # only encrypt the file data, not the random bytes
        len_real_data = int(len(data) / 6 * 8) + 1 # b64encoded length
        len_real_data += 100 # zip header & co
        to_encrypt = data_b64[:len_real_data]
        junk = data_b64[len_real_data:]
        junk = search_and_replace_longest_occ(junk, "QUFB") # b64("AAA") => QUFB
        bypass_query = "&b=1"
    else:
        to_encrypt = data_b64
        junk = '""'
        bypass_query = ""
    iv, cipher = encrypt_aes(to_encrypt, key)
    return render_template("download.html", filecontent_enc=cipher, iv=iv, junk=junk, fp_enc=fp_enc, fp_iv=fp_iv, bypass_query=bypass_query)


@app.errorhandler(Exception)
def handle_exception(e):
    if isinstance(e, HTTPException): # don't catch 4xx errors
        return e

    logging.error(f"[!] Error: {e}")
    return "Bad Request<!--you made the server vewy angwy, pls stop-->", 400
