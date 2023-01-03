from flask import Flask, request, jsonify, render_template, redirect, session
from hashlib import pbkdf2_hmac
from itertools import cycle
from os.path import isdir, isfile, join
from os import listdir
from secrets import token_bytes
import base64
import io
import zipfile

app = Flask(__name__)
app.secret_key = token_bytes(32) # 256 bit
app.config['SESSION_COOKIE_HTTPONLY'] = False # client side JS needs access to the decryption key
pw_hash = b"\xe1\xe62f\x1e\x93\x05\x8b\xcb\xbd\xba\xf6:\xdd9\x9f\xf6\t\xe0\x07G\xc1\xbc\xd8\x06\xd1V_&\xd2e\x18"

base_path = "/mnt/public/"
download_ids = {}


@app.route("/")
def index():
    return redirect("/login")


@app.route("/login", methods=["GET", "POST"])
def login():
    if "key" in session and session["key"]:
        return redirect("/download/")
    if request.method == "GET":
        return render_template("login.html")
    pw = request.form.get("password")
    if pw is None:
        return False
    h = pbkdf2_hmac("sha256", pw.encode(), b"p3pery-$4lt", 2<<16)
    if h == pw_hash:
        session["key"] = token_bytes(16).hex() # 128 bit
        return redirect("/download/")
    return redirect("/login")


@app.route("/logout", methods=["GET"])
def logout():
        session.clear()
        return redirect("/login")


def makezip(filename, filedata):
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "a", zipfile.ZIP_DEFLATED, False) as zip_file:
        zip_file.writestr(filename, filedata)
    zip_buffer.seek(0)
    return zip_buffer.read()


def encrypt(data: str) -> str:
    key = get_session_key()
    cipher = bytearray([f ^ k for f, k in zip(data.encode(), cycle(key))])
    return base64.b64encode(cipher).decode().replace("A", "(").replace("B", ")")


def decrypt(cipher: str) -> str:
    key = get_session_key()
    cipher = base64.b64decode(cipher.encode().replace(b"(", b"A").replace(b")", b"B"))
    return "".join([chr(f ^ k) for f, k in zip(cipher, cycle(key))])


def get_session_key() -> bytes:
    return bytes.fromhex(session["key"])


@app.route("/download/", defaults={"filepath": ""})
@app.route("/download/<path:filepath>")
def download(filepath):
    # secure_filename removes trailing /, but this is required here
    if filepath.startswith("/") or ".." in filepath:
        return "File name must not start with / or contain ..", 400

    if "key" not in session or not session["key"]:
        return redirect("/login")

    p = decrypt(filepath)
    p = join(base_path, p)
    if isdir(p):
        print(f"[*] Requested contents of {p}")
        files = [join(p, fp) for fp in listdir(p)]
        # appends / for directories
        files = [fp + "/" if isdir(fp) else fp for fp in files]
        # remove base path
        files = [fp.replace(base_path, "") for fp in files]
        files.sort(key = lambda fp: fp.lower())
        files = [encrypt(fp) for fp in files] # encrypt again for sending
        print(f"[#] Encrypted filepaths in {p}")
        return render_template("filelist.html", filelist=files)

    print(f"[*] Requested download for {p}")
    global download_ids
    file_id = token_bytes(16).hex() # 128 bit
    download_ids[file_id] = p
    print(f"[#] Created id: {file_id} => {p}")
    return redirect(f"/d/{file_id}")


@app.route("/d/<file_id>")
def download_with_random_name(file_id):
    global download_ids
    if "key" not in session or not session["key"]:
        return redirect("/login")

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
    filecontent = base64.b64encode(data).decode("utf-8")
    filecontent_enc = encrypt(filecontent)
    return render_template("download.html", filecontent_enc=filecontent_enc)
