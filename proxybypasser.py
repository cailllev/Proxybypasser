from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key
from flask import Flask, request, jsonify, render_template, redirect, session
from hashlib import pbkdf2_hmac
from itertools import cycle
from os.path import isdir, isfile, join
from os import listdir
from secrets import token_bytes
import io
import zipfile

app = Flask(__name__)
app.secret_key = token_bytes(32) # 256 bit
login_pw_hash = b"\xe1\xe62f\x1e\x93\x05\x8b\xcb\xbd\xba\xf6:\xdd9\x9f\xf6\t\xe0\x07G\xc1\xbc\xd8\x06\xd1V_&\xd2e\x18"
#pre_secret = "Password > ECDH?"

base_path = "/mnt/public/"
# invalidate keys over time?
pre_keys = {}
secret_keys = {}
download_ids = {}


def create_ec_keypair() -> (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey):
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()
    return private_key, public_key


def convert_to_pem(public_key: ec.EllipticCurvePublicKey) -> str:
    return public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    ).decode()


def convert_from_pem(data: bytes) -> ec.EllipticCurvePublicKey:
    return load_pem_public_key(data)


# TODO, incompatible with JS crypto?
def derive_secret_key(
        server_private_key: ec.EllipticCurvePrivateKey,
        client_public_key: ec.EllipticCurvePublicKey,
) -> AESGCM:
    shared_key = server_private_key.exchange(ec.ECDH(), client_public_key)
    derived_key = HKDF(
        algorithm=SHA256(),
        length=32, #256bit
        salt=b"",
        info=b"secret key"
    ).derive(shared_key)
    print("raw secret", [c for c in derived_key])
    aesgcm = AESGCM(derived_key)
    return aesgcm


@app.route("/")
def index():
    return redirect("/login")


@app.route("/login", methods=["GET", "POST"])
def login():
    global pre_keys, secret_keys

    if "id" in session and session["id"] in secret_keys:
        return redirect("/download/")

    if request.method == "GET":
        private_key, public_key = create_ec_keypair()
        pem = convert_to_pem(public_key)
        pre_keys[pem] = (private_key, public_key)
        pem_b64 = b64encode(pem.encode()).decode()
        return render_template("login.html", server_pem_b64=pem_b64)

    # POST
    pw = request.form.get("password")
    server_pem = b64decode(request.form.get("serverPEMb64").encode()).decode()
    client_pem = b64decode(request.form.get("clientPEMb64").encode()).decode()
    if not client_pem or server_pem not in pre_keys:
        print("client or server pem not found")
        return redirect("/login")
    server_private_key, server_public_key = pre_keys.pop(server_pem)

    if not pw:
        return redirect("/login")

    client_public_key = convert_from_pem(client_pem.encode())
    h = pbkdf2_hmac("sha256", pw.encode(), b"p3pery-$4lt", 2<<16)
    if h == login_pw_hash: # create new secret key for each login
        secret_key = derive_secret_key(server_private_key, client_public_key)
        secret_key = AESGCM(b"e"*32) # TODO
        session_id = token_bytes(8)
        session["id"] = session_id # token_bytes(16).hex() # 128 bit
        secret_keys[session_id] = secret_key
        return redirect("/download/")

    return redirect("/login")


@app.route("/logout", methods=["GET"])
def logout():
    if "id" in session and session["id"] in secret_keys:
        secret_keys.pop(session["id"])
    session.clear()
    return redirect("/login")


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
