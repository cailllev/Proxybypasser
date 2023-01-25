from hashlib import pbkdf2_hmac
from re import match

filename = "proxybypasser.py"


def replace_in_file(old, new):
    with open(filename) as f:
        lines = f.readlines()
    for i, line in enumerate(lines):
        if match(old, line):
            lines[i] = new
            break
    with open(filename, "w") as f:
        f.writelines(lines)


def main():
    root_dir = input("[*] Please enter the root directory of the webserver (files in this folder will be available "
                     "for downloading): ")
    replace_in_file('base_path = ".*"', f'base_path = "{root_dir}"\n')

    pre_secret = input("[*] Please enter your pre secret: ")
    replace_in_file('pre_secret = b".*"', f'pre_secret = b"{pre_secret}"\n')

    password = input("[*] Please enter your password: ")
    login_pw_hash = pbkdf2_hmac("sha256", password.encode(), b"p3pery-$4lt", 1 << 20).hex()
    replace_in_file('login_pw_hash = ".*"', f'login_pw_hash = "{login_pw_hash}"\n')


if __name__ == "__main__":
    main()
