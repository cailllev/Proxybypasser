import requests as req
from os import system
from re import search


url = "http://localhost:8081"
tmp_file = "/mnt/public/this-is-a-temporary-test-file-with-a-long-name-to-really-test-it.txt"
tmp_contents = bytearray([i for i in range(256)])


def init():
    with open(tmp_file, "wb") as f:
        f.write(tmp_contents)
    try:
        res = req.get(url)
    except req.exceptions.ConnectionError:
        print(f"[!] Server down? Make sure the proxybypasser is started and reachable at {url}")

    s = req.Session()
    s.post(url + "/login", data={"password": "Red Team Deluxe"})
    return s


def test_file_listing(s):
    # this site needs to be rendered with JS, else the tests won't work
    res = s.get(url + "/download").text
    parsed = search('<a href="(.)*">(.)*</a>', res).groups()
    link, name = parsed[0], parsed[1]
    print(f"[*] Got {link = } and {name = }")
    return link


def test_file_download(s, download_link):
    res = s.get(url + download_link)
    print(res.text)
    res = s.get(url + "/d/" + file_id)
    print(res.text)


def main():
    sess = init()
    download_link = test_file_listing(sess)
    test_file_download(sess, download_link)
    system(f"rm {tmp_file}")
    print("[*] All tests succeded")


if __name__ == "__main__":
    print("[#] WARNING: Tests are not complete, js must be executed to test it")
    main()



