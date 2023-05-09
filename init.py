import requests


domain = "http://assignment-code-warriors.unimelb.life/"
flag_pattern = r"FLAG\{.+?\}"

username = "jiahchen4"
password = "jiahchen4"
auth_url = domain + "auth.php"
login_fail_msg = "Username or password is incorrect. Please try again."


def login():
    session = requests.Session()
    auth_data = {
        "user": username,
        "pass": password
    }
    resp = session.post(auth_url, data=auth_data)
    if resp.text == login_fail_msg:
        print(login_fail_msg)
    else:
        print("Successful Login ...")
    return session
