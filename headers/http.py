import random
import json


class HTTP:

    def __init__(self, url, method, content_type=None):
        self.host = url.split("/")[2]
        self.route = "/".join(url.split("/")[3:])
        self.secure = "s" in url.split("/")[0]
        self.method = method
        self.content_type = content_type

    def get_http_header(self):
        with open('data/user-agents.txt', 'r') as f:
            user_agents = [ua.strip() for ua in f.readlines()]

        referer_list = ["http://www.bing.com/search?q=",
                        "http://www.google.com/search?q=",
                        "http://duckduckgo.com/?q=",
                        "http://en.wikipedia.org/wiki/Special:Search?search="]

        if self.method == "GET":
            return f"GET /{self.route} HTTP/1.1\r\n" \
                   f"Host: {self.host}\r\n" \
                   f"User-Agent: {random.choice(user_agents).strip()}\r\n" \
                   f"Cache-Control: no-store\r\n" \
                   f"Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n" \
                   f"Referer: {random.choice(referer_list)}\r\n" \
                   f"Keep-Alive: {random.randint(110, 120)}\r\n" \
                   f"Connection: keep-alive\r\n\r\n".encode('utf-8')

        if self.method == "POST":
            with open('data/content-type.json', 'r') as f:
                types = json.load(f)

            return f"POST /{self.route} HTTP/1.1\r\n" \
                   f"Host: {self.host}\r\n" \
                   f"User-Agent: {random.choice(user_agents).strip()}\r\n" \
                   f"Content-Type: {types[self.content_type]}\r\n" \
                   f"Cache-Control: no-store\r\n\r\n".encode('utf-8')