from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import pandas as pd

PORT_NUMBER = 8000
import json


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

        message = "Hello, World! Here is a GET response"
        self.wfile.write(bytes(message, "utf8"))

    def run(self, data):
        print(type(data))  # return a dictionary
        print(pd.DataFrame([data]))  # convert dictionary to dataframe

    def do_POST(self):
        ln = int(self.headers.get('content-length'))
        self.run(json.loads(self.rfile.read(ln)))
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        json_object = json.dumps({"random_forest": 1.0})
        self.wfile.write(bytes(json_object, "utf8"))


with HTTPServer(('', PORT_NUMBER), handler) as server:
    server.serve_forever()
