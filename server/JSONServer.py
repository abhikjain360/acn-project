from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import joblib
import pandas as pd

PORT_NUMBER = 8000

class handler(BaseHTTPRequestHandler):

    def run(self, data):
        df = pd.DataFrame([data])
        df.replace(False, 0, inplace=True)
        df.replace(True, 1, inplace=True)
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        # the dataframe from json
        inp = df.iloc[0].to_numpy().reshape((1, 24))
        # pls figure out data dimensions pls :|
        json_object = json.dumps(
            {"random_forest": int(clf.predict(inp)[0])})
        self.wfile.write(bytes(json_object, "utf8"))

    def log_message(self, format, *args):
        return

    def do_POST(self):
        ln = int(self.headers.get('content-length'))
        self.run(json.loads(self.rfile.read(ln)))


with HTTPServer(('', PORT_NUMBER), handler) as server:
    clf = joblib.load("./random_forest.pkl")

    server.serve_forever()
