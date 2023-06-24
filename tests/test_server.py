import json
import time
from random import random

from flask import Flask, request

app = Flask(__name__)


@app.route('/', defaults={'path': ''}, methods=['POST', 'GET'])
@app.route('/<path:path>', methods=['POST', 'GET'])
def endpoint(path):
    time.sleep(0.2+0.05*random())
    if '\'' in request.url:  # simulate potential SQLi
        return 'Error.', 500
    if '..' in request.url:  # simulate potential directory traversal
        return 'Not found.', 404
    if "nan" in request.form.values():  # simulate nan injection
        return 'nan error in form data', 500
    if (
        "jsondata" in request.url  # flask will throw 400 if .json is accessed without json data in the body
        and "+nan" in json.dumps(request.json)
    ):
        return 'nan error in JSON data', 500
    if random() < 0.2:  # simulate unreliable API
        return 'Service unavailable.', 503

    return request.url + '\n' + str(request.cookies)


if __name__ == '__main__':
    app.run(port=443)
