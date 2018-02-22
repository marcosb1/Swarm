import logging
from flask import Flask, g, current_app
from flask_restful import Api, Resource
from flask_cors import CORS
from src.core import HoneypotsGetUpdate, HoneypotsPutDelete
import psycopg2.extras
import pprint


# logging.basicConfig(filename="Swarm.log", level=logging.DEBUG,
#                     format="%(asctime)s.%(msecs)03d %(levelname)s:%(message)s",
#                     datefmt='%Y-%m-%d %H:%M:%S')

class HTTPMethodOverrideMiddleware(object):
    allowed_methods = frozenset([
        'GET',
        'HEAD',
        'POST',
        'DELETE',
        'PUT',
        'PATCH',
        'OPTIONS'
    ])
    bodyless_methods = frozenset(['HEAD', 'OPTIONS', 'DELETE'])

    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        method = environ.get('HTTP_X_HTTP_METHOD_OVERRIDE', '').upper()
        if method in self.allowed_methods:
            # method = method.encode('ascii', 'replace')
            # encoding with a b'GET'????
            environ['REQUEST_METHOD'] = method
        if method in self.bodyless_methods:
            environ['CONTENT_LENGTH'] = '0'
        return self.app(environ, start_response)


app = Flask(__name__)
app.wsgi_app = HTTPMethodOverrideMiddleware(app.wsgi_app)
CORS(app)
api = Api(app)
api.add_resource(HoneypotsGetUpdate, '/honeypots')
api.add_resource(HoneypotsPutDelete, '/honeypots/<hpid>')


if __name__ == '__main__':
    app.run(debug=True)

