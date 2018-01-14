import logging
from flask import Flask, g, current_app
from flask_restful import Api, Resource
from src.core import Honeypots
import psycopg2.extras
import pprint


# logging.basicConfig(filename="Swarm.log", level=logging.DEBUG,
#                     format="%(asctime)s.%(msecs)03d %(levelname)s:%(message)s",
#                     datefmt='%Y-%m-%d %H:%M:%S')

app = Flask(__name__)
api = Api(app)
api.add_resource(Honeypots, '/honeypots')


if __name__ == '__main__':
    app.run(debug=True)

