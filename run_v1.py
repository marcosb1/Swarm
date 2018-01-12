import logging
from flask import Flask
from flask_restful import Api, Resource

# logging.basicConfig(filename="Swarm.log", level=logging.DEBUG,
#                     format="%(asctime)s.%(msecs)03d %(levelname)s:%(message)s",
#                     datefmt='%Y-%m-%d %H:%M:%S')

app = Flask(__name__)
api = Api(app)


if __name__ == '__main__':
    app.run(debug=True)
