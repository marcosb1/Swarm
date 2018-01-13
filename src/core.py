from flask import request
from flask_restful import Resource
import pprint
import json
from src.helpers import _validate_honeypot_input


class Honeypots(Resource):
    """
    Honeypot Endpoint for getting stats about a given honeypot and even adding honeypots
    """

    def get(self):
        """No IP/HPID Passed in, thus returns all honeypots(Limit?)"""
        args = request.args
        pprint.pprint(args)

        if _validate_honeypot_input(args):
            print("YES")
        else:
            return json.loads('{"ERROR": "Input(s) not valid"}')

class IPs(Resource):
    """
    IP Endpoint for getting stats about a given IP. Also get info about neighborhoods of IPs
    """

    def get(self):
        return None


class Usernames(Resource):
    """
    Username Endpoint for getting stats about a given username.
    """

    def get(self):
        return None


class Passwords(Resource):
    """
    Password Endpoint for getting stats about a given password.
    """

    def get(self):
        return None


class Dictionaries(Resource):
    """
    Dictionary Endpoint for getting stats about a given dictionary.
    """

    def get(self):
        return None


class Attacks(Resource):
    """
    Attack Endpoint for getting information about a given attack
    """

    def get(self):
        return None


class ISPs(Resource):
    """
    ISP Endpoint for getting stats about a given ISP
    """

    def get(self):
        return None


class Geolocations(Resource):
    """
    Geolocation Endpoint for getting stats about a given location.
    """