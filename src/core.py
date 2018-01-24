from flask import request
from flask_restful import Resource
import pprint
import json
from src.helpers import _validate_honeypot_input, _process_honeypot_get, _validate_hpid_input, _process_honeypot_put


class HoneypotsGetUpdate(Resource):
    """
    Honeypot Endpoint for getting stats about a given honeypot and even adding honeypots
    """

    def get(self):
        """No IP/HPID Passed in, thus returns all honeypots(Limit?)"""
        args = request.args
        pprint.pprint(args)

        if _validate_honeypot_input(args):
            print("YES")
            return _process_honeypot_get(args), 200
        else:
            return json.loads('{"ERROR": "Input(s) not valid"}'), 400


class HoneypotsPutDelete(Resource):

    def put(self, hpid):
        if _validate_hpid_input(hpid):
            body = request.get_json(silent=True)
            pprint.pprint(body)

            print(body["IP"])
            print("Yes")
            return _process_honeypot_put(body, hpid)
        else:
            return json.loads('{"ERROR": "Input(s) not valid"}'), 400


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