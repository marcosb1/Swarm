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
        body = request.get_json(silent=True)

        if body is None:
            return json.loads('{"ERROR": "GET Requires JSON Body"}'), 400
        else:
            try:
                _validate_honeypot_input(body)
            except ValueError as error:
                return error.args[0], 400
            pprint.pprint(body)
            return _process_honeypot_get(body), 200


class HoneypotsPutDelete(Resource):

    def put(self, hpid):
        if _validate_hpid_input(hpid):
            body = request.get_json(silent=True)

            return _process_honeypot_put(body, hpid), 200
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