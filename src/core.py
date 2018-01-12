from run_v1 import Resource


class Honeypots(Resource):
    """
    Honeypot Endpoint for getting stats about a given honeypot and even adding honeypots
    """

    def get(self):
        return None


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