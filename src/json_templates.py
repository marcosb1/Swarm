DEFAULT_COUNT = 10

response_get_honeypots = \
    {
        "Honeypots": []
    }

response_get_honeypot = \
    {
        "HPID": "",
        "IP History": [],
        "Services": [],
        "Number of Attempts": 0,
        "Top IPs": [],
        "Top Usernames": [],
        "Top Passwords": [],
        "Top Geolocation": []
    }

geolocation = \
    {
        "name": "",
        "value": 0,
        "code": "",
    }

default_services = \
    {
        "Start Timestamp": False,
        "End Timestamp": False
    }

default_attempts = \
    {
        "Start Timestamp": False,
        "End Timestamp": False,
        "Step": False,
        "Step Scale": False
    }

default_internal_geolocation = \
    {
        "LatLong": True,
        "Country": True,
        "Country Code": True,
        "City": True
    }

default_ips = \
    {
        "Count": DEFAULT_COUNT,
        "Geolocation": default_internal_geolocation,
        "Order": "asc"
    }

default_usernames = \
    {
        "Count": DEFAULT_COUNT,
        "Order": "asc"
    }

default_passwords = \
    {
        "Count": DEFAULT_COUNT,
        "Order": "asc"
    }

default_geolocations = \
    {
        "Count": DEFAULT_COUNT,
        "Country Code": False,
        "Order": "asc"
    }

default_ip_history = \
    {
        "Attempts": False,
        "Date Range": False,
        "Geolocation": default_internal_geolocation
    }

default_uptime = \
    {
        "Format": "epoch"
    }
