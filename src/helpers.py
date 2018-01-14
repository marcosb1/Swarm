import socket
import copy
import psycopg2.extras
from flask import g
import pprint
import json

from src.json_templates import response_get_honeypot, response_get_honeypots

db = psycopg2.connect("dbname=" + "Beekeeper" + " user=" + "postgres"
                            + " host=" + "10.11.12.80" + " password=" + "Password1")


def is_valid_ipv4_address(address):
    try:
        socket.inet_aton(address)
    except socket.error:
        return False

    if address.count(".") == 3:
        temp_list = address.split(".")
        for i in range(0, len(temp_list)):
            if isinstance(int(temp_list[i]), int) is not True:
                return False

            if int(temp_list[i]) < 0 or int(temp_list[i]) > 254:
                return False

            if temp_list[i] is temp_list[len(temp_list) - 1] and int(temp_list[i]) is 0:
                return False

        return True

    return False


def is_valid_ipv6_address(address):
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:  # not a valid address
        return False
    return True


def _validate_honeypot_input(args):
    if len(args) == 0:
        return True
    else:
        for key, value in args.items():
            if key[:2].lower() == 'ip' and is_valid_ipv4_address(value) is not True:
                # if is_valid_ipv6_address(value) is not True:
                    return False
            elif key[:4].lower() == 'hpid' and isinstance(value, str) is not True:
                return False
    return True


def _process_honeypot_get(args):
    response = copy.deepcopy(response_get_honeypots)

    if len(args) == 0:
        response["Honeypots"].append(_build_honeypot_get_response())

    for key, value in args.items():
        if key[:2].lower() == 'ip':
            response["Honeypots"].append(_build_honeypot_get_response(value, "ip"))
        elif key[:4].lower() == 'hpid':
            response["Honeypots"].append(_build_honeypot_get_response(value, "hpid"))

    return response


def _build_honeypot_get_response(arg=None, type=None):

    hpid = ""
    cursor = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
    response = copy.deepcopy(response_get_honeypot)

    if type is "ip":
        cursor.execute(
            'Select honeypot_id from honeypot_IPS where ip = %s order by create_time AT TIME ZONE \'UTC\' DESC limit 1',
            (arg,)
        )

        # Row holds the HPID
        row = cursor.fetchone()

        if row:
            hpid = row["honeypot_id"]
        else:
            return json.loads('{"ERROR": "No honeypot found for IP: ' + arg + '"}')

    elif type is "hpid":
        cursor.execute(
            'Select honeypot_id from honeypots where honeypot_id = %s limit 1',
            (arg,)
        )

        # Row holds the HPID
        row = cursor.fetchone()

        if row:
            hpid = row["honeypot_id"]
        else:
            return json.loads('{"ERROR": "No honeypot found for HPID: ' + arg + '"}')

    # HPID
    response["HPID"] = hpid

    # IP History
    cursor.execute(
        'Select ip, create_time AT TIME ZONE \'UTC\' from Honeypot_IPS where honeypot_id = %s '
        'order by create_time AT TIME ZONE \'UTC\' DESC',
        (hpid,)
    )
    ips = cursor.fetchall()

    for ip in ips:
        response["IP History"].append(ip["ip"])

    # Services
    cursor.execute(
        'Select service, port from honeypot_services where honeypot_id = %s',
        (hpid,)
    )

    services = cursor.fetchall()

    current_services = []
    for service in services:
        if service["service"] in current_services:
            response["Services"][service["service"]].append(service["port"])
        else:
            response["Services"].append(json.loads('{"' + service["service"] + '": []}'))
            current_services.append(service["service"])
            pprint.pprint(response)

    pprint.pprint(response)
