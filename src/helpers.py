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
        MAX_HONEYPOTS_RETURNED = 10

        honeypots = _get_hpid(MAX_HONEYPOTS_RETURNED)

        for honeypot in honeypots:
            response["Honeypots"].append(_build_honeypot_get_response(honeypot, "hpid"))

    for key, value in args.items():
        if key[:2].lower() == 'ip':
            response["Honeypots"].append(_build_honeypot_get_response(value, "ip"))
        elif key[:4].lower() == 'hpid':
            response["Honeypots"].append(_build_honeypot_get_response(value, "hpid"))

    return response


def _get_hpid(num):
    honeypots = []

    cursor = db.cursor(cursor_factory=psycopg2.extras.DictCursor)

    cursor.execute(
        'Select honeypot_id from honeypots order by honeypot_id ASC limit %s',
        (num,)
    )

    rows = cursor.fetchall()

    for row in rows:
        honeypots.append(row["honeypot_id"])

    return honeypots


def _build_honeypot_get_response(arg=None, type=None):

    hpid = ""
    times = None
    cursor = db.cursor(cursor_factory=psycopg2.extras.DictCursor)
    # cursorTemp = db.cursor(cursor_factory=psycopg2.extras.NamedTupleCursor)
    response = copy.deepcopy(response_get_honeypot)

    if type == "ip":
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

    elif type == "hpid":
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
    response = _format_ip_history(cursor, response, hpid)

    # Services
    response = _format_services(cursor, response, hpid)

    # Number of Attempts, Top IPS, TOP Username, TOP Passwords, Top Geolocation
    if type == "ip":
        times = _honeypot_bounds(cursor, arg, hpid)
        response = _number_of_attempts(cursor, hpid, type, response, times)
        response = _top_ips(cursor, hpid, type, response, times)
        response = _top_usernames(cursor, hpid, type, response, times)
        response = _top_passwords(cursor, hpid, type, response, times)
        response = _top_geolocation(cursor, hpid, type, response, times)
    elif type == "hpid":
        response = _number_of_attempts(cursor, hpid, type, response)
        response = _top_ips(cursor, hpid, type, response)
        response = _top_usernames(cursor, hpid, type, response)
        response = _top_passwords(cursor, hpid, type, response)
        response = _top_geolocation(cursor, hpid, type, response)

    return response


def _format_ip_history(cursor, response, hpid):
    cursor.execute(
        'Select ip, create_time AT TIME ZONE \'UTC\' from Honeypot_IPS where honeypot_id = %s '
        'order by create_time AT TIME ZONE \'UTC\' DESC',
        (hpid,)
    )
    rows = cursor.fetchall()

    for row in rows:
        response["IP History"].append(row["ip"])

    return response


def _format_services(cursor, response, hpid):
    cursor.execute(
        'Select service, port from honeypot_services where honeypot_id = %s',
        (hpid,)
    )

    rows = cursor.fetchall()

    current_services = []

    for row in rows:
        if row["service"] in current_services:
            index = _find_service_index(response, row["service"])
            response["Services"][index][row["service"]].append(row["port"])
        else:
            response["Services"].append({row["service"]: []})
            index = _find_service_index(response, row["service"])
            response["Services"][index][row["service"]].append(row["port"])
            current_services.append(row["service"])

    return response


def _find_service_index(response, name):
    count = 0

    for service in response["Services"]:
        for key, value in service.items():
            if key == name:
                return count
            else:
                count = count + 1


def _honeypot_bounds(cursor, ip, hpid):
    create_time = None
    end_time = None


    cursor.execute(
        'Select ip, create_time from Honeypot_IPS where honeypot_id = %s '
        'order by create_time ASC ',
        (hpid,)
    )

    rows = cursor.fetchall()

    for row in rows:
        if ip == row["ip"]:
            create_time = row["create_time"]
        elif create_time is not None:
            end_time = row["create_time"]
            break

    return (create_time, end_time)


def _number_of_attempts(cursor, hpid, type, response, arg=None):
    if type == "ip":

        cursor.execute(
            'Select honeypot_ip, count(attempt_id) as attempt_count from honeypot_endpoint_get '
            'where \'[%s, %s]\'::tstzrange @> timestamp and \'[%s, %s)\'::tstzrange @> create_time '
            'and honeypot_id = %s group by honeypot_ip',
            (arg[0], arg[1], arg[0], arg[1], hpid)
        )

        row = cursor.fetchone()

        if row:
            response["Number of Attempts"] = row["attempt_count"]

    elif type == "hpid":
        cursor.execute(
            'Select honeypot_ip, count(attempt_id) as attempt_count from honeypot_endpoint_get '
            'where honeypot_id = %s group by honeypot_ip',
            (hpid,)
        )

        row = cursor.fetchone()

        if row:
            response["Number of Attempts"] = row["attempt_count"]

    return response


def _top_ips(cursor, hpid, type, response, arg=None):
    if type == "ip":

        cursor.execute(
            'Select ip, count(attempt_id) as attempt_count from honeypot_endpoint_get where '
            '\'[%s, %s]\'::tstzrange @> timestamp and \'[%s, %s)\'::tstzrange @> create_time and honeypot_id = %s '
            'group by ip order by attempt_count DESC limit 10',
            (arg[0], arg[1], arg[0], arg[1], hpid)
        )

        rows = cursor.fetchall()

        for row in rows:
            response["Top IPs"].append({row["ip"]: row["attempt_count"]})

    elif type == "hpid":

        cursor.execute(
            'Select ip, count(attempt_id) as attempt_count from attacks_connections_attempts inner join '
            'honeypots on attacks_connections_attempts.honeypot_id = honeypots.honeypot_id where '
            'attacks_connections_attempts.honeypot_id = %s group by ip order by attempt_count DESC limit 10',
            (hpid,)
        )

        rows = cursor.fetchall()

        for row in rows:
            response["Top IPs"].append({row["ip"]: row["attempt_count"]})

    return response


def _top_usernames(cursor, hpid, type, response, arg=None):
    if type == "ip":

        cursor.execute(
            'Select username, count(username) as attempt_count from honeypot_endpoint_get where '
            '\'[%s, %s]\'::tstzrange @> timestamp and \'[%s, %s)\'::tstzrange @> create_time and honeypot_id = %s '
            'group by username order by attempt_count DESC limit 10',
            (arg[0], arg[1], arg[0], arg[1], hpid)
        )

        rows = cursor.fetchall()

        for row in rows:
            response["Top Usernames"].append({row["username"]: row["attempt_count"]})

    elif type == "hpid":

        cursor.execute(
            'Select username, count(username) as attempt_count from attacks_connections_attempts inner join honeypots'
            ' on attacks_connections_attempts.honeypot_id = honeypots.honeypot_id where '
            'attacks_connections_attempts.honeypot_id = %s group by username order by attempt_count DESC limit 10',
            (hpid,)
        )

        rows = cursor.fetchall()

        for row in rows:
            response["Top Usernames"].append({row["username"]: row["attempt_count"]})

    return response


def _top_passwords(cursor, hpid, type, response, arg=None):
    if type == "ip":

        cursor.execute(
            'Select password, count(password) as attempt_count from honeypot_endpoint_get where '
            '\'[%s, %s]\'::tstzrange @> timestamp and \'[%s, %s)\'::tstzrange @> create_time and honeypot_id = %s '
            'group by password order by attempt_count DESC limit 10',
            (arg[0], arg[1], arg[0], arg[1], hpid)
        )

        rows = cursor.fetchall()

        for row in rows:
            response["Top Passwords"].append({row["password"]: row["attempt_count"]})

    elif type == "hpid":

        cursor.execute(
            'Select password, count(password) as attempt_count from attacks_connections_attempts inner join honeypots'
            ' on attacks_connections_attempts.honeypot_id = honeypots.honeypot_id where '
            'attacks_connections_attempts.honeypot_id = %s group by password order by attempt_count DESC limit 10',
            (hpid,)
        )

        rows = cursor.fetchall()

        for row in rows:
            response["Top Passwords"].append({row["password"]: row["attempt_count"]})

    return response


def _top_geolocation(cursor, hpid, type, response, arg=None):
    if type == "ip":

        cursor.execute(
            'Select ip_and_geolocation.country, count(ip_and_geolocation.country) as attempt_count from '
            'honeypot_endpoint_get INNER JOIN ip_and_geolocation on honeypot_endpoint_get.ip = ip_and_geolocation.ip '
            'where \'[%s, %s]\'::tstzrange @> honeypot_endpoint_get.timestamp and \'[%s, %s)\'::tstzrange @> '
            'honeypot_endpoint_get.create_time and honeypot_id = %s group by ip_and_geolocation.country '
            'order by attempt_count DESC limit 10',
            (arg[0], arg[1], arg[0], arg[1], hpid)
        )

        rows = cursor.fetchall()

        for row in rows:
            response["Top Geolocation"].append({row["country"]: row["attempt_count"]})

    elif type == "hpid":

        cursor.execute(
            'Select ip_and_geolocation.country, count(ip_and_geolocation.country) as attempt_count from '
            'attacks_connections_attempts inner join honeypots on attacks_connections_attempts.honeypot_id = '
            'honeypots.honeypot_id INNER JOIN ip_and_geolocation on attacks_connections_attempts.ip = '
            'ip_and_geolocation.ip where attacks_connections_attempts.honeypot_id = %s group by '
            'ip_and_geolocation.country order by attempt_count DESC limit 10',
            (hpid,)
        )

        rows = cursor.fetchall()

        for row in rows:
            response["Top Geolocation"].append({row["country"]: row["attempt_count"]})

    return response
