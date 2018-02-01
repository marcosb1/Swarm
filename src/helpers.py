import socket
import copy
import psycopg2.extras
from flask import g
import pprint
import json
import arrow

from src.json_templates import response_get_honeypot, response_get_honeypots
from src.database import Database

db = Database("postgres", "postgres", "Password1", "10.11.12.80", "Beekeeper")
db.create_db_connection()


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


def _process_honeypot_put(body, hpid):
    if "IP" in body:
        if is_valid_ipv4_address(body["IP"]) is False:
            return json.loads('{"ERROR": "IP ' + body["IP"] + ' is not valid"}')
        else:
            return _build_honeypot_put_response(body, hpid)


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

    rows = db.query_fetch('Select honeypot_id from honeypots order by honeypot_id ASC limit %s', (num,), "all")

    for row in rows:
        honeypots.append(row["honeypot_id"])

    return honeypots


def _build_honeypot_get_response(arg=None, type=None):

    hpid = ""
    times = None
    # cursorTemp = db.cursor(cursor_factory=psycopg2.extras.NamedTupleCursor)
    response = copy.deepcopy(response_get_honeypot)

    if type == "ip":
        # Row holds the HPID
        row = db.query_fetch(
            'Select honeypot_id from honeypot_IPS where ip = %s order by create_time AT TIME ZONE \'UTC\' DESC limit 1',
            (arg, ), "one"
        )

        if row:
            hpid = row["honeypot_id"]
        else:
            return json.loads('{"ERROR": "No honeypot found for IP: ' + arg + '"}')

    elif type == "hpid":
        # Row holds the HPID
        row = db.query_fetch('Select honeypot_id from honeypots where honeypot_id = %s limit 1', (arg, ), "one")

        if row:
            hpid = row["honeypot_id"]
        else:
            return json.loads('{"ERROR": "No honeypot found for HPID: ' + arg + '"}')

    # HPID
    response["HPID"] = hpid

    # IP History
    response = _format_ip_history(response, hpid)

    # Services
    response = _format_services(response, hpid)

    # Number of Attempts, Top IPS, TOP Username, TOP Passwords, Top Geolocation
    if type == "ip":
        times = _honeypot_bounds(arg, hpid)
        response = _number_of_attempts(hpid, type, response, times)
        response = _top_ips(hpid, type, response, times)
        response = _top_usernames(hpid, type, response, times)
        response = _top_passwords(hpid, type, response, times)
        response = _top_geolocation(hpid, type, response, times)
    elif type == "hpid":
        response = _number_of_attempts(hpid, type, response)
        response = _top_ips(hpid, type, response)
        response = _top_usernames(hpid, type, response)
        response = _top_passwords(hpid, type, response)
        response = _top_geolocation(hpid, type, response)

    return response


def _format_ip_history(response, hpid):
    rows = db.query_fetch('Select ip, create_time AT TIME ZONE \'UTC\' from Honeypot_IPS where honeypot_id = %s '
                          'order by create_time AT TIME ZONE \'UTC\' DESC', (hpid, ), "all")

    for row in rows:
        response["IP History"].append(row["ip"])

    return response


def _format_services(response, hpid):
    rows = db.query_fetch('Select service, port from honeypot_services where honeypot_id = %s', (hpid, ), "all")

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


def _honeypot_bounds(ip, hpid):
    create_time = None
    end_time = None

    rows = db.query_fetch('Select ip, create_time from Honeypot_IPS where honeypot_id = %s order by create_time ASC ',
                          (hpid,), "all")

    for row in rows:
        if ip == row["ip"]:
            create_time = row["create_time"]
        elif create_time is not None:
            end_time = row["create_time"]
            break

    return (create_time, end_time)


def _number_of_attempts(hpid, type, response, arg=None):
    if type == "ip":

        row = db.query_fetch('Select honeypot_ip, count(attempt_id) as attempt_count from honeypot_endpoint_get '
                             'where \'[%s, %s]\'::tstzrange @> timestamp and \'[%s, %s)\'::tstzrange @> create_time '
                             'and honeypot_id = %s group by honeypot_ip',
                             (arg[0], arg[1], arg[0], arg[1], hpid, ), "one")

        if row:
            response["Number of Attempts"] = row["attempt_count"]

    elif type == "hpid":
        row = db.query_fetch('Select honeypot_ip, count(attempt_id) as attempt_count from honeypot_endpoint_get '
                             'where honeypot_id = %s group by honeypot_ip', (hpid,), "one")

        if row:
            response["Number of Attempts"] = row["attempt_count"]

    return response


def _top_ips(hpid, type, response, arg=None):
    if type == "ip":

        rows = db.query_fetch('Select ip, count(attempt_id) as attempt_count from honeypot_endpoint_get where '
                              '\'[%s, %s]\'::tstzrange @> timestamp and \'[%s, %s)\'::tstzrange @> create_time and '
                              'honeypot_id = %s group by ip order by attempt_count DESC limit 10',
                              (arg[0], arg[1], arg[0], arg[1], hpid), "all")

        for row in rows:
            response["Top IPs"].append({row["ip"]: row["attempt_count"]})

    elif type == "hpid":

        rows = db.query_fetch('Select ip, count(attempt_id) as attempt_count from attacks_connections_attempts inner join '
                              'honeypots on attacks_connections_attempts.honeypot_id = honeypots.honeypot_id where '
                              'attacks_connections_attempts.honeypot_id = %s group by ip order by attempt_count '
                              'DESC limit 10', (hpid,), "all")

        for row in rows:
            response["Top IPs"].append({row["ip"]: row["attempt_count"]})

    return response


def _top_usernames(hpid, type, response, arg=None):
    if type == "ip":

        rows = db.query_fetch('Select username, count(username) as attempt_count from honeypot_endpoint_get where '
                              '\'[%s, %s]\'::tstzrange @> timestamp and \'[%s, %s)\'::tstzrange @> create_time and '
                              'honeypot_id = %s group by username order by attempt_count DESC limit 10',
                              (arg[0], arg[1], arg[0], arg[1], hpid), "all")

        for row in rows:
            response["Top Usernames"].append({row["username"]: row["attempt_count"]})

    elif type == "hpid":

        rows = db.query_fetch('Select username, count(username) as attempt_count from attacks_connections_attempts '
                              'inner join honeypots on attacks_connections_attempts.honeypot_id = honeypots.honeypot_id '
                              'where attacks_connections_attempts.honeypot_id = %s group by username order by '
                              'attempt_count DESC limit 10', (hpid,), "all")

        for row in rows:
            response["Top Usernames"].append({row["username"]: row["attempt_count"]})

    return response


def _top_passwords(hpid, type, response, arg=None):
    if type == "ip":

        rows = db.query_fetch('Select password, count(password) as attempt_count from honeypot_endpoint_get where '
                              '\'[%s, %s]\'::tstzrange @> timestamp and \'[%s, %s)\'::tstzrange @> create_time and '
                              'honeypot_id = %s group by password order by attempt_count DESC limit 10',
                              (arg[0], arg[1], arg[0], arg[1], hpid), "all")

        for row in rows:
            response["Top Passwords"].append({row["password"]: row["attempt_count"]})

    elif type == "hpid":

        rows = db.query_fetch('Select password, count(password) as attempt_count from attacks_connections_attempts '
                              'inner join honeypots on attacks_connections_attempts.honeypot_id = honeypots.honeypot_id '
                              'where attacks_connections_attempts.honeypot_id = %s group by password order by '
                              'attempt_count DESC limit 10', (hpid,), "all")

        for row in rows:
            response["Top Passwords"].append({row["password"]: row["attempt_count"]})

    return response


def _top_geolocation(hpid, type, response, arg=None):
    if type == "ip":

        rows = db.query_fetch('Select ip_and_geolocation.country, count(ip_and_geolocation.country) as attempt_count '
                              'from honeypot_endpoint_get INNER JOIN ip_and_geolocation on honeypot_endpoint_get.ip = '
                              'ip_and_geolocation.ip where \'[%s, %s]\'::tstzrange @> honeypot_endpoint_get.timestamp '
                              'and \'[%s, %s)\'::tstzrange @> honeypot_endpoint_get.create_time and honeypot_id = %s '
                              'group by ip_and_geolocation.country order by attempt_count DESC limit 10',
                              (arg[0], arg[1], arg[0], arg[1], hpid), "all")

        for row in rows:
            response["Top Geolocation"].append({row["country"]: row["attempt_count"]})

    elif type == "hpid":

        rows = db.query_fetch('Select ip_and_geolocation.country, count(ip_and_geolocation.country) as attempt_count '
                              'from attacks_connections_attempts inner join honeypots on '
                              'attacks_connections_attempts.honeypot_id = honeypots.honeypot_id INNER JOIN '
                              'ip_and_geolocation on attacks_connections_attempts.ip = ip_and_geolocation.ip where '
                              'attacks_connections_attempts.honeypot_id = %s group by ip_and_geolocation.country '
                              'order by attempt_count DESC limit 10', (hpid,), "all")

        for row in rows:
            response["Top Geolocation"].append({row["country"]: row["attempt_count"]})

    return response


def _validate_hpid_input(arg):

    row = db.query_fetch('Select honeypot_id from honeypots where honeypot_id = %s', (arg,), "one")

    if row:
        return True
    else:
        return False


def _build_honeypot_put_response(body, hpid):

    if "OS" in body:
        db.query_commit('UPDATE Honeypots SET os = %s where honeypot_id = %s', (body["OS"], hpid))

    if "IP" in body:
        row = db.query_fetch('Select ip, create_time from Honeypot_IPS where honeypot_id = %s order by create_time DESC',
                             (hpid, ), "one")

        create_time = arrow.utcnow()
        if "Timestamp" in body:
            create_time = arrow.get(body["Timestamp"])

        row_time = arrow.get(row["create_time"])

        if row["ip"] != body["IP"] and create_time > row_time:
            db.query_commit('INSERT INTO Honeypot_IPS(honeypot_id, ip, create_time) VALUES (%s, %s, %s)',
                            (hpid, body["IP"], create_time.datetime))

    if "Services" in body:
        db.query_commit('DELETE FROM Honeypot_Services where honeypot_id = %s', (hpid, ))

        for service in body["Services"]:
            for key, value in service.items():
                for port in value:
                    db.query_commit("INSERT INTO Honeypot_Services(honeypot_id, service, port) VALUES (%s, %s, %s)",
                                    (hpid, key, port))

    return json.loads('{"Status": "Successful!"}')
