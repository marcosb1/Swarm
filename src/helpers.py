import socket
import copy
import psycopg2.extras
from flask import g
import pprint
import json
import arrow

from src.json_templates import response_get_honeypot, response_get_honeypots, geolocation
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


def _validate_honeypot_input(body):
    count = 1
    if len(body["Requests"]) == 0:
        return json.loads('{"ERROR": "Nothing Requested"}')
    else:
        for request in body["Requests"]:
            try:
                _validate_keys_input(request, count)
                _validate_request_input(request, count)
                _validate_services_input(request, count)
                _validate_attempts_input(request, count)
                _validate_ips_input(request, count)
                _validate_usernames_input(request, count)
                _validate_passwords_input(request, count)
                _validate_ips_history_input(request, count)
                _validate_uptime_input(request, count)
            except ValueError:
                raise

            count = count + 1
        return body


def _key_check(_dict, _list, loc, count):
    temp_list = list(_dict)

    for key in temp_list:
        if key not in _list:
            raise ValueError(json.loads('{"ERROR": "Unsupported key value, ' + str(key) + ', in ' + str(loc) + ' for '
                                        'request ' + str(count) + '"}'))


def _validate_keys_input(request, count):
    key_list = ["Request", "Services", "Attempts", "IPs", "Usernames", "Passwords", "IP History", "Uptime"]

    try:
        _key_check(request, key_list, "Requests", count)
    except ValueError:
        raise


def _validate_request_input(request, count):
    """
    Validates Request is a String and check if its a default call
    :param request: JSON dict
    :param count: Number of request
    :return: Return ERROR or modified request
    """
    if isinstance(request["Request"], str) is not True:
        raise ValueError(json.loads('{"ERROR": "Request field for request ' + str(count) + ' is not a string"}'))
    elif ("Services" in request) is False and ("Attempts" in request) is False and ("IPs" in request) is False and (
        "Usernames" in request) is False and ("Passwords" in request) is False and (
        "IP History" in request) is False and ("Uptime" in request) is False:
        if "Default" in request:
            raise ValueError(json.loads(
                '{"ERROR": "Default can not be set for any request! Error occurred for request ' + str(count) + '"}'))
        else:
            request["Default"] = True


def _validate_services_input(request, count):
    if "Services" in request:
        if isinstance(request["Services"], bool) is not True:
            if isinstance(request["Services"], dict) is True:
                _key_check(request["Services"], ["Start Timestamp", "End Timestamp"], "Services", count)

                if ("Start Timestamp" in request["Services"]) and ("End Timestamp" in request["Services"]):
                    # Check if valid timestamps
                    try:
                        request["Services"]["Start Timestamp"] = arrow.get(request["Services"]["Start Timestamp"],
                                                                           'YYYY-MM-DD HH:mm:ss.SZZ').to('utc').datetime
                    except:
                        raise ValueError(json.loads(
                            '{"ERROR": "Invalid Start timestamp in Services for request ' + str(count) + '"}'))

                    try:
                        request["Services"]["End Timestamp"] = arrow.get(request["Services"]["End Timestamp"],
                                                                         'YYYY-MM-DD HH:mm:ss.SZZ').to('utc').datetime
                    except:
                        raise ValueError(json.loads(
                            '{"ERROR": "Invalid End timestamp in Services for request ' + str(count) + '"}'))
                elif ("Start Timestamp" in request["Services"]) or ("End Timestamp" in request["Services"]):
                    raise ValueError(json.loads(
                        '{"ERROR": "Both Start and End Timestamp must be set in Services for request ' + str(
                            count) + '"}'))
                else:
                    request["Services"]["Start Timestamp"] = False
                    request["Services"]["End Timestamp"] = False
            else:
                raise ValueError(json.loads('{"ERROR": "Invalid input in Services for request ' + str(count) + '"}'))
    else:
        request["Services"] = False


def _validate_attempts_input(request, count):
    if "Attempts" in request:
        data_flag = False
        step_flag = False
        if isinstance(request["Attempts"], bool) is not True:
            if isinstance(request["Attempts"], dict) is True:
                _key_check(request["Attempts"], ["Start Timestamp", "End Timestamp", "Step", "Step Scale"], "Attempts", count)

                if ("Start Timestamp" in request["Attempts"]) and ("End Timestamp" in request["Attempts"]):
                    data_flag = True
                    try:
                        request["Attempts"]["Start Timestamp"] = arrow.get(request["Attempts"]["Start Timestamp"],
                                                                           'YYYY-MM-DD HH:mm:ss.SZZ').to('utc').datetime
                    except:
                        raise ValueError(json.loads(
                            '{"ERROR": "Invalid Start timestamp in Attempts for request ' + str(count) + '"}'))

                    try:
                        request["Attempts"]["End Timestamp"] = arrow.get(request["Attempts"]["End Timestamp"],
                                                                         'YYYY-MM-DD HH:mm:ss.SZZ').to('utc').datetime
                    except:
                        raise ValueError(json.loads(
                            '{"ERROR": "Invalid End timestamp in Attempts for request ' + str(count) + '"}'))
                elif ("Start Timestamp" in request["Attempts"]) or ("End Timestamp" in request["Attempts"]):
                    raise ValueError(json.loads(
                        '{"ERROR": "Both Start and End Timestamp must be set in Attempts for request ' + str(
                            count) + '"}'))
                else:
                    request["Attempts"]["Start Timestamp"] = False
                    request["Attempts"]["End Timestamp"] = False

                if "Step Scale" in request["Attempts"]:
                    data_flag = True
                    if isinstance(request["Attempts"]["Step Scale"], str) is True:
                        request["Attempts"]["Step Scale"] = request["Attempts"]["Step Scale"].lower()
                        if request["Attempts"]["Step Scale"] != "year" and request["Attempts"][
                            "Step Scale"] != "month" and request["Attempts"]["Step Scale"] != "week" and \
                                        request["Attempts"]["Step Scale"] != "day" and request["Attempts"][
                            "Step Scale"] != "hour" and request["Attempts"]["Step Scale"] != "minute":
                            raise ValueError(json.loads(
                                '{"ERROR": "Attempts Step Scale is invalid for request ' + str(count) + '"}'))
                    else:
                        raise ValueError(json.loads(
                            '{"ERROR": "Attempts Step Scale is not a String for request ' + str(count) + '"}'))
                    step_flag = True
                else:
                    request["Attempts"]["Step Scale"] = False

                if "Step" in request["Attempts"]:
                    data_flag = True
                    if (isinstance(request["Attempts"]["Step"], int) is True) and (
                        isinstance(request["Attempts"]["Step"], bool) is False):
                        if step_flag is False:
                            raise ValueError(json.loads(
                                '{"ERROR": "Attempts Step can not be set without valid Step Scale for request ' + str(
                                    count) + '"}'))
                    else:
                        raise ValueError(json.loads('{"ERROR": "Attempts Step is not a number for request ' + str(count) + '"}'))
                else:
                    request["Attempts"]["Step"] = False

                if data_flag is False:
                    raise ValueError(json.loads('{"ERROR": "Invalid input in Attempts for request ' + str(count) + '"}'))
            else:
                raise ValueError(json.loads('{"ERROR": "Invalid input in Attempts for request ' + str(count) + '"}'))
    else:
        request["Attempts"] = False


def _validate_ips_input(request, count):
    if "IPs" in request:
        data_flag = False
        if isinstance(request["IPs"], bool) is not True:
            if isinstance(request["IPs"], dict) is True:
                _key_check(request["IPs"], ["Count", "Geolocation", "Order"], "IPs", count)

                if "Count" in request["IPs"]:
                    data_flag = True
                    if (isinstance(request["IPs"]["Count"], int) is not True) or (
                        isinstance(request["IPs"]["Count"], bool) is True):
                        raise ValueError(json.loads('{"ERROR": "IPs Count is not a number for request ' + str(count) + '"}'))
                else:
                    request["IPs"]["Count"] = False

                if "Geolocation" in request["IPs"]:
                    if isinstance(request["IPs"]["Geolocation"], bool) is not True:
                        if isinstance(request["IPs"]["Geolocation"], dict) is True:
                            _key_check(request["IPs"]["Geolocation"], ["LatLong", "Country", "Country Code", "City"], "IPs Geolocation", count)

                            flag = False
                            # Need to make sure they did not just pass in a random number or something
                            if "LatLong" in request["IPs"]["Geolocation"]:
                                flag = True
                                if isinstance(request["IPs"]["Geolocation"]["LatLong"], bool) is not True:
                                    raise ValueError(json.loads(
                                        '{"ERROR": "IPs LatLong is not a boolean for request ' + str(count) + '"}'))
                            else:
                                request["IPs"]["Geolocation"]["LatLong"] = False

                            if "Country" in request["IPs"]["Geolocation"]:
                                flag = True
                                if isinstance(request["IPs"]["Geolocation"]["Country"], bool) is not True:
                                    raise ValueError(json.loads(
                                        '{"ERROR": "IPs Country is not a boolean for request ' + str(count) + '"}'))
                            else:
                                request["IPs"]["Geolocation"]["Country"] = False

                            if "Country Code" in request["IPs"]["Geolocation"]:
                                flag = True
                                if isinstance(request["IPs"]["Geolocation"]["Country Code"], bool) is not True:
                                    raise ValueError(json.loads(
                                        '{"ERROR": "IPs Country Code is not a boolean for request ' + str(count) + '"}'))
                            else:
                                request["IPs"]["Geolocation"]["Country Code"] = False

                            if "City" in request["IPs"]["Geolocation"]:
                                flag = True
                                if isinstance(request["IPs"]["Geolocation"]["City"], bool) is not True:
                                    raise ValueError(json.loads(
                                        '{"ERROR": "IPs City is not a boolean for request ' + str(count) + '"}'))
                            else:
                                request["IPs"]["Geolocation"]["City"] = False
                            if flag is False:
                                raise ValueError(json.loads(
                                    '{"ERROR": "Invalid input for Geolocation in IPs for request ' + str(count) + '"}'))
                        else:
                            raise ValueError(json.loads(
                                '{"ERROR": "Invalid input for Geolocation in IPs for request ' + str(count) + '"}'))
                else:
                    request["IPs"]["Geolocation"] = False

                if "Order" in request["IPs"]:
                    data_flag = True
                    if request["IPs"]["Order"].lower() != "asc" and request["IPs"]["Order"].lower() != "desc":
                        raise ValueError(json.loads('{"ERROR": "IPs Order is not ASC or DESC for request ' + str(count) + '"}'))
                else:
                    request["IPs"]["Order"] = False

                if data_flag is False:
                    raise ValueError(json.loads('{"ERROR": "Invalid input in IPs for request ' + str(count) + '"}'))
            else:
                raise ValueError(json.loads('{"ERROR": "Invalid input in IPs for request ' + str(count) + '"}'))
    else:
        request["IPs"] = False


def _validate_usernames_input(request, count):
    if "Usernames" in request:
        if isinstance(request["Usernames"], bool) is not True:
            if isinstance(request["Usernames"], dict) is True:
                _key_check(request["Usernames"], ["Count", "Order"], "Usernames", count)

                data_flag = False
                if "Count" in request["Usernames"]:
                    data_flag = True
                    if (isinstance(request["Usernames"]["Count"], int) is not True) or (
                        isinstance(request["Usernames"]["Count"], bool) is True):
                        raise ValueError(json.loads('{"ERROR": "Usernames Count is not a number for request ' + str(count) + '"}'))
                else:
                    request["Usernames"]["Count"] = False

                if "Order" in request["Usernames"]:
                    data_flag = True
                    if isinstance(request["Usernames"]["Order"], str) is True:
                        if request["Usernames"]["Order"].lower() != "asc" and request["Usernames"][
                            "Order"].lower() != "desc":
                            raise ValueError(json.loads(
                                '{"ERROR": "Usernames Order is not set to ASC or DESC for request ' + str(count) + '"}'))
                    else:
                        return json.loads(
                            '{"ERROR": "Usernames Order is not set to ASC or DESC for request ' + str(count) + '"}')
                else:
                    request["Usernames"]["Order"] = False

                if data_flag is False:
                    raise ValueError(json.loads('{"ERROR": "Invalid input in Usernames for request ' + str(count) + '"}'))
            else:
                raise ValueError(json.loads('{"ERROR": "Invalid input in Usernames for request ' + str(count) + '"}'))
    else:
        request["Usernames"] = False


def _validate_passwords_input(request, count):
    if "Passwords" in request:
        if isinstance(request["Passwords"], bool) is not True:
            if isinstance(request["Passwords"], dict) is True:
                _key_check(request["Passwords"], ["Count", "Order"], "Passwords", count)

                data_flag = False
                if "Count" in request["Passwords"]:
                    data_flag = True
                    if (isinstance(request["Passwords"]["Count"], int) is not True) or (
                        isinstance(request["Passwords"]["Count"], bool) is True):
                        raise ValueError(json.loads('{"ERROR": "Passwords Count is not a number for request ' + str(count) + '"}'))
                else:
                    request["Passwords"]["Count"] = False

                if "Order" in request["Passwords"]:
                    data_flag = True
                    if isinstance(request["Passwords"]["Order"], str) is True:
                        if request["Passwords"]["Order"].lower() != "asc" and request["Passwords"][
                            "Order"].lower() != "desc":
                            raise ValueError(json.loads(
                                '{"ERROR": "Passwords Order is not set to ASC or DESC for request ' + str(count) + '"}'))
                    else:
                        raise ValueError(json.loads(
                            '{"ERROR": "Passwords Order is not set to ASC or DESC for request ' + str(count) + '"}'))
                else:
                    request["Passwords"]["Order"] = False

                if data_flag is False:
                    raise ValueError(json.loads('{"ERROR": "Invalid input in Passwords for request ' + str(count) + '"}'))
            else:
                raise ValueError(json.loads('{"ERROR": "Invalid input in Passwords for request ' + str(count) + '"}'))
    else:
        request["Passwords"] = False


def _validate_ips_history_input(request, count):
    if "IP History" in request:
        if isinstance(request["IP History"], bool) is not True:
            if isinstance(request["IP History"], dict) is True:
                _key_check(request["IP History"], ["Geolocation", "Date Range", "Attempts"], "IP History", count)

                data_flag = False
                if "Geolocation" in request["IP History"]:
                    data_flag = True
                    if isinstance(request["IP History"]["Geolocation"], bool) is not True:
                        if isinstance(request["IP History"]["Geolocation"], dict) is True:
                            _key_check(request["IP History"]["Geolocation"], ["LatLong", "Country", "Country Code", "City"], "IP History Geolocation", count)

                            flag = False
                            # Need to make sure they did not just pass in a random number or something
                            if "LatLong" in request["IP History"]["Geolocation"]:
                                flag = True
                                if isinstance(request["IP History"]["Geolocation"]["LatLong"], bool) is not True:
                                    raise ValueError(json.loads(
                                        '{"ERROR": "IP History LatLong is not a boolean for request ' + str(
                                            count) + '"}'))
                            else:
                                request["IP History"]["Geolocation"]["LatLong"] = False

                            if "Country" in request["IP History"]["Geolocation"]:
                                flag = True
                                if isinstance(request["IP History"]["Geolocation"]["Country"], bool) is not True:
                                    raise ValueError(json.loads(
                                        '{"ERROR": "IP History Country is not a boolean for request ' + str(
                                            count) + '"}'))
                            else:
                                request["IP History"]["Geolocation"]["Country"] = False

                            if "Country Code" in request["IP History"]["Geolocation"]:
                                flag = True
                                if isinstance(request["IP History"]["Geolocation"]["Country Code"], bool) is not True:
                                    raise ValueError(json.loads(
                                        '{"ERROR": "IP History Country Code is not a boolean for request ' + str(
                                            count) + '"}'))
                            else:
                                request["IP History"]["Geolocation"]["Country Code"] = False

                            if "City" in request["IP History"]["Geolocation"]:
                                flag = True
                                if isinstance(request["IP History"]["Geolocation"]["City"], bool) is not True:
                                    raise ValueError(json.loads(
                                        '{"ERROR": "IP History City is not a boolean for request ' + str(count) + '"}'))
                            else:
                                request["IP History"]["Geolocation"]["City"] = False

                            if flag is False:
                                raise ValueError(json.loads(
                                    '{"ERROR": "Invalid input for Geolocation in IP History for request ' + str(
                                        count) + '"}'))
                        else:
                            raise ValueError(json.loads(
                                '{"ERROR": "Invalid input for Geolocation in IP History for request ' + str(
                                    count) + '"}'))
                else:
                    request["IP History"]["Geolocation"] = False

                if "Date Range" in request["IP History"]:
                    data_flag = True
                    if isinstance(request["IP History"]["Date Range"], bool) is not True:
                        raise ValueError(json.loads(
                            '{"ERROR": "IP History Date Range is not a boolean for request ' + str(count) + '"}'))
                else:
                    request["IP History"]["Date Range"] = False

                if "Attempts" in request["IP History"]:
                    data_flag = True
                    if isinstance(request["IP History"]["Attempts"], bool) is not True:
                        raise ValueError(json.loads(
                            '{"ERROR": "IP History Attempts is not a boolean for request ' + str(count) + '"}'))
                else:
                    request["IP History"]["Attempts"] = False

                if data_flag is False:
                    raise ValueError(json.loads('{"ERROR": "Invalid input in IP History for request ' + str(count) + '"}'))
            else:
                raise ValueError(json.loads('{"ERROR": "Invalid input in IP History for request ' + str(count) + '"}'))
    else:
        request["IP History"] = False


def _validate_uptime_input(request, count):
    if "Uptime" in request:
        if isinstance(request["Uptime"], bool) is not True:
            if isinstance(request["Uptime"], dict) is True:
                _key_check(request["Uptime"], ["Format"], "Uptime", count)

                if "Format" in request["Uptime"]:
                    if isinstance(request["Uptime"]["Format"], str) is True:
                        request["Uptime"]["Format"] = request["Uptime"]["Format"].lower()
                        if request["Uptime"]["Format"] != "epoch" and request["Uptime"]["Format"] != "date range" and \
                                        request["Uptime"]["Format"] != "time since":
                            raise ValueError(json.loads(
                                '{"ERROR": "Uptime Format is not a valid format for request ' + str(count) + '"}'))
                    else:
                        raise ValueError(json.loads('{"ERROR": "Invalid input in Uptime for request ' + str(count) + '"}'))
                else:
                    # return False, json.loads('{"ERROR": "Invalid input in Uptime for request ' + str(count) + '"}')
                    request["Uptime"]["Format"] = False
            else:
                raise ValueError(json.loads('{"ERROR": "Invalid input in Uptime for request ' + str(count) + '"}'))
    else:
        request["Uptime"] = False


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
        print(times)
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
            temp = copy.deepcopy(geolocation)
            temp["name"] = row["country"]
            temp["value"] = row["attempt_count"]
            temp["code"] = row["country_code"]

            response["Top Geolocation"].append(temp)

    elif type == "hpid":

        rows = db.query_fetch('Select ip_and_geolocation.country, Country_Abbreviation.country_code, count(ip_and_geolocation.country) as attempt_count '
                              'from attacks_connections_attempts inner join honeypots on '
                              'attacks_connections_attempts.honeypot_id = honeypots.honeypot_id INNER JOIN '
                              'ip_and_geolocation on attacks_connections_attempts.ip = ip_and_geolocation.ip '
                              'INNER JOIN Country_Abbreviation on Country_Abbreviation.country = ip_and_geolocation.country '
                              'where attacks_connections_attempts.honeypot_id = %s group by ip_and_geolocation.country, Country_Abbreviation.country_code '
                              'order by attempt_count DESC', (hpid,), "all")

        for row in rows:
            temp = copy.deepcopy(geolocation)
            temp["name"] = row["country"]
            temp["value"] = row["attempt_count"]
            temp["code"] = row["country_code"]

            response["Top Geolocation"].append(temp)

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
