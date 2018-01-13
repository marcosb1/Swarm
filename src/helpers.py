import socket
import copy

from src.json_templates import response_get_honeypot, response_get_honeypots

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
    return None
