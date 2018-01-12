import socket


def is_valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False

    return True


def _validate_honeypot_input(args):

    if len(args) == 0:
        return True
    else:
        for key, value in args.items():
            if key[:2].lower() == 'ip' and is_valid_ipv4_address(value) is not True:
                return False
            elif key[:4].lower() == 'hpid' and isinstance(value, str) is not True:
                return False
    return True
