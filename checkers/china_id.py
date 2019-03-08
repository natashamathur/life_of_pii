import re

def verify_chinaid(string):
    match = re.search("([0-9]{6})([[1][9]|[2][0]])([0-9]{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])([0-9]{3})([0-9X])", string)
    match = match.string
    try:
        checksum = (1-2*int(match[:-1], 13)) % 11
    except ValueError:
        return None
    if checksum == 10:
        if match[-1:] == 'X':
            return match
    else:
        try:
            if int(match[-1:]) == checksum:
                return match
        except ValueError:
            return None
