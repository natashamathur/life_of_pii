import re
import nltk
import json



def check_age(possible_age):
    print(f'possible_age passed: {possible_age}')
    age_alone = possible_age.split(' ')[0]
    # print(f'age_alone calculated: {age_alone}, from possible_age passed: {possible_age}')
    if int(age_alone) < 111:
        return age_alone
    else:
        return False


def verify_cc_match(match):
    digits = re.sub("\D", "", match)
    if digits[:1] in ["3", "4", "5", "6", "8"]:
        if len(digits) >= 12 and len(digits) <= 19:
            stripped = [int(x) for x in digits]

            sum_odd = sum(stripped[-1::-2])
            sum_even = sum([sum(divmod(2 * digits, 10)) for digits in stripped[-2::-2]])

            if (sum_odd + sum_even) % 10 == 0:
                return digits
            return False
        return False
    return False


def check_mac_local(mac_address):

    first_two = mac_address[0:2]
    # combine binary representation of first and second characters in mac
    # address into one number,
    binary_form = ''.join(f"{int(char, 16):b}" for char in first_two)

    # check whether second to last number (second least significant digit) is 1
    if int(binary_form[-2]) == 1:
        return mac_address
    else:
        return False


def verify_phone(possible_us):
    with open('area_codes.json') as f:
        valid_us_codes = json.loads(f.read())

    if possible_us.replace('(', '').replace(')', '').replace('-', '').replace(' ', '')[-10:-7] in valid_us_codes.keys():
        return possible_us
    else:
        return False


def check_ip(possible_ip):
    nums = possible_ip.split('.')
    if all(num for num in nums) <= 255:
        return possible_ip
    else:
        return False


def verify_ssn(possible_ssn):
    if len(possible_ssn) > 0:
        t = possible_ssn[0][:3]
        if int(t) < 772:
            return possible_ssn
        else:
            return False

def extract_names(match):
    token_line = nltk.sent_tokenize(match)
    token_line = [nltk.word_tokenize(sent) for sent in token_line]
    token_line = [nltk.pos_tag(sent) for sent in token_line][0]

    return " ".join((new_string for new_string, tag in token_line if tag in ("NNP", "NN")))



def standardize_gender(possible_gender):
    possible = possible_gender.lower()
    if possible in ('girl', 'woman', 'female'):
        return "Female"
    elif possible in ('boy', 'man', 'male'):
        return "Male"


def dea_checksum(dea):
    v = dea[-7:-1]
    check1, check2 = 0, 0
    check1 = int(v[0])+ int(v[2]) + int(v[4])
    check2 = int(v[1]) + int(v[3]) + int(v[5])
    check = check1 + check2*2
    cd = str(check)[-1]
    if dea[-1] == cd:
        return dea
    else:
        return False



def australia_tax(n):
    total = 0
    for i in n:
        total = total + int(i)
    check = total % 11
    if check == 0:
        return n


def australia_medicare(n):
    checksum_weights = [1, 3, 7, 9, 1, 3, 7, 9]
    total = 0
    for i in range(8):
        total = int(n[i]) * checksum_weights[i]
    cs = total % 10
    if cs == n[8]:
        return n


def sweden_id(string):
    digits = re.sub("\D", "", (string)[:-1])
    checksum = int(string[-1:])
    if digits[:1] in ["3", "4", "5", "6", "8"]:
        stripped = [int(x) for x in digits]
        sum_odd = sum(stripped[-1::-2])
        sum_even = sum([sum(divmod(2 * digits, 10)) for digits in stripped[-2::-2]])
        if (sum_odd + sum_even) % 10 == checksum:
            return string


def south_korea_id(string):
    string = re.sub('[-]', '', string)
    checksum = string[-1:]
    mults = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5]
    total = 0
    for x in range(0, 12):
        total += int(string[x]) * mults[x]

    remainder = (11 - total % 11) % 10
    if remainder == int(checksum):
        return string[0:6] + "-" + string[7:13]


def south_africa_id(string):
    digits = re.sub("\D", "", string)
    if digits[:1] in ["3", "4", "5", "6", "8"]:
        if len(digits) >= 12 and len(digits) <= 19:
            stripped = [int(x) for x in digits]

            sum_odd = sum(stripped[-1::-2])
            sum_even = sum([sum(divmod(2 * digits, 10)) for digits in stripped[-2::-2]])

            if (sum_odd + sum_even) % 10 == 0:
                return digits
            else:
                return False
        else:
            return False
    else:
        return False


def verify_chinaid(match):
    match = match.string
    try:
        checksum = (1-2*int(match[:-1], 13)) % 11
    except ValueError:
        return False
    if checksum == 10:
        if match[-1:] == 'X':
            return match
        else:
            return False
    else:
        try:
            if int(match[-1:]) == checksum:
                return match
        except ValueError:
            return False


def hong_kong_id(string):
    string = re.sub('[()]', '', string)
    checksum = string [-1:]
    string = string [:-1]
    mults = [9, 8, 7, 6, 5, 4, 3, 2]
    total = 0
    length = len(string)
    if length:
        for x in range(0, 2):
            total += ((ord(string[x]) - 55) * mults[x])
        for y in range(2, 8):
            total += (int(string[y]) * mults[y])
    elif length:
        total += 36*9
        total += (ord(string[0]) - 55) * mults[1]
        for y in range(1, 7):
            total += int(string[y]) * mults[y + 1]
    remainder = total % 11
    if remainder != 0:
        if remainder == 1:
            remainder = "A"
        else:
            remainder = 11 - remainder
    if remainder == int(checksum):
        return string + "(" + checksum + ")"
    else:
        return False


