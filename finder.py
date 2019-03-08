import re
import os
import sys
import json
import nltk
from collections import defaultdict



def read_ascii(ascii_file, f=None):
    if ascii_file == '':
        sys.exit(f"pii_recognition error: No text detected for PII recognition in '{ascii_file}'. Please review parameters.")
    try:
        # test whether ascii_file is a valid file
        if not f:
            with open(ascii_file, 'r') as f:
                text_as_str = f.read().split('\n')
        else:
            text_as_str = f.read().split('\n')

    except FileNotFoundError:
        # if not a valid file, parse as a text string
        ascii_str = ascii_file
        text_as_str = ascii_str.split('\n')
    except Exception as e:
        sys.exit(f"pii_recognition error: An error occurred in accessing text: {e}")

    text_by_row = {row: (val, len(val)) for row, val in enumerate(text_as_str)}
    return text_by_row



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


def extract_names(match):
    # name = ""
    token_line = nltk.sent_tokenize(match)
    token_line = [nltk.word_tokenize(sent) for sent in token_line]
    token_line = [nltk.pos_tag(sent) for sent in token_line][0]

    return " ".join((new_string for new_string, tag in token_line if tag in ("NNP", "NN")))
    # for (new_string, tag) in token_line:
    #     if tag in ["NNP", "NN"]:
    #             name += new_string
    #             name += " "
    # return name[:-1]


def check_age(possible_age):
    print(f'possible_age passed: {possible_age}')
    age_alone = possible_age.split(' ')[0]
    # print(f'age_alone calculated: {age_alone}, from possible_age passed: {possible_age}')
    if int(age_alone) < 111:
        return age_alone
    else:
        return False


def standardize_gender(possible_gender):
    possible = possible_gender.lower()
    if possible in ('girl', 'woman', 'female'):
        return "Female"
    elif possible in ('boy', 'man', 'male'):
        return "Male"



def checked(match):
    return match



def verify_phone(possible_us):
    with open('area_codes.json') as f:
        valid_us_codes = json.loads(f.read())

    if possible_us.replace('(', '').replace(')', '').replace('-', '')[0:3] in valid_us_codes.keys():
        return possible_us
    else:
        return False


def check_ip(possible_ip):
    nums = possible_ip.split('.')
    if all(num for num in nums) <= 255:
        return possible_ip
    else:
        return False


PII_CORPUS = {
    # 'AGE': (r"\b([1-9]?\d{1,2})\b|\b([0]?[1-9]{1,2})\b|\b(\d{1,3} (years|ans|y.o.|años|anni|Jahre))\b|(?=\b(Age|Alter)[:\s\,\-]{1,2})(\d{1,3})\b", check_age),
    'IP_ADDRESS': (r"\b([0-9]{3}.[0-9]{3}.[0-9]{3}.[0-9]{3})\b", check_ip),
    'GENDER': (r"\b(male)\b|\b(female)\b|\b(man)\b|\b(woman)\b|\b(girl)\b|\b(boy)\b", standardize_gender),
    'CREDIT_CARD_NUMBER': (r"^[0-9]{1,5}[-|,|_]?[0-9]{1,5}[-|,]?[0-9]{1,5}[-|,]?[0-9]{1,5}[-|,]", verify_cc_match),
    'EMAIL_ADDRESS': (r"([a-zA-Z0-9\_\'][\.'\\a-zA-Z0-9_]*[\'\_a-zA-Z0-9]@[a-zA-Z0-9]+\.(com|edu|gov|org|net|ca))", checked),
    # 'FDA_CODE': (r"^[0-9]{0,2}$", checked),
    'PHONE_NUMBER_INT': (r"\b\+?((\d{2}[-\.\s]??){1,3}\d{3}[-\.\s]??\d{5})\b|(?<![-\+])([\(]??\d{3}\)?[-\.\s/]{0,3}\d{3}[-\.\s]??\d{5})\b", checked),
    'PHONE_NUMBER_US': (r"(?<![-])\b([\+]??\d{0,2}[-\.\s/]??([\(]??\d{3}\)??[-\.\s/]??){0,3}\d{3}[-\.\s]??\d{4})\b", verify_phone),
    'CHINA ID': (r"([0-9]{6})([[1][9]|[2][0]])([0-9]{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])([0-9]{3})([0-9X])", verify_chinaid),
    'NAME': (r"([A-Z][a-z]*(\-[A-Z][a-z]*)?\.?)\s([A-Z][a-z]*(\-[A-Z][a-z]*)?\.?)(\s?[A-Z][a-z]*(\-[A-Z][a-z]*)?\.?)?", extract_names),
    'NORWAY_ID': ()
    }


def pii_finder(ascii_file, output_file=None):
    # return ascii text as dictionary of numbered rows
    text_by_row = read_ascii(ascii_file)

    # initiate dictionary to capture findings
    detected = defaultdict(dict)

    if output_file:
        try:
            o = open(output_file, 'w')

            # open list in JSON file
            o.write("[{")

            for row, (line_text, line_length) in text_by_row.items():

                for info_type, (pattern, verify_fcn) in PII_CORPUS.items():
                    detected_row = []
                    for m in re.finditer(pattern, line_text):
                        if m:

                            verified = verify_fcn(m.group(0).strip())

                            if verified:
                                if line_length > 50:
                                    truncated = line_text[max(0, m.start()-20):min(line_length, m.end()+20)]
                                # create tuple of info type, info detected, start and end positions,
                                    found = (info_type, verified, f"{m.start()} - {m.end()}", truncated)
                                else:
                                    found = (info_type, verified, f"{m.start()} - {m.end()}", line_text)

                                detected_row.append(found)

                    if len(detected_row) > 0:
                        detected[row][info_type] = detected_row

                if detected[row]:
                    o.write(f'"{str(row)}":')
                    o.write(json.dumps(detected[row]))
                    o.write(",\n")

        except Exception as e:
            sys.exit(f"pii_recognition error: An error occurred during text parsing: {e}")

        try:
            # once all rows written, remove last comma by seeking to end of file
            o.seek(0, os.SEEK_END)
            o.seek(o.tell() - 3, os.SEEK_SET)

            # close dict and end JSON file
            o.write("}}]\n")
            o.truncate()
            o.close()

            return detected

        except Exception as e:
            sys.exit(f"pii_recognition error: An unexpected error occurred in file write completion: {e}.")

    else:
        try:
            for row, (line_text, line_length) in text_by_row.items():

                for info_type, pattern in PII_CORPUS.items():
                    detected_row = []
                    print(pattern)
                    for m in re.finditer(pattern, line_text):
                        if m:
                            if line_length > 50:
                                truncated = line_text[max(0, m.start() - 20):min(line_length, m.end() + 20)]

                                # create tuple of info type, info detected, start and end positions,
                                found = (info_type, m.group(0).strip(), f"{m.start()} - {m.end()}", truncated)
                            else:
                                found = (info_type, m.group(0).strip(), f"{m.start()} - {m.end()}", line_text)

                            # add to list
                            detected_row.append(found)

                    if len(detected_row) > 0:
                        detected[row][info_type] = detected_row

            return detected
        except Exception as e:
            sys.exit(f"pii_recognition error: An error occurred during text parsing: {e}")


