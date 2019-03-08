import re
import os
import sys
import json
import nltk
from collections import defaultdict



check_functions = {}
check_function['CREDIT_CARD_NUMBER'] = "verify_cc_match"
check_function['AGE'] = "check_age"


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
    digits = re.sub("\D", "", match.string)
    if digits[:1] in ["3", "4", "5", "6", "8"]:
        if len(digits) >= 12 and len(digits) <= 19:
            stripped = [int(x) for x in digits]

            sum_odd = sum(stripped[-1::-2])
            sum_even = sum([sum(divmod(2 * digits, 10)) for digits in stripped[-2::-2]])

            if (sum_odd + sum_even) % 10 == 0:
                return digits

def verify_chinaid(match):
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

def extract_names(match):
    name = ""
    token_line = nltk.sent_tokenize(match.string)
    token_line = [nltk.word_tokenize(sent) for sent in token_line]
    token_line = [nltk.pos_tag(sent) for sent in token_line][0]
    for (new_string, tag) in token_line:
        if tag in ["NNP", "NN"]:
                name += new_string
                name += " "
    return name[:-1]
        
def check_age(possible_age):
    age_alone = possible_age.split(' ')[0]
    if age_alone < 111:
        return age_alone

def standardize_gener(possible_gender):
    if possible_gender.lower() in ('girl', 'woman', 'female'):
        return "Female"
    else:
        return "Male"

def checked(match):
    return match

     
PII_CORPUS = {
    # 'eu_country_area': r"\b\+?((\d{2}[-\.\s]??){1,3}\d{3}[-\.\s]??\d{5})\b",
    'AUSTRALIA_MEDICARE_NUMBER' : (r"[2-6][0-9]{8}"),
    'AGE': (r"\b\d{1,2}\b|\b\d{1,2} y.o.\b|\b\d{1,2} years\b", check_age),
    'GENDER': (r"\b(male)\b|\b(female)\b|\b(man)\b|\b(woman)\b|\b(girl)\b|\b(boy)\b", standardize_gener),
    'CREDIT_CARD_NUMBER': (r"^[0-9]{1,5}[-|,|_]?[0-9]{1,5}[-|,]?[0-9]{1,5}[-|,]?[0-9]{1,5}[-|,]", verify_cc_match),
    # TO DO: figure out why only some emails are being recognized
    # 'old_email': r"^[\.'\x07-z0-9_]*[a-z0-9]+[\.'\x07-z0-9_]*[a-z0-9]+@[a-z0-9]+\.(com|edu|gov|ca|org|net)$",
    'EMAIL_ADDRESS': (r"([a-zA-Z0-9\_\'][\.'\\a-zA-Z0-9_]*[\'\_a-zA-Z0-9]@[a-zA-Z0-9]+\.(com|edu|gov|org|net|ca))", checked),
    'FDA_CODE': (r"([0-9]{0,2}[a-zA-Z]{3,5}[a-zA-Z0-9]{6,7})", checked),
    'PHONE_NUMBER_INT': r"\b\+?((\d{2}[-\.\s]??){1,3}\d{3}[-\.\s]??\d{5})\b|(?<![-\+])([\(]??\d{3}\)?[-\.\s/]{0,3}\d{3}[-\.\s]??\d{5})\b",
    # 'eu_area': r"(?<![-\+])([\(]??\d{3}\)?[-\.\s/]{0,3}\d{3}[-\.\s]??\d{5})\b",
    'PHONE_NUMBER_US': r"(?<![-])\b([\+]??\d{0,2}[-\.\s/]??([\(]??\d{3}\)??[-\.\s/]??){0,3}\d{3}[-\.\s]??\d{4})\b",
    'CHINA ID': (r"([0-9]{6})([[1][9]|[2][0]])([0-9]{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])([0-9]{3})([0-9X])", verify_chinaid)
    'NAME': (r"([A-Z][a-z]*(\-[A-Z][a-z]*)?\.?)\s([A-Z][a-z]*(\-[A-Z][a-z]*)?\.?)(\s?[A-Z][a-z]*(\-[A-Z][a-z]*)?\.?)?", extract_names)
    'ICD_CODE': (r"[A-Z][0-9]{2}.[0-9]{1,2}", checked),
    'MAC_ADDRESS': (r"\b([0-9A-Z]{2}(\:|\-)){5}[0-9A-Z]{2}", checked)

def find_numbers(ascii_file, output_file=None):
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
                # detected[row] = defaultdict(list)

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
                            # detected[row][info_type].append(found)
                            detected_row.append(found)

                    if len(detected_row) > 0:
                        detected[row][info_type] = detected_row

            return detected
        except Exception as e:
            sys.exit(f"pii_recognition error: An error occurred during text parsing: {e}")


