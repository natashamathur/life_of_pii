import re
import os
import sys
import json
import nltk
from collections import defaultdict

from checkers.check_functions import *


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


def format_plaintext(info_type, match_found, line_text, line_length, start, end):
    if line_length > 50:
        truncated = line_text[max(0, start - 20):min(line_length, end + 20)]

        # create tuple of info type, info detected, start and end positions,
        return (info_type, match_found, f"{start} - {end}", truncated)
    else:
        return (info_type, match_found, f"{start} - {end}", line_text)


VERIFY_CORPUS = {

    # 'AGE': (r"\b([1-9]?\d{1,2})\b|\b([0]?[1-9]{1,2})\b|\b(\d{1,3} (years|ans|y.o.|años|anni|Jahre))\b|(?=\b(Age|Alter)[:\s\,\-]{1,2})(\d{1,3})\b", check_age),
    'SSN': (r"[0-9]{3}-[0-9{2}-[0-9]{4}]", verify_ssn),
    'IP_ADDRESS': (r"\b([0-9]{3}.[0-9]{3}.[0-9]{3}.[0-9]{3})\b", check_ip),
    'GENDER': (r"\b(male)\b|\b(female)\b|\b(man)\b|\b(woman)\b|\b(girl)\b|\b(boy)\b", standardize_gender),
    'AUSTRALIA_MEDICARE_NUMBER' : (r"[2-6][0-9]{8}"),
    'AGE': (r"\b\d{1,2}\b|\b\d{1,2} y.o.\b|\b\d{1,2} years\b", check_age),
    'CREDIT_CARD_NUMBER': (r"^[0-9]{1,5}[-|,|_]?[0-9]{1,5}[-|,]?[0-9]{1,5}[-|,]?[0-9]{1,5}[-|,]", verify_cc_match),
    'PHONE_NUMBER_US': (r"(?<![-])\b([\+]??\d{0,2}[-\.\s/]??([\(]??\d{3}\)??[-\.\s/]??){0,3}\d{3}[-\.\s]??\d{4})\b", verify_phone),
    'CHINA ID': (r"([0-9]{6})([[1][9]|[2][0]])([0-9]{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])([0-9]{3})([0-9X])", verify_chinaid),
    'NAME': (r"([A-Z][a-z]*(\-[A-Z][a-z]*)?\.?)\s([A-Z][a-z]*(\-[A-Z][a-z]*)?\.?)(\s?[A-Z][a-z]*(\-[A-Z][a-z]*)?\.?)?", extract_names),
    'MAC_ADDRESS_LOCAL': (r"\b([0-9A-Z]{2}(\:|\-)){5}[0-9A-Z]{2}", check_mac_local),
    'SOUTH_AFRICA_NATIONAL_ID': (r"([0-9]{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])([0-9]{4})(0|1)(8|9)([0-9])", south_africa_id),
    'HONG_KONG_NATIONAL_ID': (r"([A-Z]{1,2})([0-9]{6})(([\(][0-9][\)])|[0-9])", hong_kong_id),
    'US_DEA_NUMBER': (r"[A|B|C|D|E|F|G|H|J|K|L|M|P|R|S|T|U|X][A-Z|9][0-9]{7}|-[A-Z0-9]{4-5}", dea_checksum),
    'SWEDEN_NATIONAL_ID': (r"([0-9]{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])(\-?)([0-9]{4})", sweden_id)
    }
REGEX_ONLY_CORPUS = {
    # 'AGE': (r"\b([1-9]?\d{1,2})\b|\b([0]?[1-9]{1,2})\b|\b(\d{1,3} (years|ans|y.o.|años|anni|Jahre))\b|(?=\b(Age|Alter)[:\s\,\-]{1,2})(\d{1,3})\b", check_age),
    'AUSTRALIA_MEDICARE_NUMBER' : r"[2-6][0-9]{8}",
    'EMAIL_ADDRESS': r"([a-zA-Z0-9\_\'][\.'\\a-zA-Z0-9_]*[\'\_a-zA-Z0-9]@[a-zA-Z0-9]+\.(com|edu|gov|org|net|ca))",
    'PHONE_NUMBER_INT': r"\b\+?((\d{2}[-\.\s]??){1,3}\d{3}[-\.\s]??\d{5})\b|(?<![-\+])([\(]??\d{3}\)?[-\.\s/]{0,3}\d{3}[-\.\s]??\d{5})\b",
    'FDA_CODE': r"([0-9]{0,2}[a-zA-Z]{3,5}[a-zA-Z0-9]{6,7})",
    'ICD_CODE': r"[A-Z][0-9]{2}.[0-9]{1,2}",
    'PHONE_NUMBER_US': r"(?<![-])\b([\+]??\d{0,2}[-\.\s/]??([\(]??\d{3}\)??[-\.\s/]??){0,3}\d{3}[-\.\s]??\d{4})\b",
    'MAC_ADDRESS': r"\b([0-9A-Z]{2}(\:|\-)){5}[0-9A-Z]{2}",
    'US_VIN_NUMBER': r"[(A-Z)(0-9)^IOQ]{17}",
    'GERMANY_PASSPORT': r"[(0-9)C|F|G|H|J-N|P|R|T|V|W-Z]{9}",
    'FRANCE_PASSPORT': r"[0-9]{2}[A-Za-z]{2}[0-9]{5}"
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

                for info_type, pattern in REGEX_ONLY_CORPUS.items():
                    detected_row = []
                    for m in re.finditer(pattern, line_text):
                        if m:
                            detected_row.append(
                                format_plaintext(info_type, m.group(0).strip(),
                                                 line_text, line_length,
                                                 start=m.start(), end=m.end())
                            )

                for info_type, (pattern, verify_fcn) in VERIFY_CORPUS.items():
                    detected_row = []
                    for m in re.finditer(pattern, line_text):
                        if m:

                            verified = verify_fcn(m.group(0).strip())

                            if verified:
                                detected_row.append(
                                    format_plaintext(info_type, verified,
                                                     line_text, line_length,
                                                     start=m.start(), end=m.end())
                                    )

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

                for info_type, pattern in REGEX_ONLY_CORPUS.items():
                    detected_row = []
                    for m in re.finditer(pattern, line_text):
                        if m:
                            detected_row.append(
                                format_plaintext(info_type, m.group(0).strip(),
                                                 line_text, line_length,
                                                 start=m.start(), end=m.end())
                            )

                for info_type, (pattern, verify_fcn) in VERIFY_CORPUS.items():
                    detected_row = []
                    for m in re.finditer(pattern, line_text):
                        if m:

                            verified = verify_fcn(m.group(0).strip())

                            if verified:
                                detected_row.append(
                                    format_plaintext(info_type, verified,
                                                     line_text, line_length,
                                                     start=m.start(), end=m.end())
                                )

                    if len(detected_row) > 0:
                        detected[row][info_type] = detected_row

            return detected
        except Exception as e:
            sys.exit(f"pii_recognition error: An error occurred during text parsing: {e}")


