import re
import os
import sys
import json
import nltk
import argparse
import warnings
from collections import defaultdict

from checkers.check_functions import *


def read_ascii(ascii_file, f=None, file_format=True):
    '''
    Reformat ASCII text string or ASCII text file for PII parssing and validation
    Inputs:
        ascii_file: (str) Valid filename, or a string of ASCII text
        f: (I/O Object) File object. Default is None.
        file_format: (boolean) Whether ascii_file is a file name, or a string to
            be parsed. Default is True.
    Returns: Dictionary with row number (from file/ text
    srting) as keys and a tuple of line text and line length (in characters)
    as values
    '''
    if ascii_file == '':
        sys.exit(f"pii_recognition error: No text detected for PII recognition. Please review text parameters.")
    if file_format:
        # test whether ascii_file is a valid file
        try:
            # split file content by end of line characters
            if not f:
                with open(ascii_file, 'r') as f:
                    text_as_str = f.read().split('\n')
            else:
                text_as_str = f.read().split('\n')
        except FileNotFoundError:
            # if not, produce an error and exit
            sys.exit(f"pii_recognition file error: File {ascii_file} was not found.")
        except Exception as e:
            # catch all other errors with a system exit
            sys.exit(f"pii_recognition error: An error occurred in accessing text in file '{ascii_file}': {e}")
    else:
        try:
            # if file_format is False, parse ASCII text as a string and split by
            # end of line characters
            text_as_str = ascii_file.split('\n')
        except Exception as e:
            # catch all other errors with a system exit
            sys.exit(f"pii_recognition error: An error occurred in accessing text: {e}")

    # reformat list of text strings into dictionary
    try:
        text_by_row = {row: (val, len(val)) for row, val in enumerate(text_as_str)}
        return text_by_row
    except Exception as e:
        sys.exit(f"pii_recognition error: An error occurred when formatting text for PII parsing: {e}")


def format_plaintext(info_type, match_found, line_text, line_length, start, end):
    '''
    Truncate text lines containing a PII match with length of more than 50
    characters to include only 20 characters before and 20 characters after
    match text
    Inputs:
        info_type: (str) Type of PII match found
        match_found: (re match object text) The text of a PII match
        line_text: (str) Text line in which PII match was found
        line_length: (int) Length of text line in which PII match was found
        start: (re match object property) Starting character position in
            line text in which PII match was found
        end: (re match object property) Ending character position in
            line text in which PII match was found
    Returns: PII match tuple containing PII type, text, character start and
        end position, and immediately surrounding text for the potential PII
        found
    '''
    if line_length > 50:
        truncated = line_text[max(0, start - 20):min(line_length, end + 20)]

        # return tuple of info type, info detected, start and end positions,
        # surrounding text
        return (info_type, match_found, f"{start} - {end}", truncated)
    else:
        return (info_type, match_found, f"{start} - {end}", line_text)


def parse_line(row, line_text, line_length, corpus, detected_dict, file_obj=None,
                verify=False):
    '''
    Helper function for pii_finder. Parses an individual line of text for PII
    types that are determined solely by Regex without additional verification,
    and then for PII types that require verification via an additional function.
    Inputs:
        row: (int) Text row number
        line_text: (str) Text line in which PII match was found
        line_length: (int) Length of text line in which PII match was found
        corpus: (dict) Regex match corpus.
            Keys: Strings indicating PII types
            Values: Regex pattern associated with the PII type (REGEX_ONLY_CORPUS), or
                    Tuple of Regex pattern associated with the PII type and the
                    PII type's verification funcitons (VERIFY_CORPUS)
        detected_dict: (dict) Dictionary containing row nunmbers as keys and
            dictionaries of PII types and PII of each type found in that row
            as values
        file_obj: (I/O object) File object corresponding to a specified output
            file. Default is None.
        verify: (boolean) Whether to use the verification or no verification
            corpus. Default is False (REGEX_ONLY_CORPUS).
    Returns: An updated detected_dict
    '''
    if verify:
        for info_type, (pattern, verify_fcn) in corpus.items():

            detected_row = []
            for m in re.finditer(pattern, line_text):
                if m and m.group(0).strip() != '':
                    verified = verify_fcn(m.group(0).strip())

                    if verified:
                        detected_row.append(
                            format_plaintext(info_type, verified,
                                             line_text, line_length,
                                             start=m.start(), end=m.end())
                        )
            if len(detected_row) > 0:
                detected_dict[row][info_type] = detected_row

    else:
        for info_type, pattern in corpus.items():

            detected_row = []
            for m in re.finditer(pattern, line_text):
                if m and len(m.group(0).strip()) > 0:
                    detected_row.append(
                        format_plaintext(info_type, m.group(0).strip(),
                                         line_text, line_length,
                                         start=m.start(), end=m.end())
                    )

            if len(detected_row) > 0:
                detected_dict[row][info_type] = detected_row

    return detected_dict


VERIFY_CORPUS = {

    'AGE': (r"(?<![\.\+\-\(])\b(\d{1,2}\s(years|ans|y.o.|años|anni|Jahre))(?![\-\:])\b|(?<![\.\+\-\(])(?=((Age|Alter)[\s\:]{0,2}))([0-1]\d{1,2})(?![\-\:])\b|(?<![\.\+\-\(])\b([0-1]?\d{1,2})(?![\-\:])\b|(?<![\.\+\-\(])\b([0]?[1-9]{1,2})(?![\-\:])\b", check_age),
    'SSN': (r"\b([0-9]{3}\-[0-9]{2}\-[0-9]{4})\b", verify_ssn),
    'IP_ADDRESS': (r"\b([0-9]{3}.[0-9]{3}.[0-9]{3}.[0-9]{3})\b", check_ip),
    'GENDER': (r"\b(male)\b|\b(female)\b|\b(man)\b|\b(woman)\b|\b(girl)\b|\b(boy)\b", standardize_gender),
    'CREDIT_CARD_NUMBER': (r"\b(^[0-9]{1,5}[-|,|_]?[0-9]{1,5}[-|,]?[0-9]{1,5}[-|,]?[0-9]{1,5}[-|,])\b", verify_cc_match),
    'PHONE_NUMBER_US': (r"(?<![-\d\.])\b((\d{2})?[\+]?1?[-\.\s\/]{0,3}?[\(]??\d{3}[\)]??[-\.\s]??\d{3}[-\.\s]??\d{4})\b", verify_phone),
    'CHINA ID': (r"\b([0-9]{6})([[1][9]|[2][0]])([0-9]{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])([0-9]{3})([0-9X])\b", verify_chinaid),
    'NAME': (r"\b(([A-Z][a-z]*(\-[A-Z][a-z]*)?(\s|[.!?,:]\s))([A-Z][a-z]*(\-[A-Z][a-z]*)?(\s|[.!?,:]\s|'s)?)([A-Z][a-z]*(\-[A-Z][a-z]*)?(\s|[.!?,:]\s?|'s)){0,3}(((IX|IV|I{1,3}|V[I]{0,3}|X)|(the\s(1st|2nd|3rd|[4-9]th)))('s)?)?)\b", extract_names),
    'MAC_ADDRESS_LOCAL': (r"\b(([0-9A-Z]{2}(\:|\-)){5}[0-9A-Z]{2})\b", check_mac_local),
    'SOUTH_AFRICA_NATIONAL_ID': (r"\b([0-9]{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])([0-9]{4})(0|1)(8|9)([0-9])\b", south_africa_id),
    'HONG_KONG_NATIONAL_ID': (r"\b([A-Z]{1,2})([0-9]{6})(([\(][0-9][\)])|[0-9])\b", hong_kong_id),
    'US_DEA_NUMBER': (r"\b([A|B|C|D|E|F|G|H|J|K|L|M|P|R|S|T|U|X][A-Z|9][0-9]{7}|-[A-Z0-9]{4-5})\b", dea_checksum),
    'SWEDEN_NATIONAL_ID': (r"\b([0-9]{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])(\-?)([0-9]{4})\b", sweden_id),
    'SPAIN_NIF_NUMBER': (r"\b([0-9]{8}-?[A-Z])\b", check_spain_nif),
    'SPAIN_NIE_NUMBER': (r"\b([X|Y|Z]-?[0-9]{7}-?[A-Z])\b", check_spain_nie),
    'UK_NHS_ID': (r"\b([0-9]{3}\s?[0-9]{3}\s?[0-9]{4})\b", uk_nhs_id),
    'CANADIAN_INSURANCE_ID': (r"\b([0-9]{3}\s?[0-9]{3}\s?[0-9]{3})\b", canadian_insur_id),
    'MEXICAN_CURP_ID': (r"\b([A-Z]{4}[0-9]{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])[HM][A-Z]{5}[0-9]{2})\b", mexico_curp),
    'FRENCH_NATIONAL_INSEE_ID': (r"\b(([12][0-9]{2})(0[1-9]|1[0-2])([0-9]{4,6})([0-9]{3})(\s?)([0[1-9]|[1-8][0-9]|9[0-7]))\b", french_insee_id),
    'POLISH_PESEL_ID': (r"\b([0-9]{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])[0-9]{5})\b", polish_pesel)
    }


REGEX_ONLY_CORPUS = {
    'AUSTRALIA_MEDICARE_NUMBER' : r"\b([2-6][0-9]{8})\b",
    'EMAIL_ADDRESS': r"\b([a-zA-Z0-9\_\'][\.'\\a-zA-Z0-9_]*[\'\_a-zA-Z0-9]@[a-zA-Z0-9]+\.(com|edu|gov|org|net|ca))\b",
    'PHONE_NUMBER_INT': r"\b\+?((\d{2}[-\.\s]??){1,3}\d{3}[-\.\s]??\d{5})\b|(?<![-\+])([\(]??\d{3}\)?[-\.\s/]{0,3}\d{3}[-\.\s]??\d{5})\b",
    'FDA_CODE': r"\b(([0-9]{4}-[0-9]{4}-[0-9]{2})|([0-9]{5}-[0-9]{3}-[0-9]{2})|([0-9]{5}-[0-9]{4}-[0-9]{1}))\b",
    'ICD_CODE': r"\b([A-Z][0-9]{2}.[0-9]{1,2})\b",
    'PHONE_NUMBER_US': r"(?<![-])\b([\+]??\d{0,2}[-\.\s/]??([\(]??\d{3}\)??[-\.\s/]??){0,3}\d{3}[-\.\s]??\d{4})\b",
    'MAC_ADDRESS': r"\b(([0-9A-Z]{2}(\:|\-)){5}[0-9A-Z]{2})\b",
    'US_VIN_NUMBER': r"\b([(A-Z)(0-9)^IOQ]{17})\b",
    'GERMANY_PASSPORT': r"\b([(0-9)C|F|G|H|J-N|P|R|T|V|W-Z]{9})\b",
    'FRANCE_PASSPORT': r"\b([0-9]{2}[A-Za-z]{2}[0-9]{5})\b",
    'UK_INSURANCE_ID': r"\b(([A-CGHJ-PR-TW-Z]{2})([0-9]{6})[A-D])\b",
    'PHYSICAL_ADDRESS': r"\b(\d{1,6}\s([a-zA-z\.\s\-]+\s){0,3}([a-zA-z0-9\s]+[a-zA-Z\.])([\,\s]{0,2})?(road|street|avenue|boulevard|lane|drive|way|court|plaza|terrace|colony|close)[\,\s]{1,2}((Apt|Apartment|Floor|Suite|House)[\s\:]{1,2}\d{0,6}[\,\s]{1,2})?(([a-zA-Z]+[\s\-]?){1,4})?([\,\s]{0,2})?([A-Za-z]{2}|[a-zA-Z]+[\s\-])?([\,\s]{0,2}([0-9\-]{1,10})|[A-Z0-9]{3}\s[A-Z0-9]{3})?)\b"
    }



def pii_finder(ascii_file, output_file=None, file_format=True):
    '''
    Parse text in a given ASCII text file or text string for potential PII
    Inputs:
        ascii_file: (str) Valid filename, or a string of ASCII text
        output_file: (str) JSON file to which dictionary of PII recognized in
            ascii_file should be written
        file_format: (boolean) Whether ascii_file is a file name, or a string to
            be parsed. Default is True.
    Returns: None. Writes output to output_file.
    '''
    # return ascii text as dictionary of numbered rows
    if not output_file:
        sys.exit(f"pii_recognition output error: PII must written to a file.")

    else:
        try:
            _, ext = os.path.splitext(output_file)

            if ext != '.json':
                sys.exit(f"pii_recognition output file error: Output file must be a '.json' file, not '{ext}'.")

            text_by_row = read_ascii(ascii_file, file_format=file_format)

            # initiate dictionary to capture findings
            detected = defaultdict(dict)
            
            # open output file
            o = open(output_file, 'w')

            # open list in JSON file
            o.write("[{")
            for row, (line_text, line_length) in text_by_row.items():

                try:
                    # parse row for PII types that are determined solely by Regex
                    detected =  parse_line(row, line_text, line_length, corpus=REGEX_ONLY_CORPUS,
                                           detected_dict=detected, file_obj=o, verify=False)

                    # parse row for PII types that require verification via an additional function
                    detected = parse_line(row, line_text, line_length, corpus=VERIFY_CORPUS,
                                          detected_dict=detected, file_obj=o, verify=True)
                except Exception as e:
                    sys.exit(f"pii_recognition error: An error occurred during text parsing in row {row}: {e}")

                if detected[row]:
                    o.write(f'"{str(row)}":')
                    o.write(json.dumps(detected[row]))
                    o.write(",\n")

        except Exception as e:
            sys.exit(f"pii_recognition error: An error occurred when writing to output file '{output_file}': {e}")

        try:
            # once all rows written, remove last comma by seeking to end of file
            o.seek(0, os.SEEK_END)
            o.seek(o.tell() - 3, os.SEEK_SET)

            # close dict and end JSON file
            o.write("}}]\n")
            o.truncate()
            o.close()


        except Exception as e:
            sys.exit(f"pii_recognition error: An unexpected error occurred in file write completion: {e}.")


if __name__ == "__main__":
    class Args():
        pass

    a = Args()

    parser = argparse.ArgumentParser(description="Collect arguments for PII recognition.")

    parser.add_argument('--output_file', type=str, help="File name with JSON extension to which to write PII found.", required = True)

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--ascii_file', type=str, help="Valid file name from which to parse text for PII.")
    group.add_argument('--ascii_text', type=str, help="ASCII text string to parse for PII.")

    try:
        args = parser.parse_args(namespace=a)
    except argparse.ArgumentError or argparse.ArgumentTypeError as exc:
        sys.exit("pii_recognition error: Please review arguements passed: {}".format(
           args, exc.message))
    except Exception as e:
        sys.exit("pii_recognition error: Please review arguements passed: {}".format(e))

    try:
        # dictionary of found PII must be returned if not written to file
        if a.ascii_file:
            if os.path.exists(a.ascii_file) == 0:
                sys.exit(f"File '{a.ascii_file}' is invalid.")
            elif os.path.getsize(a.ascii_file) == 0:
                sys.exit(f"File '{a.ascii_file}' is blank.")

            else:
                if a.output_file:
                    pii_finder(a.ascii_file, output_file=a.output_file, file_format=True)
                else:
                    pii_finder(a.ascii_file, file_format=True)
        elif a.ascii_text:
            if a.output_file:
                pii_finder(a.ascii_text, output_file=a.output_file,  file_format=False)
            else:
                pii_finder(a.ascii_text, output_file=None, file_format=False)


    except Exception as e:
        # check for any exceptions not covered above
        sys.exit(f"pii_recognition error: An unexpected error occured when processing your request: {e}")