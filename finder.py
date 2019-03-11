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
                if m:

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
                if m:
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
    'SSN': (r"\b([0-9]{3}\-[0-9{2}\-[0-9]{4}])\b", verify_ssn),
    'IP_ADDRESS': (r"\b([0-9]{3}.[0-9]{3}.[0-9]{3}.[0-9]{3})\b", check_ip),
    'GENDER': (r"\b(male)\b|\b(female)\b|\b(man)\b|\b(woman)\b|\b(girl)\b|\b(boy)\b", standardize_gender),
    'CREDIT_CARD_NUMBER': (r"\b(^[0-9]{1,5}[-|,|_]?[0-9]{1,5}[-|,]?[0-9]{1,5}[-|,]?[0-9]{1,5}[-|,])\b", verify_cc_match),
    'PHONE_NUMBER_US': (r"(?<![-\d\.])\b((\d{2})?[\+]?1?[-\.\s\/]{0,3}?[\(]??\d{3}[\)]??[-\.\s]??\d{3}[-\.\s]??\d{4})\b", verify_phone),
    'CHINA ID': (r"\b([0-9]{6})([[1][9]|[2][0]])([0-9]{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])([0-9]{3})([0-9X])\b", verify_chinaid),
    'NAME': (r"\b(([A-Z][a-z]*(\-[A-Z][a-z]*)?\.?)\s([A-Z][a-z]*(\-[A-Z][a-z]*)?\.?)(\s?[A-Z][a-z]*(\-[A-Z][a-z]*)?\.?)?)\b", extract_names),
    'MAC_ADDRESS_LOCAL': (r"\b(([0-9A-Z]{2}(\:|\-)){5}[0-9A-Z]{2})\b", check_mac_local),
    'SOUTH_AFRICA_NATIONAL_ID': (r"\b([0-9]{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])([0-9]{4})(0|1)(8|9)([0-9])\b", south_africa_id),
    'HONG_KONG_NATIONAL_ID': (r"\b([A-Z]{1,2})([0-9]{6})(([\(][0-9][\)])|[0-9])\b", hong_kong_id),
    'US_DEA_NUMBER': (r"\b([A|B|C|D|E|F|G|H|J|K|L|M|P|R|S|T|U|X][A-Z|9][0-9]{7}|-[A-Z0-9]{4-5})\b", dea_checksum),
    'SWEDEN_NATIONAL_ID': (r"\b([0-9]{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])(\-?)([0-9]{4})", sweden_id),
    'SPAIN_NIF_NUMBER': (r"[0-9]{8}-?[A-Z]", check_spain_nif),
    'SPAIN_NIE_NUMBER': (r"[X|Y|Z]-?[0-9]{7}-?[A-Z]", check_spain_nie),
    'UK_NHS_ID': (r"[0-9]{3}\s?[0-9]{3}\s?[0-9]{4}", uk_nhs_id),
    'CANADIAN_INSURANCE_ID': (r"[0-9]{3}\s?[0-9]{3}\s?[0-9]{3}", canadian_insur_id),
    'MEXICAN_CURP_ID': (r"[A-Z]{4}[0-9]{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])[HM][A-Z]{5}[0-9]{2}", mexico_curp),
    'FRENCH_NATIONAL_INSEE_ID': (r"[12][0-9]{2}(0[1-9]|1[0-2])[0-9]{4,6}[0-9]{3}\s?[0[1-9]|[1-8][0-9]|9[0-7]]", french_insee_id),
    'POLISH_PESEL_ID': (r"[0-9]{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])[0-9]{5}", polish_pesel)
    }


REGEX_ONLY_CORPUS = {
    'AUSTRALIA_MEDICARE_NUMBER' : r"[2-6][0-9]{8}",
    'EMAIL_ADDRESS': r"([a-zA-Z0-9\_\'][\.'\\a-zA-Z0-9_]*[\'\_a-zA-Z0-9]@[a-zA-Z0-9]+\.(com|edu|gov|org|net|ca))",
    'PHONE_NUMBER_INT': r"\b\+?((\d{2}[-\.\s]??){1,3}\d{3}[-\.\s]??\d{5})\b|(?<![-\+])([\(]??\d{3}\)?[-\.\s/]{0,3}\d{3}[-\.\s]??\d{5})\b",
    'FDA_CODE': r"([0-9]{0,2}[a-zA-Z]{3,5}[a-zA-Z0-9]{6,7})",
    'ICD_CODE': r"[A-Z][0-9]{2}.[0-9]{1,2}",
    'PHONE_NUMBER_US': r"(?<![-])\b([\+]??\d{0,2}[-\.\s/]??([\(]??\d{3}\)??[-\.\s/]??){0,3}\d{3}[-\.\s]??\d{4})\b",
    'MAC_ADDRESS': r"\b([0-9A-Z]{2}(\:|\-)){5}[0-9A-Z]{2}",
    'US_VIN_NUMBER': r"[(A-Z)(0-9)^IOQ]{17}",
    'GERMANY_PASSPORT': r"[(0-9)C|F|G|H|J-N|P|R|T|V|W-Z]{9}",
    'FRANCE_PASSPORT': r"[0-9]{2}[A-Za-z]{2}[0-9]{5}",
    'UK_INSURANCE_ID': r"(([A-CGHJ-PR-TW-Z]{2})([0-9]{6})[A-D])"
    }



def pii_finder(ascii_file, file_format=True, output_file=None, ret=False):
    '''
    Parse text in a given ASCII text file or text string for potential PII

    Inputs:
        ascii_file: (str) Valid filename, or a string of ASCII text
        file_format: (boolean) Whether ascii_file is a file name, or a string to
            be parsed. Default is True.
        output_file: (str) JSON file to which dictionary of PII recognized in
            ascii_file should be written
        ret: (boolean) Whether to return dictionary of PII recognized in
            ascii_file

    Returns: Dictionary containing row nunmbers as keys and dictionaries of
        PII types and PII of each type found in that row as values
    '''
    # return ascii text as dictionary of numbered rows
    text_by_row = read_ascii(ascii_file, file_format=file_format)

    # initiate dictionary to capture findings
    detected = defaultdict(dict)

    if output_file:
        _, ext = os.path.splitext(output_file)

        if ext != ',json':
            sys.exit(f"pii_recognition output file error: Output file must be a '.json' file, not '{ext}'.")

        else:
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

            if ret:
                return detected

        except Exception as e:
            sys.exit(f"pii_recognition error: An unexpected error occurred in file write completion: {e}.")

    else:
        try:
            for row, (line_text, line_length) in text_by_row.items():
                # parse row for PII types that are determined solely by Regex
                detected = parse_line(row, line_text, line_length, corpus=REGEX_ONLY_CORPUS,
                                      detected_dict=detected, verify=False)

                # parse row for PII types that require verification via an additional function
                detected = parse_line(row, line_text, line_length, corpus=VERIFY_CORPUS,
                                      detected_dict=detected, verify=True)

            return detected

        except Exception as e:
            sys.exit(f"pii_recognition error: An error occurred during text PII parsing: {e}")


if __name__ == "__main__":
    class Args():
        pass

    a = Args()

    parser = argparse.ArgumentParser(description="Collect arguments for PII recognition.")

    parser.add_argument('--display', action='store_true', default=True, help="Whether to display dictionary of PII found.")
    parser.add_argument('--output_file', type=str, help="File name with JSON extension to which to write PII found.")

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
        # check that file is entered and exists
        # if args.ascii_file == None and args.ascii_text == None:
        #     print("Please enter a string or file to be checked for PII.",file=sys.stderr)
        #     sys.exit("pii_recognition error: ")

        # file_format is True if it is a file
        if not a.output_file and not a.display:
            parser.error("pii_recognition output error: PII must be displayed if output will not be written to a file.")

        if a.ascii_file:
            if os.path.exists(a.ascii_file) == 0:
                sys.exit(f"File '{args.file}' is invalid.")
            elif os.path.getsize(args.file) == 0:
                sys.exit(f"File '{args.file}' is blank.")

            else:
                if a.output_file:
                    pii_finder(a.ascii_file, output_file=a.output_file, ret=a.display, file_format=True)
                else:
                    pii_finder(a.ascii_file, ret=a.display, file_format=True)
        elif a.ascii_text:
            if a.output_file:
                pii_finder(a.ascii_text, output_file=a.output_file, ret=a.display, file_format=False)
            else:
                pii_finder(a.ascii_text, ret=True, file_format=False)

        # if args.ascii_text == None:
        #     if os.path.exists(args.ascii_file) == 0:
        #         sys.exit(f"File '{args.file}' is invalid.")
        #
        #      # check if file is blank
        # if os.path.getsize(args.file) == 0:
        #     sys.exit(f"File '{args.file}' is blank.")
        # else:
        #     file_format = False
        #
        # output_file,ret = None, False
        # if args.print_to_file == True:
        #     output_file = args.output_file
        #     ret = True
        #
        # pii_finder(args.ascii, output_file=output_file, ret=ret, file_format)
    except Exception as e:
        # check for any exceptions not covered above
        sys.exit(f"pii_recognition error: An unexpected error occured when processing your request: {e}")
