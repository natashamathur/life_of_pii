import re
# (\d{3}[-\.\s]??\d{3}[-\.\s]??\d{4})
# (\(\d{3}\)\s*\d{3}[-\.\s]??\d{4})
# (\d{3}[-\.\s]??\d{4})
# Phone number formats
# US Local: 754-3010
# US Domestic: (541) 754-3010
# US International: +1-541-754-3010
# US Dialed in the US: 1-541-754-3010
# US Dialed from Germany: 001-541-754-3010
# US Dialed from France: 191 541 754 3010
#
# In the US, the convention is 1 (area code) extension, while
# in Germany it is (0 area code)/extension.
# German Local: 636-48018
# German Domestic: (089) / 636-48018
# German International: +49-89-636-48018
# German EU: 19-49-89-636-48018

TELE_CORPUS = {
    'eu_country_area': r"\b\+?((\d{2}[-\.\s]??){1,3}\d{3}[-\.\s]??\d{5})\b",
    'eu_area': r"(?<![-\+])(([\(]??\d{3}\)??[-\.\s/]{0,3}){0,3}\d{3}[-\.\s]??\d{5})\b",
    'us_number': r"?<![-])\b([\+]??\d{0,2}[-\.\s/]??([\(]??\d{3}\)??[-\.\s/]??){0,3}\d{3}[-\.\s]??\d{4})\b"}

def read_ascii(ascii_file):
    with open(ascii_file, 'r') as f:
        text_as_str = f.read().split('\n')

    text_by_row = {row: val for row, val in enumerate(text_as_str)}
    return text_by_row

def find_numbers(ascii_file):
    text_by_row = read_ascii(ascii_file)

    for row, linetext in text_by_row.items():
        print(type(linetext))
        for info_type, pattern  in TELE_CORPUS.items():
            for m in re.finditer(pattern, linetext):
                if m:
                    print('row {}, position {} - {}: {} ({})'.format(row, m.start(), m.end(), m.group(0).strip(), info_type))
