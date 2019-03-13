# Life of PII Recognition Utility

This utility parses ASCII text for several kinds of personally identifiable 
information (PII), including national ID numbers, US and international telephone
numbers, gender, IP and MAC addresses, physical addresses, credit card numbers,
etc. 

The utility writes all possible PII found to a JSON file, including each match's 
location in the file (row and character position in the row), and text 
immediately surrounding match text. This output format enables the user to 
easily verify the results and locate associated information. 

## Authors

- [Andrew Deng](https://github.com/CAPPAndrew)
- [Loren Hinkson](https://github.com/lorenh516)
- [Natasha Mathur](https://github.com/natashamathur)


## Getting Started

This utility requires at least Python 3.6 and the packages [`re`](https://docs.python.org/3/library/re.html) and [`nltk`](https://www.nltk.org/).

The utility can be run on either a file or a string, and outputs the results into a file. 


### Examples
Below is an example of a command line input to run the utilty on the file **FILENAME** and save the output to the file **OUTPUT_FILE**
```
$ python3.6 finder.py --ascii_file 'FILENAME' --output_file OUTPUT_FILE
```

Below is an example of a command line input to run this utilty on the string **pii_string** and save the output to the file **OUTPUT_FILE**.
```
$ python3.6 finder.py --ascii_string "I am 90 years old and I have an SSN of 310-74-3223" --output_file OUTPUT_FILE
```

## File Descriptions

 - Main Utility: [`finder.py`](https://github.com/natashamathur/life_of_pii/blob/master/finder.py)
 - Ancilliary Code: [`checkers`](https://github.com/natashamathur/life_of_pii/tree/master/checkers) [`area_codes.json`](https://github.com/natashamathur/life_of_pii/blob/master/area_codes.json) 
 - Used for Testing: [`fake_pii.txt`](https://github.com/natashamathur/life_of_pii/blob/master/fake_pii.txt) [`found.json`](https://github.com/natashamathur/life_of_pii/blob/master/found.json)

## Uses
This utility provides the ability to extract multiple types of PII from 
documents with large quantities of data in an efficient manner. For example, 
this could be used to check public-facing documents prior to publication to 
ensure that PII is not inadvertently exposed.

The [`fake_pii.txt`](https://github.com/natashamathur/life_of_pii/blob/master/fake_pii.txt) is provided as an example to showcase a potential use of the utility as a categorizer of scattered PII within a single document.


## Methodology
The PII utility relies heavily on the `re` library for regex text matching, and
passes potential PII matches through a series of verification functions to 
validate match types, utilizing algorithms such as the Luhn algorithm for credit 
card numbers, and libraries such as NLTK for natural language tokenization for 
recognizing nouns in regex matches for name-like structures. 

The utility is "greedy," identifying all possible PII types for a given text 
string, so text need only be parsed once to identify as many possible types of 
PII in a document or text string. The dictionary format makes it extremely easy 
for users to "filter" results to view possible PII matches of a certain type.

## PII Covered
Our implementation focuses on PII that can be verified as valid, such as credit
cards, phone numbers, and various national IDs. As many IDs are numerical, or
can be otherwise converted into integers, particular focus was levied on IDs
which can be verified against a known algorithim or checksum pattern over 
IDs that are randomly or sequentially generated.

**Verifiable PII**
- American SSN
- American Phone Numbers
- American DEA Number
- Canadian Insurance Number
- Chinese National ID Number
- Credit Card Number
- French National INSEE ID Number
- Gender
- Hong Kong National ID Number
- IP Address
- MAC Address Local
- Name
- Mexican CURP National ID Number
- Polish National PESEL ID Number
- South African National ID Number
- South Korean National ID Number
- Spanish NIE Number
- Spanish NIF Number
- Swedish National ID Number
- UK NHS ID Number

**REGEX'ed PII**
- Age
- American VIN Number
- Australian Medicare Number
- Email Address
- FDA Code
- French Passport Number
- German Passport Number
- ICD Code
- International Phone Number
- MAC Address
- UK Insurance ID Number
- Physical Address
