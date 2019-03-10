# Life of PII Recognition Utility
This utility parses ASCII text for several kinds of personally identifiable 
information (PII), including national ID numbers, US and international telephone
numbers, gender, IP and MAC addresses, physical addresses, credit card numbers,
etc. 

The utility writes all possible PII found to a JSON file, including each match's 
location in the file (row and character position in the row), and text 
immediately surrounding match text. This output format enables the user to 
easily verify the results and locate associated information. 

The utility can also return a dictionary with the relevant data (versus writing 
to a file), to allow for flexible interaction with possible PII.


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


## Uses
This utility provides the ability to extract multiple types of PII from 
documents with large quantities of data in an efficient manner. For example, 
this could be used to check public-facing documents prior to publication to 
ensure that PII is not inadvertently exposed.


## PII Covered
Our implementation focuses on PII that can be verified as valid, such as credit
cards, phone numbers, and various national IDs. As many IDs are numerical, or
can be otherwise converted into integers, particular focus was levied on IDs
which can be verified ones with a known algorithim or checksum pattern over 
IDs that are randomly or sequentially generated.

## Usage

This utility requires Python 3.7. and uses the following packages. 

[`re`](https://docs.python.org/3/library/re.html)
[`nltk`](https://www.nltk.org/)
