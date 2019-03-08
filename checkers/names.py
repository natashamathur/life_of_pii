import re
import nltk

def extract_names(line):
    match = re.search("([A-Z][a-z]*(\-[A-Z][a-z]*)?\.?)\s([A-Z][a-z]*(\-[A-Z][a-z]*)?\.?)(\s?[A-Z][a-z]*(\-[A-Z][a-z]*)?\.?)?", line)
    name = ""
    token_line = nltk.sent_tokenize(match.string)
    token_line = [nltk.word_tokenize(sent) for sent in token_line]
    token_line = [nltk.pos_tag(sent) for sent in token_line][0]
    for (new_string, tag) in token_line:
        if tag in ["NNP", "NN"]:
                name += new_string
                name += " "
    return name[:-1]
	
