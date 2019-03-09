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

def check_mac(mac_address):
    imp = bin(int(mac[:2]))
    imp = imp[-2:-1]
    if int(imp) == 1:
	return True
    else:
	return False

def dea_checksum(dea):
    v = dea[-7:-1]
    check1, check2 = 0, 0
    check1 = int(v[0])+ int(v[2]) + int(v[4])
    check2 = int(v[1]) + int(v[3]) + int(v[5])
    check = check1 + check2*2
    cd = str(check)[-1]
    if dea[-1] == cd:
        return True
    else:
        return False
	
