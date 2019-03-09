def south_korea_id(string):
    string = re.sub('[-]', '', string)
    checksum = string[-1:]
    mults = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5]
    total = 0
    for x in range(0, 12):
        total += int(string[x]) * mults[x]
    
    remainder = (11 - total % 11) % 10
    if remainder == int(checksum):
        return string[0:6] + "-" + string[7:13]
