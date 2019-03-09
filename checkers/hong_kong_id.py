def hong_kong_id(string):
    string = re.sub('[()]', '', string)
    checksum = string [-1:]
    string = string [:-1]
    mults = [9, 8, 7, 6, 5, 4, 3, 2]
    total = 0
    length = len(string)
    if length:
        for x in range(0, 2):
            total += ((ord(string[x]) - 55) * mults[x])
        for y in range(2, 8):
            total += (int(string[y]) * mults[y])
    elif length:
        total += 36*9
        total += (ord(string[0]) - 55) * mults[1]
        for y in range(1, 7):
            total += int(string[y]) * mults[y + 1]
    remainder = total % 11
    if remainder != 0:
        if remainder == 1:
            remainder = "A"
        else:
            remainder = 11 - remainder
    if remainder == int(checksum):
        return string + "(" + checksum + ")"
