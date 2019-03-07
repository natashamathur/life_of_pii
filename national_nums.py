#argentina = 9 digits, starts with 20, 23 for males, 27 for female
#japan = 12 digits
#koren = 13 digits, first 6 YYMMDD, 2 for females 3 for males, 6 random
#norwegian = 11 digits, first 6 DDMMYY, 000–499 includes persons born in the period 1900–1999.
    #500–749 includes persons born in the period 1854–1899.
    #500–999 includes persons born in the period 2000–2039.
    #900–999 includes persons born in the period 1940–1999.
    #The last two digits of the social security number are called control digits and are calculated from the previous digits.

norway_num = '0824199490432'
def check_nw(num):
    if len(num) == 11:
        if int(num[0:2]) < 31:
            print("maybe")


print(check_nw(norway_num))
