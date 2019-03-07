#AUSTRALIA_MEDICARE_NUMBER = 11 digits, First digit should be in the range 2-6 https://clearwater.com.au/code/medicare
#AUSTRALIA_TAX_FILE_NUMBER = 9 digits, checksum divisible by 11
#BRAZILIAN_CPF_NUMBER https://gist.github.com/gorork/4c3a04d0dcf0c50b958a
#GERMAN_PASSPORT Passport number (9 alphanumeric digits, chosen from numerals 0–9 and letters C, F, G, H, J, K, L, M, N, P, R, T, V, W, X, Y, Z. Thus, "0" denotes the numeral, not the letter "O".)

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
