import re

# https://www.ssa.gov/employer/ssns/HGJune2411_final.txt
# ssn 001 - 772

sample = 'fake ssn 775329234 3 castle hill close'

x = re.findall('[0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9][0-9]', sample)
if len(x) > 0:
    t = x[0][:3]
    if int(t) < 772:
        print(x, "valid")
    else:
        print(x, "not valid")

y = re.findall('[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]', sample)
if len(y) > 0:
    q = y[0][:3]
    if int(q) < 772:
        print(q, "valid")
    else:
        print(q, "not valid")


add_end = ['road', 'street', 'avenue', 'boulevard', 'lane', 'drive', 'way',
           'court', 'plaza', 'terrace', 'close']

s = sample.split(" ")
for i in range(1, len(s)):
    if s[i] in add_end:
        for a in range(5):
            t =s[i-a:i+1]
            if t[0].isdigit():
                print(' '.join(t))
                break;
    

