import re

def credit_card_number(cc):

    match = re.fullmatch("^[0-9]{1,5}[-|,|_]?[0-9]{1,5}[-|,]?[0-9]{1,5}[-|,]?[0-9]{1,5}[-|,]?", cc)
    if match:
        digits = re.sub("\D", "", match.string)
        if digits[:1] in ["3", "4", "5", "6", "8"]:
            if len(digits) >= 12 and len(digits) <= 19:
                stripped = [int(x) for x in digits]

                sum_odd = sum(stripped[-1::-2])
                sum_even = sum([sum(divmod(2 * digits, 10)) for digits in stripped[-2::-2]])

                if (sum_odd + sum_even) % 10 == 0:
                    return digits
                else:
                    return None
            else:
                return None
        else:
            return None
    else:
        return match

