def sweden_id(string):
	digits = re.sub("\D", "", (string)[:-1])
	checksum = int(string[-1:])
	if digits[:1] in ["3", "4", "5", "6", "8"]:
		stripped = [int(x) for x in digits]
		sum_odd = sum(stripped[-1::-2])
		sum_even = sum([sum(divmod(2 * digits, 10)) for digits in stripped[-2::-2]])
		if (sum_odd + sum_even) % 10 == checksum:
			return string
