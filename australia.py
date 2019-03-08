def australia_tax(n):
  total = 0
  for i in n:
	  total = total + int(i)
	check = total % 11
	if check == 0:
		return n
