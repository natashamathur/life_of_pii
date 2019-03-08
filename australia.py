def australia_tax(n):
  total = 0
  for i in n:
	  total = total + int(i)
	check = total % 11
	if check == 0:
		return n
	
def australia_medicare(n):
	checksum_weights = [1,3,7,9,1,3,7,9]
	total= 0
	for i in range(8):
		total = int(n[i]) * checksum_weights[i]
	cs = total % 10
	if cs == n[8]:
		return n
