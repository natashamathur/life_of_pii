import re

def check_email(email):
	email_string = re.search("^[\.'\a-z0-9_]*[a-z0-9]+[\.'\a-z0-9_]*[a-z0-9]+@[a-z0-9]+\.(com|edu|gov|org)$", email)
	if email_string:
		return email_string.string
	else:
		return None
