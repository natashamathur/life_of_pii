pattern = r'\\bmale\\b | \\bfemale\\b | \\man\\b| \\woman\\b| \\girl\\b| \\boy\\b'

for m in re.finditer(pattern, text.lower()):
  if m:
    print('position {} - {}: {} ({})'.format(m.start(), m.end(), m.group(0).strip(), "gender"))
