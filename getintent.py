from urllib.parse import unquote
import re
def find_intent(text):
  if text is None or text=='':
    return ''
  match = re.search(r'\bintent:[^\s]+\b', text)
  if match:
    x= match.group()
    header='intent:'
    x=x[len(header):]
    y = unquote(x)
    return y
  return ''
