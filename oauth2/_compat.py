try:
    TEXT = unicode
except NameError: #pragma NO COVER Py3k
    TEXT = str
    STRING_TYPES = (str, bytes)
else:
    STRING_TYPES = (unicode, bytes)

def u(x, encoding='ascii'):
    if isinstance(x, TEXT):
        return x
    try:
        return x.decode(encoding)
    except AttributeError:
        raise ValueError('WTF: %s' % x)
