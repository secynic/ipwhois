"""
RIPE associated functions.
"""
__author__ = 'roberto.polli@par-tec.it'


def get_attribute(entry, name):
    """Parses RIPE entries eg. role, person, ...
    :param entry: a RIPE entry.
    :param name: a valid attribute name, eg. abuse-mailbox.
    :return the attribute value or None.
    """
    try:
        d = entry['objects']['object']
        if len(d) > 1:
            raise ValueError("More than one object passed.")
        d = d[0]['attributes']['attribute']
    except KeyError as e:
        raise ValueError("Malformed RIPE entry. Missing key %r", e.message)

    # I didn't use a generator to be able to
    #  raise a ValueError.
    ret = []
    for a in d:
        if 'name' not in a:
            raise ValueError("Malformed RIPE entry: missing name.")

        if a['name'] == name:
            ret.append(a['value'])

    return '\n'.join(ret)
