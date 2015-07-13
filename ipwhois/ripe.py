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
    except KeyError:
        raise ValueError("Malformed error. Missing objects->object.")

    if len(d) > 1:
        raise ValueError("More than one object passed.")

    ret = []
    for a in d[0]['attributes']['attribute']:
        if 'name' not in a:
            raise ValueError("Malformed RIPE entry: missing name.")

        if a['name'] == name:
            ret.append(a['value'])

    return '\n'.join(ret)

def resolve_abuse(iw, nets):
    ripe_abuse_emails = []
    # Resolve abuse-c entries and flatten the list.
    nets_with_abuse_ref = [net_['abuse-c'] for net_ in nets if 'abuse-c' in net_]
    nets_with_abuse_ref = [link_
                           for n_ in nets_with_abuse_ref
                           for link_ in n_
                           if link_ and link_.startswith('http')]
    for link in nets_with_abuse_ref:
        abuse_c = iw.get_rws(link)
        ripe_abuse_emails.append(get_attribute(abuse_c, 'abuse-mailbox'))

    return ripe_abuse_emails