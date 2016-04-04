# Copyright (c) 2013, 2014, 2015, 2016 Philip Hane
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

# TODO: Add '_links' for RFC/other references

HR_ASN = {
    'asn': {
        '_short': 'ASN',
        '_name': 'Autonomous System Number',
        '_description': 'Globally unique identifier used for routing '
                        'information exchange with Autonomous Systems.'
    },
    'asn_cidr': {
        '_short': 'ASN CIDR Block',
        '_name': 'ASN Classless Inter-Domain Routing Block',
        '_description': 'Network routing block assigned to an ASN.'
    },
    'asn_country_code': {
        '_short': 'ASN Country Code',
        '_name': 'ASN Assigned Country Code',
        '_description': 'ASN assigned country code in ISO 3166-1 format.'
    },
    'asn_date': {
        '_short': 'ASN Date',
        '_name': 'ASN Allocation Date',
        '_description': 'ASN allocation date in ISO 8601 format.'
    },
    'asn_registry': {
        '_short': 'ASN Registry',
        '_name': 'ASN Assigned Registry',
        '_description': 'ASN assigned regional internet registry.'
    }
}

HR_RDAP_COMMON = {
    'events': {
        '_short': 'Event',
        '_name': 'Event',
        '_description': 'An event for an RIR object.',
        'action': {
            '_short': 'Action',
            '_name': 'Event Action (Reason)',
            '_description': 'The reason for an event.'
        },
        'timestamp': {
            '_short': 'Timestamp',
            '_name': 'Event Timestamp',
            '_description': 'The date an event occured in ISO 8601 '
                            'format.'
        },
        'actor': {
            '_short': 'Actor',
            '_name': 'Event Actor',
            '_description': 'The identifier for an event initiator.'
        }
    },
    'notices': {
        '_short': 'Notice',
        '_name': 'Notice',
        '_description': 'A notice for an RIR object.',
        'description': {
            '_short': 'Description',
            '_name': 'Notice Description',
            '_description': 'The description/body of a notice.'
        },
        'title': {
            '_short': 'Title',
            '_name': 'Notice Title',
            '_description': 'The title/header for a notice.'
        }
    },
    'remarks': {
        '_short': 'Remark',
        '_name': 'Remark',
        '_description': 'A remark for an RIR object.',
        'description': {
            '_short': 'Description',
            '_name': 'Remark Description',
            '_description': 'The description/body of a remark.'
        },
        'title': {
            '_short': 'Title',
            '_name': 'Remark Title',
            '_description': 'The title/header for a remark.'
        }
    }
}

HR_RDAP = {
    'network': {
        '_short': 'Network',
        '_name': 'RIR Network',
        '_description': 'The assigned network for an IP address.',
        'cidr': {
            '_short': 'CIDR Block',
            '_name': 'Classless Inter-Domain Routing Block',
            '_description': 'Network routing block an IP address belongs to.'
        },
        'country': {
            '_short': 'Country Code',
            '_name': 'Country Code',
            '_description': 'Country code registered with the RIR in '
                            'ISO 3166-1 format.'
        },
        'end_address': {
            '_short': 'End Address',
            '_name': 'Ending IP Address',
            '_description': 'The last IP address in a network block.'
        },
        'events': HR_RDAP_COMMON['events'],
        'handle': {
            '_short': 'Handle',
            '_name': 'RIR Handle',
            '_description': 'Unique identifier for a registered network.'
        },
        'ip_version': {
            '_short': 'IP Version',
            '_name': 'IP Protocol Version',
            '_description': 'The IP protocol version (v4 or v6) of an IP '
                            'address.'
        },
        'name': {
            '_short': 'Name',
            '_name': 'Network Name',
            '_description': 'The identifier assigned to the network '
                            'registration for an IP address.'
        },
        'notices': HR_RDAP_COMMON['notices'],
        'parent_handle': {
            '_short': 'Parent Handle',
            '_name': 'RIR Parent Handle',
            '_description': 'Unique identifier for the parent network of '
                            'a registered network.'
        },
        'remarks': HR_RDAP_COMMON['remarks'],
        'start_address': {
            '_short': 'Start Address',
            '_name': 'Starting IP Address',
            '_description': 'The first IP address in a network block.'
        },
        'status': {
            '_short': 'Status',
            '_name': 'Network Status',
            '_description': 'List indicating the state of a registered '
                            'network.'
        },
        'type': {
            '_short': 'Type',
            '_name': 'RIR Network Type',
            '_description': 'The RIR classification of a registered network.'
        }
    },
    'entities': {
        '_short': 'Entities',
        '_name': 'RIR Entities',
        '_description': 'List of object names referenced by an RIR network.'
    },
    'objects': {
        '_short': 'Object',
        '_name': 'RIR Object',
        '_description': 'The objects (entities) referenced by an RIR network.',
        'contact': {
            '_short': 'Contact',
            '_name': 'Contact Information',
            '_description': 'Contact information registered with an RIR '
                            'object.',
            'address': {
                '_short': 'Address',
                '_name': 'Postal Address',
                '_description': 'The contact postal address.'
            },
            'email': {
                '_short': 'Email',
                '_name': 'Email Address',
                '_description': 'The contact email address.'
            },
            'kind': {
                '_short': 'Kind',
                '_name': 'Kind',
                '_description': 'The contact information kind (individual, '
                                'group, org, etc).'
            },
            'name': {
                '_short': 'Name',
                '_name': 'Name',
                '_description': 'The contact name.'
            },
            'phone': {
                '_short': 'Phone',
                '_name': 'Phone Number',
                '_description': 'The contact phone number.'
            },
            'role': {
                '_short': 'Role',
                '_name': 'Role',
                '_description': 'The contact\'s role.'
            },
            'title': {
                '_short': 'Title',
                '_name': 'Title',
                '_description': 'The contact\'s position or job title.'
            }
        },
        'entities': {
            '_short': 'Entities',
            '_name': 'RIR Object Entities',
            '_description': 'List of object names referenced by an RIR object.'
        },
        'events': HR_RDAP_COMMON['events'],
        'event_actor': {
            '_short': 'Event',
            '_name': 'Event w/o Actor',
            '_description': 'An event for an RIR object with no event actor.',
            'action': {
                '_short': 'Action',
                '_name': 'Event Action (Reason)',
                '_description': 'The reason for an event.'
            },
            'timestamp': {
                '_short': 'Timestamp',
                '_name': 'Event Timestamp',
                '_description': 'The date an event occured in ISO 8601 '
                'format.'
            }
        },
        'handle': {
            '_short': 'Handle',
            '_name': 'RIR Object Handle',
            '_description': 'Unique identifier for a registered object.'
        },
        'notices': HR_RDAP_COMMON['notices'],
        'remarks': HR_RDAP_COMMON['remarks'],
        'roles': {
            '_short': 'Roles',
            '_name': 'Roles',
            '_description': 'List of roles assigned to a registered object.'
        },
        'status': {
            '_short': 'Status',
            '_name': 'Object Status',
            '_description': 'List indicating the state of a registered '
                            'object.'
        }
    }
}
