"""alot hooks file by luc"""


import re


def reply_subject(subject):
    """Format the subject for a reply message.

    :subject: the original subject line
    :returns: the formatted subject line

    """
    return 'Re: ' + strip_subject(subject, 're', 'aw')


def forward_subject(subject):
    """Format the subject for a forwarded message.

    :subject: the original subject line
    :returns: the formatted subject line

    """
    return 'Fwd: ' + strip_subject(subject, 'fwd', 'wg')


def strip_subject(subject, *prefixes):
    """Strip a list of prefix strings from a subject line.

    :subject: the subject line
    :prefixes: a list of prefixes to strip
    :returns: the striped subject line

    """
    return re.sub(r'^(\s*('+'|'.join(prefixes)+r'):\s)*', '', subject,
                  flags=re.IGNORECASE).strip()
