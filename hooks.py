"""alot hooks file by luc"""


import logging
import re
import subprocess


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


def post_global_bclose(ui, **kwarg):
    logging.debug('post_global_bclose() results in {} buffer(s).'.format(
        len(ui.buffers)))


def pre_global_bclose(ui, **kwargs):
    """Check if the last buffer is beeing closed and update the awesome mail
    widget in case it is.

    :ui: the alot ui instance
    :returns: None

    """
    logging.debug('pre_global_bclose() results in {} buffer(s).'.format(
        len(ui.buffers)))
    if len(ui.buffers) == 1:
        update_awesome_mail_widget()


def update_awesome_mail_widget():
    """Force awesome WM to update the mail widget to see changes in the inbox
    state.

    :returns: None

    """
    p = subprocess.Popen(['awesome-client'], stdin=subprocess.PIPE)
    p.communicate(
        'require("vicious").force({require("widgets/notmuch").widget})')
