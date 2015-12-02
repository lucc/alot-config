"""alot hooks file by luc"""


import logging
import re
import subprocess
import sys


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


def pre_search_bclose(ui, **kwargs): bclose_wrapper(ui)
def pre_thread_bclose(ui, **kwargs): bclose_wrapper(ui)
def pre_global_bclose(ui, **kwargs): bclose_wrapper(ui)
def pre_envelope_bclose(ui, **kwargs): bclose_wrapper(ui)
def pre_taglist_bclose(ui, **kwargs): bclose_wrapper(ui)
def pre_bufferlist_bclose(ui, **kwargs): bclose_wrapper(ui)


def bclose_wrapper(ui, **kwargs):
    """Helper function is needed because there is no uniform hook for all
    bclose events.

    :ui: the alot ui instance
    :returns: None

    """
    logging.debug('Calling {} results in {} buffer(s).'.format(
        sys._getframe().f_back.f_code.co_name, len(ui.buffers)))
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
