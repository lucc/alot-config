# -*- coding: utf-8 -*-

"""alot hooks file by luc"""

from email.utils import getaddresses, parseaddr
from twisted.internet.defer import inlineCallbacks
import alot
import logging
import os
import re
import subprocess


class GPGDatabase():

    """A data storage holding the key ids from the gpg database on disk."""

    def __init__(self, config=None, home=None, capability=None):
        """Initialize the database object with the given config file and
        gnupghome directory.

        :config: the path to the config file
        :home: the path to the gnupg home direcory
        :capability: the capabilities to look for (other keys will not be taken
            into the database)

        """
        self._home = home or os.path.expanduser(os.getenv('GNUPGHOME',
                                                          '~/.gnupg'))
        self._config = config or os.path.join(self._home, 'gpg.conf')
        self._database = os.path.join(self._home, 'pubring.kbx')
        self._capability = capability
        self._cache = {}
        self._timestamp = 0

    def _cache_outdated(self):
        """Check the timestamp to see if the cache is outdated.

        :returns: True or False

        """
        return self._get_timestamp() > self._timestamp

    def _get_timestamp(self):
        """Get the timestamp of the public key database from disk.

        :returns: TODO

        """
        return os.stat(self._database).st_mtime

    def _update(self):
        """Update the cache.

        :returns: None

        """
        if self._cache_outdated():
            self._cache = self._parse()

    def _parse(self):
        """Parse the output from gpg.

        :returns: a dict holding all information of interest

        """
        new_cache = []
        # Initialize the current variable to be able to "find" the first entry.
        current = None
        for line in subprocess.check_output(
                ['gpg', '--list-public-keys', '--with-colons'],
                universal_newlines=True).splitlines():
            # For a description of the fields see doc/DETAILS in the gnupg
            # source.
            fields = line.split(':')
            type = fields[0]
            if type not in ('pub', 'sub', 'uid'):
                continue
            if type == 'pub' or type == 'sub':
                validity = fields[1]
                keyid = fields[4]
                capability = fields[11]
                if type == 'pub':
                    # This is the start of a new main key entry.  Only add it
                    # the last entry to the cache if we are not in the first
                    # for loop iteration.  Also drop entries with no key ids.
                    if current and current['kid']:
                        new_cache.append(current)
                    current = {'uid': [], 'kid': {}}
                # Check validity of the key.
                if not ('m' in validity or 'f' in validity or 'u' in validity):
                    continue
                if self._capability is None:
                    # Accept all keys.
                    current['kid'][keyid] = {'val': validity, 'cap':
                            capability}
                else:
                    for c in self._capability.lower():
                        if c in capability.lower():
                            current['kid'][keyid] = {'val': validity, 'cap':
                                    capability}
                            break
                    else:
                        continue  # with the next line.
            elif type == 'uid':
                userid = fields[9]
                current['uid'].append(userid)
        return new_cache

    def search(self, query):
        """Return a list of key ids and user ids that match the given query.

        :query: a string to search for
        :returns: a list of pairs of strings representing keyid and userid

        """
        self._update()
        for item in self._cache:
            take_item = False
            for kid in item['kid']:
                if query.lower() in kid.lower():
                    take_item = True
                    break
            if take_item:
                yield item
                continue  # with the next item
            for uid in item['uid']:
                if query in uid.lower():
                    break  # out of the inner loop to yield the item
            else:
                continue  # with the next item
            yield item


class AutoEncryptHook():

    """Class to wrap a custom autoencryption hook."""

    gpg_database = GPGDatabase(capability='e')

    @classmethod
    def find_gpg_key(cls, query):
        """Find a gpg key that matches the query."""
        results = cls.gpg_database.search(query)
        for item in results:
            for uid in item['uid']:
                name, address = parseaddr(uid)
                if query.lower() in address.lower():
                    for kid in item['kid']:
                        if 'e' in item['kid'][kid]['cap']:
                            return kid

    @classmethod
    def run_hook(cls, ui, buffer):
        """Enable automatic gpg encryption of mail if possible.

        :ui: the alot user interface
        :buffer: the alot.buffers.EnvelopeBuffer instance
        :returns: None

        """
        envelope = buffer.envelope
        addresses = [addr.lower() for name, addr in getaddresses(
            envelope.get_all('To') + envelope.get_all('Cc') +
            envelope.get_all('Bcc') + envelope.get_all('From'))]
        keys = [cls.find_gpg_key(addr) for addr in addresses]
        if all(keys):
            ui.apply_commandline('encrypt '+' '.join(keys))


def post_buffer_open(ui, dbm, buf):
    """Enable automatic gpg encryption of mail if possible."""
    if isinstance(buf, alot.buffers.EnvelopeBuffer):
        AutoEncryptHook.run_hook(ui, buf)


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


transitions = [
    ('.*grillchill@googlegroups.com.*', 'Lucas <luc.lists@gmail.com>'),
    ('.*tanzhans@googlegroups.com.*', 'Lucas <luc.lists@gmail.com>'),
    ]

addr_trans = []
for addr, fr in transitions:
    addr_trans.append((re.compile("(To|Cc): %s" % addr, re.MULTILINE),
                       "From: %s" % fr))

def pre_edit_translate(bodytext, ui, dbm):
    fromre = re.compile('^From: .*$', re.MULTILINE)
    for addr, new_from in addr_trans:
        if addr.search(bodytext):
            bodytext = re.sub(fromre, new_from,
                              bodytext)
    return bodytext


# warn before sending mail without attachment.  Copied from wiki.
attachments_re = re.compile('(attach|anhang|beigefügt|anhängen|angehängt)',
        re.IGNORECASE)

@inlineCallbacks
def pre_envelope_send(ui, dbm, cmd):
    e = ui.current_buffer.envelope
    if attachments_re.search(e.body) and not e.attachments:
        msg = 'no attachments. send anyway?'
        if not (yield ui.choice(msg, select='yes')) == 'yes':
            raise Exception()
