#! /usr/bin/env python

"""Git Fusion submit triggers.

    These triggers coordinate with Git Fusion to support git atomic pushes.
    User Reviews are used to contain list of locked files per GitFusion instance
    and another user for non-gitFusion users.
    Compatible with python version 2.x >= 2.6 and >= 3.3
"""
                        # pylint:disable=W9903
                        # Skip localization/translation warnings about config strings
                        # here at the top of the file.

# -- Configuration ------------------------------------------------------------
# Edit these constants to match your P4D server and environment.

CHARSET = []
# For unicode servers uncomment the following line
#CHARSET = ['-C', 'utf8']

# Set to the location of the p4 binary.
# When in doubt, change this to an absolute path.
P4GF_P4_BINARY = "p4"

# For Windows systems use no spaces in the p4.exe path
#P4GF_P4_BINARY = "C:\PROGRA~1\Perforce\p4.exe"
# -----------------------------------------------------------------------------


import sys

# Determine python version
PYTHON3 = True
if sys.hexversion < 0x03000000:
    PYTHON3 = False

# For triggers, sys.exit(CODE)
P4PASS = 0
P4FAIL = 1
KEY_VIEW = 'view'

# Import the configparser - either from python2 or python3
# pylint:disable=F0401
# Unable to import
# pylint:disable=C0103
# Invalid class name
try:
    # python3.x import
    import configparser
    PARSING_ERROR = configparser.ParsingError
except ImportError:
    # python2.x import
    import cStringIO
    import ConfigParser
    PARSING_ERROR = ConfigParser.ParsingError
# pylint:enable=C0103
# pylint:enable=F0401

P4GF_USER = "git-fusion-user"

# Permit Git Fusion to operate without engaging its own triggers.
# Triggers are to be applied only to non P4GF_USERS.
# With one exception: apply the change-commit trigger defined for p4gf_config files.
# Git Fusion edits the p4gf_config files.
#
if (len(sys.argv) >= 4
     and sys.argv[3] == P4GF_USER
     and sys.argv[1] != "change-commit-p4gf-config"):
    sys.exit(P4PASS)   # continue the submit but skip the trigger for GF

# these imports here to avoid unneeded processing before the early exit test above

import os
import re
from   subprocess import Popen, PIPE
import marshal
import time
import datetime
import tempfile
import calendar
import getopt

                        # Optional localization/translation support.
                        # If the rest of Git Fusion's bin folder
                        # was copied along with this file p4gf_submit_trigger.py,
                        # then this block loads LC_MESSAGES .mo files
                        # to support languages other than US English.
try:
    from p4gf_l10n import _, NTR
except ImportError:
                        # pylint:disable=C0103
                        # Invalid name NTR()
    def NTR(x):
        '''No-TRanslate: Localization marker for string constants.'''
        return x
    _ = NTR
                        # pylint:enable=C0103
                        # pylint:enable=W9903


# Find the 'p4' command line tool.
# If this fails, edit P4GF_P4_BINARY in the "Configuration"
# block at the top of this file.

import distutils.spawn
P4GF_P4_BIN = distutils.spawn.find_executable(P4GF_P4_BINARY)
if not P4GF_P4_BIN:
    print(_("Git Fusion Submit Trigger cannot find p4 binary: '{0}'"
            "\nPlease update this trigger using the full path to p4").
                    format(P4GF_P4_BINARY))
    sys.exit(P4FAIL) # Cannot find the binary

# disallow SPACE in path name
if ' ' in P4GF_P4_BIN:
    print(_("Please edit p4gf_submit_trigger.py and set P4GF_P4_BIN to a path without spaces."))
    sys.exit(P4FAIL) # Space in binary path

# -----------------------------------------------------------------------------
#                 Begin block copied to both p4gf_const.py
#                 and p4gf_submit_trigger.py.
#
# Normal usage of Git Fusion should not require changing of the
# P4GF_DEPOT constant. If a site requires a different depot name
# then set this constant on ALL Git Fusion instances to the same
# depot name.
#
# This depot should be created by hand prior to running any Git
# Fusion instance. Wildcard and revision characters are not
# allowed in depot names (*, ..., @, #) and non-alphanumberic
# should typically be avoided.

P4GF_DEPOT         = NTR('.git-fusion')

#
#                 End block copied to both p4gf_const.py
#                 and p4gf_submit_trigger.py.
# -----------------------------------------------------------------------------

# second block

# -----------------------------------------------------------------------------
#                 Begin block copied to both p4gf_const.py
#                 and p4gf_submit_trigger.py.
#
# Atomic Push
#
# Atomic view locking requires special counters and users to insert Reviews into
# the user spec Each Git Fusion server has its own lock.
#
P4GF_REVIEWS_GF                     = NTR('git-fusion-reviews-') # Append GF server_id.
P4GF_REVIEWS__NON_GF                = P4GF_REVIEWS_GF + NTR('-non-gf')
P4GF_REVIEWS__ALL_GF                = P4GF_REVIEWS_GF + NTR('-all-gf')
P4GF_REVIEWS_NON_GF_SUBMIT          = NTR('git-fusion-non-gf-submit-')
P4GF_REVIEWS_NON_GF_POPULATE        = NTR('git-fusion-non-gf-populate-')
P4GF_REVIEWS_NON_GF_RESET           = NTR('git-fusion-non-gf-')
DEBUG_P4GF_REVIEWS__NON_GF          = NTR('DEBUG-') + P4GF_REVIEWS__NON_GF
DEBUG_SKIP_P4GF_REVIEWS__NON_GF     = NTR('DEBUG-SKIP-') + P4GF_REVIEWS__NON_GF
P4GF_REVIEWS_SERVICEUSER            = P4GF_REVIEWS_GF + '{0}'

# Is the Atomic Push submit trigger installed and at the correct version?
#
P4GF_COUNTER_PRE_TRIGGER_VERSION    = NTR('git-fusion-pre-submit-trigger-version')
P4GF_COUNTER_POST_TRIGGER_VERSION   = NTR('git-fusion-post-submit-trigger-version')
P4GF_TRIGGER_VERSION                = NTR('00003')

#
#                 End block copied to both p4gf_const.py
#                 and p4gf_submit_trigger.py.
# -----------------------------------------------------------------------------

P4GF_HEARTBEATS             = "git-fusion-view-*-lock-heartbeat"
HEARTBEAT_TIMEOUT_SECS      = 60

# Value for counter P4GF_REVIEWS_NON_GF_SUBMIT when submit trigger decided this
# changelist requires no further processing by this trigger.
#
# Value must not be a legal depot path. Lack of leading // works.
#
DECIDED_TO_SKIP             = NTR('skip')

TRIGGER_TYPES = ['change-submit', 'change-commit',
                 'change-content', 'change-commit-p4gf-config']
# Messages for human users.
# Complete sentences.
# Except for trigger spec, hardwrap to 78 columns max, 72 columns preferred.
MSG_LOCKED_BY_GF            = _("\nFiles in the changelist are locked by Git Fusion user '{0}'.")
MSG_PRE_SUBMIT_FAILED       = _("Git Fusion pre-submit trigger failed.")
MSG_POST_SUBMIT_FAILED      = _("Git Fusion post-submit trigger failed.")
MSG_TRIGGER_FAILED          = _("\nGit Fusion '{0}' trigger failed: {1}")
MSG_ARGS                    = _("user: '{0}' changelist: {1}")
MSG_MISSING_ARGS            = _("Git Fusion trigger missing arguments.")
MSG_TRIGGER_FILENAME        = _("p4gf_submit_trigger.py")
MSG_MALFORMED_CONFIG        = _("p4gf_config file submitted, but will not work for Git Fusion.")
# pylint: disable = C0301,W1401
# Line too long;  Anomalous backslash in string
TRIGGER_PARAMETERS          = NTR('trigger-type %changelist% %user% %client% %serverport% [%oldchangelist%]')
TRIGGER_PARAMETERS_13_2     = NTR('trigger-type %changelist% %user% %client% %serverport% [%oldchangelist%] %serverid% %peerhost% %clienthost%')
MSG_TRIGGER_SPEC = NTR("""
    GF-pre-submit         change-submit  //...                       "/path/to/python /path/to/p4gf_submit_trigger.py change-submit             %changelist% %user% %client% %serverport%"
    GF-post-submit        change-commit  //...                       "/path/to/python /path/to/p4gf_submit_trigger.py change-commit             %changelist% %user% %client% %serverport% %oldchangelist%"
    GF-chg-submit         change-content //...                       "/path/to/python /path/to/p4gf_submit_trigger.py change-content            %changelist% %user% %client% %serverport%"
    GF-post-submit-config change-commit  //""" + P4GF_DEPOT +"""/repos/*/p4gf_config "/path/to/python /path/to/p4gf_submit_trigger.py change-commit-p4gf-config %changelist% %user% %client% %serverport% %oldchangelist%"
""")
MSG_EXAMPLE_UNIX = NTR('python p4gf_submit_trigger.py --generate-trigger-entries "/absolute/pathto/python" "/absolute/pathto/p4gf_submit_trigger.py"')
MSG_EXAMPLE_DOS  = NTR('python p4gf_submit_trigger.py --generate-trigger-entries "C:\\absolute\\pathto\\python" "C:\\absolute\\pathto\\p4gf_submit_trigger.py"')
MSG_USAGE = _("""

    Git Fusion requires a submit trigger to be installed on your Perforce server
    to properly support atomic commits from Git.

    Installing Triggers
    -------------------
    Install triggers for each Perforce server configured for Git Fusion:

    1) Copy 'p4gf_submit_trigger.py' to your Perforce server machine.
    2) These triggers require Python 2.6+ or Python 3.2+ on the
       Perforce server machine.
    3) (optional) If '/usr/bin/env python' is not a path to Python on
       the Perforce server machine, edit the top line of
       'p4gf_submit_trigger.py' to a path that works.
    4) As a Perforce super user run 'p4 triggers' and add the
       following entries:
       (See --generate-trigger-entries option below to generate
        trigger entries.)
{MSG_TRIGGER_SPEC}

    Logging in Perforce users
    -------------------------
    p4gf_super_init.py on the Git Fusion server creates these users:
        git-fusion-user
        git-fusion-reviews-<server-id>
        git-fusion-reviews--non-gf
        git-fusion-reviews--all-gf

    After running p4gf_super_init.py, you must log these users into the
    Perforce server:

    1) Set a password with 'p4 passwd'
    2) Log that user in with 'p4 login':
        - from the Git Fusion unix account on the Git Fusion server.
        - from the OS account on the Perforce server where the
          triggers run.

    Installing This Trigger
    -----------------------
    To generate a sample text file suitable for use as a 'p4 triggers' spec:

        {MSG_EXAMPLE_UNIX}

        (for Windows):
        {MSG_EXAMPLE_DOS}

    Copy the output into the 'p4 trigger' spec.

    Tell Git Fusion that Triggers Are Installed
    -------------------------------------------
    To tell Git Fusion that these triggers are installed, and
    thus avoid 'triggers are not installed' or 'triggers need updating'
    error messages:

        python p4gf_submit_trigger.py --set-version-counter P4PORT

    Clearing Locks
    --------------
    To clear any locks created by previous runs of this trigger:

        python p4gf_submit_trigger.py --reset P4PORT [superuser]

    This removes all 'p4 reviews' and 'p4 counters -u' data stored
    by this trigger.

    Defining Depot Paths Managed by Git Fusion
    ------------------------------------------
    To rebuild the list of Perforce depot paths currently part of any
    Git Fusion repo:

        python p4gf_submit_trigger.py --rebuild-all-gf-reviews P4PORT [superuser]

    By default this command runs as Perforce user 'git-fusion-reviews--all-gf'.
    The optional superuser parameter must be a Perforce super user.


""").format( MSG_TRIGGER_SPEC = MSG_TRIGGER_SPEC
           , MSG_EXAMPLE_UNIX = MSG_EXAMPLE_UNIX
           , MSG_EXAMPLE_DOS  = MSG_EXAMPLE_DOS )
# pylint: enable = C0301,W1401


# time.sleep() accepts a float, which is how you get sub-second sleep durations.
MS = 1.0 / 1000.0

# How often we retry to acquire the lock.
_RETRY_PERIOD = 100 * MS

# By default P4PORT is set from the p4d trigger %serverport% argument.
# Admins optionally may override the %serverport% by setting P4PORT here to a non-empty string.
P4PORT = None
SEPARATOR  = '...'

# Valid fields when updating the user spec
USER_FIELDS = NTR(['User', 'Type', 'Email', 'Update', 'Access',
    'FullName', 'JobView', 'Password', 'Reviews'])

# regex
LR_SEPARATOR       = re.compile(r'(.*?)([\t ]+)(.*)')
QUOTE_PLUS_WHITE   = re.compile(r'(.*[^"]+)("[\t ]+)(.*)')
# Edit these as needed for non-English p4d error messages
NOLOGIN_REGEX         = re.compile(r'Perforce password \(P4PASSWD\) invalid or unset')
CONNECT_REGEX         = re.compile(r'.*TCP connect to.*failed.*')
CHANGE_UNKNOWN_REGEX  = re.compile(r'Change \d+ unknown')

# values for "action" argument to update_reviews()
ACTION_REMOVE = NTR('remove')
ACTION_RESET  = NTR('reset')
ACTION_UNSET  = NTR('unset')
ACTION_ADD    = NTR('add')

def mini_usage(invalid=False):
    """Argumment help"""
    _usage = ''
    if (invalid):
                        # Newline moved out to make l10n.t script easier.
        _usage += _("Unrecognized or invalid arguments.") + "\n"
                        # pylint:disable=W9904
                        # quotation marks part of command line syntax, required.
    _usage += _("""
Usage:
    p4gf_submit_trigger.py --generate-trigger-entries "/absolute/pathto/python" "/absolute/pathto/p4gf_submit_trigger.py"
    p4gf_submit_trigger.py --set-version-counter P4PORT
    p4gf_submit_trigger.py --reset P4PORT [superuser]
    p4gf_submit_trigger.py --rebuild-all-gf-reviews P4PORT [superuser]
    p4gf_submit_trigger.py --help
""")
                        # pylint:enable=W9904
    print(_usage)
    if (invalid):
        print(_("    args: {0}").format(sys.argv))

def p4d_or_later(required):
    '''Check for required p4d version.'''
    version = p4d_version_string()
    if not version:
        return False
    version = version.split('/')
    m = re.search(r'^(\d+\.\d+)', version[2])
    return m.group(1) >= required



def p4d_version_string():
    '''
    Return the serverVersion string from 'p4 info':

    P4D/LINUX26X86_64/2012.2.PREP-TEST_ONLY/506265 (2012/08/07)
    '''
    r = p4_run(['info'])
    key = 'serverVersion'
    for e in r:
        if isinstance(e, dict) and key in e:
            return e[key]
    return None

# pylint: disable=E1101
# has no member
def generate_trigger_entries(path_to_python, path_to_trigger):
    '''Display Git Fusion trigger entries for local paths'''

    global MSG_TRIGGER_SPEC
#    if P4PORT:
#        req = "2014.1"
#        print("p4d >= {0} : {1}".format(req, p4d_or_later(req)))

    MSG_TRIGGER_SPEC = MSG_TRIGGER_SPEC.replace(
        '/path/to/' + MSG_TRIGGER_FILENAME, path_to_trigger)
    MSG_TRIGGER_SPEC = MSG_TRIGGER_SPEC.replace(
        '/path/to/python', path_to_python)
    print(MSG_TRIGGER_SPEC)

def usage():
    '''Display full usage.'''
    print (MSG_USAGE)


class TriggerContext:
    """TriggerContext class for the change-content trigger.

    Used for p4 submit, p4 submit -e, p4 populate.
    """

    def __init__(self, is_submit, change, client):
        self.is_submit = is_submit
        self.change = change
        self.client = client

        self.cfiles  = None          # depot files from current change
        self.reviews_file = None     # tmp file used to pass cfiles to p4 reviews for populate
        self.is_locked = False
        self.is_in_union = False
        self.countername = get_trigger_countername(change, is_submit=is_submit)

    def check_if_locked_by_review(self):
        '''Call the proper methods to check if GF has a lock on these submitted files.'''
        if self.is_submit:
            # For p4 submit,  'reviews -C -c' does not require the list of changelist files.
            # But there is a catch for its use with shelves submitted with 'p4 submit -e'.
            # For submiting shelves p4d creates a temporary client and
            # sets the client name = changelist number.
            # The %client% trigger parameter should be set to the changelist - but it is not.
            # Git Fusion lock detection must cover the shelf possibility by calling reviews twice.
            # First check using the passed %client% name - valid for the non-shelf submit.
            # If no lock is detected, call again setting client=change to check for
            # a potential shelf submit

            # First check as a non-shelf submit
            self.is_locked, self.is_in_union =  submit_is_locked_by_review(self.change, self.client)
            if not (self.is_locked or self.is_in_union):
                # No lock - so check for potential 'p4 submit -e' by setting client=change
                self.is_locked, self.is_in_union = \
                    submit_is_locked_by_review(self.change, self.change)
        else:
            # For populate, 'reviews' requires the list of changelist files
            # which is saved in file 'reviews_file' and passed as a file argument.
            # The file is preserved for a second reviews call after adding
            # the file list to the git-fusion-reviews--non-gf user.
            self.get_cfiles()
            self.is_locked, self.reviews_file, self.is_in_union = \
                populate_is_locked_by_review(self.cfiles, self.reviews_file)

    def get_cfiles(self):
        ''' Lazy load of files from changelist.'''
        if not self.cfiles:
            self.cfiles = p4_files_at_change(self.change)
        return self.cfiles

    def cleanup(self):
        '''Remove the reviews_file which exist only in the populate case.'''

        # remove the input file to 'p4 -x file reviews'
        if self.reviews_file:
            remove_file(self.reviews_file)


def gf_reviews_user_name_list():
    '''
    Return a list of service user names that match our per-server reviews user.
    '''
    expr = P4GF_REVIEWS_SERVICEUSER.format('*')
    r = p4_run(['users', '-a', expr])
    result = []
    for rr in r:
        if isinstance(rr, dict) and 'User' in rr:
            result.append(rr['User'])
    return result


def p4_write_data(cmd, data, stdout=None):
    """ Execute command with data passed to stdin"""
    cmd = [P4GF_P4_BIN, "-p", P4PORT] + CHARSET + cmd
    process = Popen(cmd, bufsize=-1, stdin=PIPE, shell=False, stdout=stdout)
    pipe = process.stdin
    val = pipe.write(data)
    pipe.close()
    if not stdout is None:
        pipe = process.stdout
        pipe.read()
    if process.wait():
        raise Exception(_('Command failed: %s') % str(cmd))
    return val


def _encoding_list():
    """
    Return a list of character encodings, in preferred order,
    to use when attempting to read bytes of unknown encoding.
    """
    return ['utf8', 'latin_1', 'shift_jis']


def encode(data):
    """
    Attempt to encode using one of several code encodings.
    """

    if not PYTHON3:
        return data

    for encoding in _encoding_list():
        try:
            s = data.encode(encoding)
            return s
        except UnicodeEncodeError:
            pass
        except Exception as e:
            print(str(e))
    # Give up, re-create and raise the first error.
    data.encode(_encoding_list[0])


def decode(bites):
    """
    Attempt to decode using one of several code pages.
    """
    for encoding in _encoding_list():
        try:
            s = bites.decode(encoding)
            return s
        except UnicodeDecodeError:
            pass
        except Exception as e:
            print(str(e))
    # Give up, re-create and raise the first error.
    bites.decode(_encoding_list[0])


def _convert_bytes(data):
    """
    For python3, convert the keys in maps from bytes to strings. Recurses through
    the data structure, processing all lists and maps. Returns a new
    object of the same type as the argument. Any value with a decode()
    method will be converted to a string.
    For python2 - return data
    """
    def _maybe_decode(key):
        """
        Convert the key to a string using its decode() method, if
        available, otherwise return the key as-is.
        """
        return decode(key) if 'decode' in dir(key) else key

    if not PYTHON3:
        return data

    if isinstance(data, dict):
        newdata = dict()
        for k, v in data.items():
            newdata[_maybe_decode(k)] = _convert_bytes(v)
    elif isinstance(data, list):
        newdata = [_convert_bytes(d) for d in data]
    else:
        # convert the values, too
        newdata = _maybe_decode(data)
    return newdata


def p4_print(depot_path):
    """Accumulate multiple 'data' entries to assemble content
    from p4 print
    """

    result = p4_run(['print', '-q', depot_path])
    contents = ''
    for item in result:
        if 'data' in item and item['data']:
            contents += item['data']
    return contents


_unicode_error = [{'generic': 36,
                   'code': NTR('error'),
                   'data': _('Unicode server permits only unicode enabled clients.\n'),
                   'severity': 3}]

# pylint: disable=R0912
# Too many branches
def p4_run(cmd, stdin=None, user=P4GF_USER):
    """Use the -G option to return a list of dictionaries."""
    raw_cmd = cmd
    global CHARSET
    while True:
        cmd = [P4GF_P4_BIN, "-p", P4PORT, "-u", user, "-G"] + CHARSET + raw_cmd
        try:
            process = Popen(cmd, shell=False, stdin=stdin, stdout=PIPE, stderr=PIPE)
        except (OSError, ValueError) as e:
            print(_("Error calling Popen with cmd: {0}").format(cmd))
            print(_("Error: {0}").format(e))
            sys.stdout.flush()
            sys.exit(1)

        data = []
        try:
            while True:
                data.append(marshal.load(process.stdout))
        except EOFError:
            pass
        ret = process.wait()
        if data:
            data = _convert_bytes(data)
        if ret != 0:
            # check for unicode error:
            if (not CHARSET) and (not stdin) and data == _unicode_error:
                #set charset and retry
                CHARSET = ['-C', 'utf8']
                continue

            else:
                error = process.stderr.read().splitlines()
                if error and len(error) > 1:
                    for err in error:
                        if CONNECT_REGEX.match(_convert_bytes(err)):
                            print (_("Cannot connect to P4PORT: {0}").format(P4PORT))
                            sys.stdout.flush()
                            # pylint: disable=W0212
                            os._exit(P4FAIL)
                            # pylint: enable=W0212
            data.append({"Error": ret})
        break
    # data = _convert_bytes(data)
    if len(data) and 'code' in data[0] and data[0]['code'] == 'error':
        if NOLOGIN_REGEX.match(data[0]['data']):
            print(_("Git Fusion Submit Trigger user '{0}' is not logged in.\n{1}").
                    format(user, data[0]['data']))
            sys.exit(P4FAIL)
    return data

# pylint: enable=E1101,R0912


def is_super(user):
    """Determine if user is a super user"""
    results = p4_run(['protects', '-u',  user], user=user)
    for r in results:
        if 'code' in r and r['code'] == 'error':
            return False
        if 'perm' in r and r['perm'] == 'super':
            return True
    return False


def set_counter(name, value):
    """Set p4 counter"""
    p4_run(['counter', '-u', name, value])


def inc_counter(name, user=P4GF_USER):
    """Increment p4 counter."""
    counter = p4_run(['counter', '-u', '-i', name], user=user)[0]
    return counter['value']


def delete_counter(name, user=P4GF_USER):
    """Delete p4 counter."""
    p4_run(['counter', '-u', '-d', name], user=user)


def get_counter(name):
    """Get p4 counter."""
    counter = p4_run(['counter', '-u',  name])[0]
    return counter['value']


def get_counter_lock(name, user=P4GF_USER):
    """Increment and test counter for value == 1."""
    return '1' == inc_counter(name, user=user)


def counter_exists(name):
    """Boolean on counter exists"""
    return str(get_counter(name)) != "0"


def release_counter_lock(name, user=P4GF_USER):
    """Delete counter lock."""
    delete_counter(name, user)


def get_local_depots():
    """Get list of local depots"""
    depot_pattern = re.compile(r"^" + re.escape(P4GF_DEPOT))
    data = p4_run(['-ztag', 'depots'])
    depots = []
    for depot in data:
        if (    (depot['type'] == 'local' or depot['type'] == 'stream')
            and not depot_pattern.search(depot['name'])):
            depots.append(depot['name'])
    return depots


def p4_files_at_change(change):
    """Get list of files in changelist

    p4 files@=CNN provides a valid file list depending on the trigger type and the p4 command.
    This table lists the command and the triggers for which the command returns a valid file list.

    p4 submit                     change_content  change_commit
    p4 submit -e  change_submit   change_content  change_commit
    p4 populate                   change_content  change_commit

    From an edge-server initiated submit, the following applies to the commit server:
    p4 submit -e                  change_content  change_commit

    """
    depot_files = []
    depots = get_local_depots()
    for depot in depots:
        cmd = ['files']
        cmd.append("//{0}/...@={1}".format(depot, change))
        data = p4_run(cmd)
        for item in data:
            if 'depotFile' in item:
                depot_files.append(enquote_if_space(item['depotFile']))
    return depot_files


def is_int(candidate):
    '''Is the candidate an int?'''
    try:
        int(candidate)
        return True
    except ValueError:
        return False

def can_cleanup_change(change):
    '''Determine whether the Reviews may be cleaned
    from a non-longer pending changelist'''
    if not is_int(change):
        return False

    data = p4_run(['describe', '-s', change])[0]
    if not data:
        print("can_clean change {0} does not exist".format(change))
        return True

    if 'code' in data and data['code'] == 'error' and 'data' in data:
        if re.search('no such changelist', data['data']):
            return True
        else:
            raise Exception(_("error in describe for change {0}: {1}").format(change, data))

    submitted = False
    pending = False
    no_files = True

    shelved = 'shelved' in data
    if 'status' in data:
        pending   = data['status'] == 'pending'
        submitted = data['status'] == 'submitted'
    if not shelved and pending:
        if 'depotFile0' in data:
            no_files = False
        else:
            no_files = len(p4_files_at_change(change)) == 0

    if pending and shelved:
        return False
    if pending and no_files:
        return True
    if submitted:
        return True
    return False


def cleanup_submits():
    """Remove non-Git Fusion submit files from Reviews."""
    counters = p4_run(['counters', '-u', '-e', P4GF_REVIEWS_NON_GF_RESET + '*'])
    for counter in counters:
        if isinstance(counter, dict) and 'counter' in counter:
            value = counter['counter']
            change = value.replace(P4GF_REVIEWS_NON_GF_SUBMIT, '')
            if can_cleanup_change(change):
                remove_counter_and_reviews( counter['counter']
                                          , counter['value'].split(SEPARATOR))


def unlock_changelist(changelist, client):
    """Unlock the files in the failed changelist so GF may continue.

    Called as git-fusion-user with admin priviledges.
    """
    p4_run(['-c', client, 'unlock', '-f', '-c', changelist ])


def delete_all_counters():
    """Delete all non-Git Fusion counters."""
    counters = p4_run(['counters', '-u', '-e', P4GF_REVIEWS_NON_GF_RESET + '*'])
    for counter in counters:
        if 'counter' in counter:
            delete_counter(counter['counter'])


def remove_file(file_):
    """Remove file from file system."""
    try:
        os.remove(file_.name)
    except IOError:
        pass


def check_heartbeat_alive(heartbeat):
    """Compares the time value in the lock contents to the current time
    on this system (clocks must be synchronized closely!) and if the
    difference is greater than HEARTBEAT_TIMEOUT_SECS then assume the lock
    holder has died.

    Returns True if lock is still valid, and False otherwise.
    """
    try:
        then = int(re.split(NTR(r'\s'), heartbeat)[4])

    except ValueError:
        #print("malformed heartbeat counter contents: {0}".format(heartbeat))
        return False
    now = calendar.timegm(time.gmtime())
    return now < then or (now - then) < HEARTBEAT_TIMEOUT_SECS


def gf_has_fresh_heartbeat():
    """ Examine all heartbeats. If any is alive
    then return True - else False
    """
    heartbeats = p4_run(['counters', '-u', '-e', P4GF_HEARTBEATS ])
    have_alive_heartbeat = False
    for heartbeat in heartbeats:
        if check_heartbeat_alive(heartbeat['value']):
            have_alive_heartbeat = True
            break
    return have_alive_heartbeat


def find_depot_prefixes(depot_paths):
    """ For each depot, find the longest common prefix """
    prefixes = {}
    if not depot_paths:
        return prefixes
    last_prefix = None
    depot_pattern = re.compile(r'^//([^/]+)/')
    for dp in depot_paths:
        dp = dequote(dp)
        # since depot_paths is probably sorted, it's very likely
        # the current depot_path starts with the last found prefix
        # so check that first and avoid hard work most of the time
        if last_prefix and dp.startswith(last_prefix):
            continue
        # extract depot from the path and see if we already have a prefix
        # for that depot
        m = depot_pattern.search(dp)
        depot = m.group(1)
        depot_prefix = prefixes.get(depot)
        if depot_prefix:
            prefixes[depot] = last_prefix = os.path.commonprefix([depot_prefix, dp])
        else:
            prefixes[depot] = last_prefix = dp
    return prefixes.values()

def get_depot_patterns(depot_path_list):
    """ Generate the reviews patterns for file list """
    return [enquote_if_space(p + "...") for p in find_depot_prefixes(depot_path_list)]


def populate_is_locked_by_review(files, ofile=None):
    """Check if locked files in changelist are locked by GF in Reviews."""
    returncode = False
    common_path_files = get_depot_patterns(files)
    if not ofile:
        ofile = write_lines_to_tempfile(NTR("islocked"), common_path_files)
    #else use the ofile which is passed in

    cmd = NTR(['-x', ofile.name, 'reviews'])
    users = p4_run(cmd)
    change_is_in_union = False
    for user in users:
        if 'code' in user and user['code'] == 'error':
            raise Exception(user['data'])
        _user = user['user']
        if _user.startswith(P4GF_REVIEWS_GF):
            if _user == P4GF_REVIEWS__ALL_GF:
                change_is_in_union = True
            elif _user != P4GF_REVIEWS__NON_GF:
                if gf_has_fresh_heartbeat():
                    print (MSG_LOCKED_BY_GF.format(user['user']))
                    # reject this submit which conflicts with GF
                    change_is_in_union = True
                    returncode =  True
                    break
    return  (returncode, ofile, change_is_in_union)


def submit_is_locked_by_review(change, client):
    """Check if locked files in changelist are locked by GF in Reviews."""
    returncode = False

    cmd = NTR(['reviews', '-C', client, '-c', change])
    users = p4_run(cmd)
    change_is_in_union = False
    for user in users:
        if 'code' in user and user['code'] == 'error':
            raise Exception(user['data'])
        _user = user['user']
        if _user.startswith(P4GF_REVIEWS_GF):
            if _user == P4GF_REVIEWS__ALL_GF:
                change_is_in_union = True
            elif _user != P4GF_REVIEWS__NON_GF:
                if gf_has_fresh_heartbeat():
                    print (MSG_LOCKED_BY_GF.format(user['user']))
                    # reject this submit which conflicts with GF
                    change_is_in_union = True
                    returncode =  True
                    break
    return  (returncode, change_is_in_union)


def set_submit_counter(countername, depot_files):
    """Set submit counter using -x file input"""
    file_ = tempfile.NamedTemporaryFile(prefix='p4gf-trigger', delete=False)
    line = "%s\n" % countername
    file_.write(encode(line))
    for ofile in depot_files:
        line = "{0}{1}".format(ofile, SEPARATOR)
        file_.write(encode(line))
    file_.flush()
    file_.seek(0, 2)  # go to eof
    file_size = file_.tell()
    file_.close()      # not deleted - so windows can re-open this file under p4
    bufparam = NTR("-vfilesys.bufsize={0}").format(file_size)
    p4_run(['-x', file_.name, bufparam, 'counter', '-u'])
    os.remove(file_.name)


def write_lines_to_tempfile(prefix_, lines):
    """Write list of lines to tempfile."""
    file_ = tempfile.NamedTemporaryFile(prefix='p4gf-trigger-' + prefix_, delete=False)
    for line in lines:
        ll = "%s\n" % dequote(line)
        file_.write(encode(ll))
    file_.flush()
    file_.close()
    return file_


def enquote_if_space(path):
    """Wrap path is double-quotes if SPACE in path."""
    if ' ' in path and not path.startswith('"'):
        path = '"' + path + '"'
    return path


def dequote(path):
    """Remove wrapping double quotes"""
    if path.startswith('"'):
        path = path[1:-1]
    return path

def shelved_files(change):
    ''' Return list of shelved files.'''
    cfiles = []
    shelved_data = p4_run(['describe', '-S', change])[0]
    for key, value in shelved_data.items():
        if key.startswith('depotFile'):
            cfiles.append(enquote_if_space(value))
    return cfiles

def not_all_files_locked(change):
    '''Return True if not all opened files are locked.'''
    data = p4_run(['opened', '-a', '-c', change])
    filecount = 0
    lockcount = 0
    for file_ in data:
        if not isinstance(file_, dict):
            continue
        try:
# pylint: disable=W0612
# unused variable
            df = file_['depotFile']
        except Exception:
            # return an empty list if this changelist does not exist
            if file_["code"] == "error":
                if CHANGE_UNKNOWN_REGEX.match(file_["data"]):
                    return []
            raise Exception(_("Key error in p4 opened: {0}").format(file_))
        filecount = filecount + 1
        if 'ourLock' in file_:
            lockcount = lockcount + 1

    return filecount != lockcount

# pylint: enable=W0612

#def submitted_files(change):
#    """Return list of files in opened in submitted changelist.
#
#    If submitting a shelf via 'p4 submit -e', then
#    fallback to 'p4 files ...@=CNN'
#    Wrap quotes around paths containing SPACE.
#    """
#    cfiles = []
#    data = p4_run(['opened', '-a', '-c', change])
#    if not data:
#        # No opened files? ... probably submitting from a shelf with 'p4 submit -e'
#        # Files in a shelved changelist are not reported as opened in that changelist
#        # And therefore, additionally, not detectable as locked
#        # Files submitted from a shelf are reported by 'p4 describe -S'
#        # or by 'p4 files ...@=CNN
#        return p4_files_at_change(change)
#    else:
#        for file_ in data:
#            if not isinstance(file_, dict):
#                continue
#            try:
#                df = file_['depotFile']
#            except Exception:
#                # return an empty list if this changelist does not exist
#                if file_["code"] == "error":
#                    if CHANGE_UNKNOWN_REGEX.match(file_["data"]):
#                        return []
#                raise Exception("Key error in p4 opened {0}".format(file_))
#            cfiles.append(enquote_if_space(df))
#
#        return cfiles


def update_userspec(userspec, user, p4user=P4GF_USER):
    """Reset P4 userspec from local userspec dictionary."""
    newspec = ""
    for key, val in userspec.items():
        if key == 'Reviews':
            reviews = '\n' + key + ":\n"
            for line in val.splitlines():
                reviews = reviews + "\t" + line + "\n"
        else:
            newspec = "{0}\n{1}:\t{2}".format(newspec, key, val)

    newspec = newspec + reviews
    file_ = tempfile.NamedTemporaryFile(prefix='p4gf-trigger-userspec', delete=False)
    line = "%s" % newspec
    file_.write(encode(line))
    file_.close()      # not deleted - so windows can re-open this file under p4
    if p4user != P4GF_USER:  # assume this is the super user as called by p4gf_super_init
        # Called by p4gf_super_init as 'super' to  --rebuild-all-gf-reviews
        command = NTR("{0} -p {1} {2} -u {3} user -f  -i < {4}")\
                  .format(P4GF_P4_BIN, P4PORT,
                          ' '.join(CHARSET), p4user, file_.name)
    else:
        command = NTR("{0} -p {1} {2} -u {3} user -i < {4}")\
                  .format(P4GF_P4_BIN, P4PORT,
                          ' '.join(CHARSET), user, file_.name)
    p = Popen(command, shell=True, stdout=PIPE, stderr=PIPE)
    stderr_data = p.communicate()[1]
    # pylint: disable=E1101
    # has no member 'returncode'
    if p.returncode:
        print ("{0}".format(stderr_data.decode('utf-8')))
        print(MSG_MALFORMED_CONFIG)
    # pylint: enable=E1101
    try:
        os.remove(file_.name)
    except IOError:
        pass


def append_reviews(user, depot_files, p4user=P4GF_USER):
    '''Add the files to Reviews to the user's user spec.'''
    update_reviews(user, depot_files, action=ACTION_ADD, p4user=p4user)


def remove_reviews(user, depot_files, p4user=P4GF_USER):
    '''Remove the files to Reviews to the user's user spec.'''
    update_reviews(user, depot_files, action=ACTION_REMOVE, p4user=p4user)


def reset_reviews(user, depot_files, p4user=P4GF_USER):
    '''Add the files to Reviews to the user's user spec.'''
    update_reviews(user, depot_files, action=ACTION_RESET, p4user=p4user)


def unset_reviews(user, p4user=P4GF_USER):
    '''Remove all files Reviews from the user's user spec.'''
    update_reviews(user, None, action=ACTION_UNSET, p4user=p4user)


def update_reviews(user, depot_files, action=ACTION_ADD, p4user=P4GF_USER):
    """
    Add or remove Reviews to the user spec

    add == Add the set of files
    remove == Remove the set of files
    unset == Set Reviews to none
    reset   == Set Reviews to these files
    """
    thisuser = p4user if p4user != P4GF_USER else user
    userspec0 = p4_run(['user', '-o', user], user=thisuser)[0]
    userspec = {}
    # Remove the keys which are not part of the user spec itsef
    # Get all the fields except 'ReviewsNNN'
    for k in userspec0.keys():
        if k in USER_FIELDS:
            userspec[k] = userspec0[k]

    newspec = dict((k, v) for k, v in userspec.items() if not k.startswith('Review'))
    if action == ACTION_UNSET:
        newspec['Reviews'] = '\n'     # Set to empty
    else:
        # Fetch the current reviews from userspec0 which contains the 'ReviewsNNN' fields
        current_reviews = [v for k, v in userspec0.items() if k.startswith('Review')]

        if action == ACTION_ADD:
            current_reviews += depot_files
        elif action == ACTION_RESET:
            current_reviews = depot_files
        else:   # remove
            for review in depot_files:
                try:
                    current_reviews.remove(review)
                except ValueError:
                    pass
        if len(newspec) > 0:
            newspec['Reviews'] = '\n'.join(current_reviews)
    update_userspec(newspec, user, p4user=p4user)


def add_non_gf_reviews(trigger_context):
    """Add files in changelist to Reviews of non-GF user.

    trigger type determines name of counter
    and method of getting list of files from changelist
    """
    set_submit_counter(trigger_context.countername, trigger_context.cfiles)
    append_reviews(P4GF_REVIEWS__NON_GF, trigger_context.cfiles)


def remove_counter_and_reviews(counter, files):
    """Remove counter and its reviews from non-gf user Spec"""
    counter_files = set(files)

    # The trigger_type is set by the change-submit trigger
    # So skip reviews removal when no actual files in counter
    if files[0].strip() not in TRIGGER_TYPES:
        remove_reviews(P4GF_REVIEWS__NON_GF, counter_files)

    delete_counter(counter)

# pylint: disable=W0613
# unused argument - is_submit
def get_trigger_countername(change, is_submit=True):
    ''' Get the counter name.'''
    # Current design uses a single counter name for submit and populate
    countername = P4GF_REVIEWS_NON_GF_SUBMIT + change
    return countername
    # pylint: enable=W0613


def change_submit_trigger(change, client, trigger_type):
    '''
    Store the trigger_type in P4GF_REVIEWS_NON_GF_SUBMIT-NNN.

    This informs the following change_content trigger
    that a submit initiated these GF triggers - not populate.
    All collision detection work will be done in the change_content trigger.
    If this counter is not detected in the change_content trigger, then
    we have a 'p4 populate' event.
    This counter will be updated in the change_content_trigger(); either:
            1) replace value with the list of change list files
         or 2) remove counter if the filelist if not in the all-gf union
    '''
    returncode = P4PASS
    counter = get_trigger_countername(change, is_submit=True)
    # In the case of 'submit -c NNN' remove the preceding counter and reviews
    # And then reset the counter
    # pylint:disable=W0703
    lock_acquired = False
    try:
        value = get_counter(counter)
        if str(value) != "0":    # valid non-gf counter
            acquire_counter_lock(P4GF_REVIEWS__NON_GF)
            lock_acquired = True
            remove_counter_and_reviews(counter, value.split(SEPARATOR))
    except Exception as exce:
        print (MSG_POST_SUBMIT_FAILED)
        print (exce.args)
        returncode = P4FAIL
    finally:
        if lock_acquired:
            release_counter_lock(P4GF_REVIEWS__NON_GF)

    # Only submits have opened files
    data = p4_run(['opened', '-m', '1' , '-c',  change, '-C', client])
    if data:
        p4_run(['counter', '-u', counter, trigger_type])
    return returncode

# pylint: disable=R0912
# Too many branches
def change_content_trigger(change, client):
    """Reject p4 submit if change overlaps Git Fusion push.


    Beginning with 13.1 p4d 'p4 reviews' added the -C option.
      'The -C flag limits the files to those opened in the specified clients
       workspace,  when used with the -c flag limits the workspace to files
       opened in the specified changelist.'

    Using this option eliminates need for the files argument to 'p4 reviews'.
    However calls to 'p4 populate' may not take advantage of this featurer,
    there being no workspace associated with the populate.
    Thus triggers for 'p4 submit' and 'p4 populate' must handle the 'p4 reviews'
    differently.


    Additionally p4 populate does not engage the change-submit trigger.
    Thus Git Fusion uses the change-submit trigger to do no more than
    set a counter to distinguish submit from populate.
    The following change-content trigger uses this counter to
    select the method of calling p4 reviews and resets its value with
    the list of changelist files.. All other work is identical.
    TriggerContext class contains all data and p4 calls to handle
    the collision detection.
    """
    # Are we handling a submit or a populate?
    if counter_exists(get_trigger_countername(change, is_submit=True)):
        is_submit = True
    else:
        is_submit = False

    returncode = P4PASS
    counter_lock_acquired = False
    trigger_context = None

    try:
        # set methods and data for this change_content trigger
        trigger_context = TriggerContext(is_submit, change, client)
        trigger_context.check_if_locked_by_review()
        if trigger_context.is_locked:
            # Already locked by GF, but was this a submit?
            if is_submit:  # then remove now unneeded placeholder counter
                delete_counter(trigger_context.countername)
            # Now reject this submit  before we add any Reviews data
            returncode = P4FAIL
        elif trigger_context.is_in_union:
            # Get the change list files into trigger_context.cfiles
            trigger_context.get_cfiles()

            # Now get the user spec lock
            acquire_counter_lock(P4GF_REVIEWS__NON_GF)
            counter_lock_acquired = True
            cleanup_submits()  # previously handled submits which left counters

            # add our Reviews
            add_non_gf_reviews(trigger_context)
            # now check again
            trigger_context.check_if_locked_by_review()
            if trigger_context.is_locked:
                # Locked by GF .. so remove the just added locked files from reviews
                remove_counter_and_reviews(trigger_context.countername, trigger_context.cfiles)
                returncode = P4FAIL
        # if not locked and not is_in_union do nothing
        # unless this was a submit - we need to remove the semaphoric submit counter
        # which marked this submit started in the change_submit trigger
        elif is_submit:
            delete_counter(trigger_context.countername)
    # pylint: disable=W0703
    # Catch Exception
    except Exception as exce:
        print (MSG_PRE_SUBMIT_FAILED)
        print (_("Exception: {0}").format(exce))
        returncode = P4FAIL
    # pylint: enable=W0703
    finally:
        if trigger_context:
            trigger_context.cleanup()
        if counter_lock_acquired:
            release_counter_lock(P4GF_REVIEWS__NON_GF)
        if returncode == P4FAIL:
            # p4 unlock the files so that GF may proceed
            unlock_changelist(change, client)
    return returncode
# pylint: enable=R0912

def _read_string(config, depot_path_msg_only, contents):
    '''
    If unable to parse, convert generic ParseError to one that
    also contains a path to the unparsable file.
    '''
    if PYTHON3:
        try:
            config.read_string(contents)
            return True
        except PARSING_ERROR as e:
            msg = _("Unable to read config file {0}.\n{1}").format(depot_path_msg_only, e)
            print(msg)
            return False

    else:
        try:
            infp = cStringIO.StringIO(str(contents))
            config.readfp(infp)
            return True
        except PARSING_ERROR as e:
            msg = _("Unable to read config file {0}.\n{1}").format(depot_path_msg_only, e)
            print(msg)
            return False


def get_lhs(view_, file_path):

    '''Extract the left map from the a config view line
    If the left map starts with " it may not contain embedded quotes
    If the left map does not start with " it may contain embedded quotes
    If the left map starts with " only then may it contain embedded space
    '''
    view = view_.strip()
    quote = '"'
    quote_r = -1
    quoted_view = False
    double_slash = view.find('//')
    quote_l = view.find(quote)
    lhs = None
    if quote_l > -1 and quote_l < double_slash:
        quoted_view = True

    if quoted_view:
        search = QUOTE_PLUS_WHITE.search(view[quote_l+1:])
        if search:
            quote_r = search.start(2)
            lhs = view[:quote_r+ + quote_l + 2]   # +2 because the search started at 1 (not 0)
        else:
            msg = _("didn't find end of quote : for '{0}' in '{1}'").format(view, file_path)
            print(msg)

    else:
        search = LR_SEPARATOR.search(view)
        if search:
            lhs = search.groups()[0]
    return lhs


def get_repo_views(file_path, contents):
    """Return array of left maps from p4gf_config file.
    contents == array
    """
    all_views = []

    if PYTHON3:
        config = configparser.ConfigParser(interpolation=None, strict=False)
    else:
        config = ConfigParser.RawConfigParser()
    valid_config = _read_string(config, depot_path_msg_only = file_path
                               , contents= str(contents))
    if not valid_config:
        return all_views   # invalid config so so nothing

    branches  = [ sec for sec in config.sections() if not sec.startswith('@')]
    view_lines = []
    for s in branches:
        if config.has_option(s, KEY_VIEW):
            view_lines = config.get(s, KEY_VIEW)
        # pylint: disable=E1103
        # has no member
        if isinstance(view_lines, str):
            view_lines = view_lines.splitlines()
        # pylint: enable=E1103
        # Common: first line blank, view starts on second line.
        if view_lines and not len(view_lines[0].strip()):
            del view_lines[0]

        for v in view_lines:
            lhs = get_lhs(v, file_path)
            if lhs and not (lhs.startswith('-') or lhs.startswith('"-')):
                all_views.append(lhs)

    return all_views


def rebuild_all_gf_reviews(user=P4GF_USER):
    """Rebuild git-fusion-reviews--all-gf Reviews from //P4GF_DEPOT/repos/*/p4gf_config.
    """
    returncode = P4PASS
    action = ACTION_RESET
    config_files = []
    repo_views = []

    # pylint:disable=W0703
    # Catch Exception
    try:
        acquire_counter_lock(P4GF_REVIEWS__ALL_GF, user=user)

        # Get list of all repos/*/p4gf_config files
        data = p4_run(['files', '//{0}/repos/*/p4gf_config'.format(P4GF_DEPOT)], user=user )
        for _file in data:
            if 'depotFile' in _file and 'action' in _file:
                if not 'delete' in _file['action']:
                    config_files.append(_file['depotFile'])

        # if no p4gf_config files - then remove all views
        if not config_files:
            action = ACTION_UNSET

        # From each p4gf_config file extract the views with a regex
        for depot_file in config_files:
            contents = p4_print(depot_file)
            views = get_repo_views(depot_file, contents)
            if views and len(views):
                repo_views.extend(views)
                # Report to caller - not invoked as a trigger
                repo_l = len('//{0}/repos/'.format(P4GF_DEPOT))
                repo_r = depot_file.rfind('/')
                print(_("Rebuild '{0}' Reviews: adding repo views for '{1}'")
                        .format(P4GF_REVIEWS__ALL_GF, depot_file[repo_l:repo_r]))

        if not repo_views:
            action = ACTION_UNSET

        if repo_views or action == ACTION_UNSET:
            update_reviews(P4GF_REVIEWS__ALL_GF, repo_views
                          , action=action, p4user=user)
    except Exception as exce:
        print (_("Exception: {0}").format(exce))
        returncode = P4FAIL
    finally:
        release_counter_lock(P4GF_REVIEWS__ALL_GF, user=user)
    return returncode

def add_repo_views_to_union(change, user=P4GF_USER):
    """Add all views in a p4gf_config to the P4GF_REVIEWS__ALL_GF Reviews user.

    Do not consider p4gf_config2 files - as these views are not user accessbible.
    Currently deletes are ignored. Reviews grow until recreate with --rebuild-all-gf-reviews.
    """
    config_files = []
    repo_views = []

    # Get the changelist file set
    data = p4_run(['describe', '-s', change])[0]

    # check against this regex for the p4gf_config file
    config_pattern = re.compile(r'^//' + re.escape(P4GF_DEPOT) + '/repos/[^/]+/p4gf_config$')
    for key, value in data.items():
        if key.startswith('depotFile'):
            action_key = key.replace('depotFile','action')
            if not 'delete' in data[action_key]:
                if config_pattern.match(value):
                    config_files.append(enquote_if_space(value))

    # From each p4gf_config file extract the views with a regex
    for depot_file in config_files:
        contents = p4_print(depot_file)
        views = get_repo_views(depot_file, contents)
        if views and len(views):
            repo_views.extend(views)

    # Add to Reviews
    if repo_views:
        append_reviews(P4GF_REVIEWS__ALL_GF, repo_views
                      , p4user=user)



def change_commit_p4gf_config(change, user=P4GF_USER):
    """Post submit trigger on changes //P4GF_DEPOT/repos/*/p4gf_config.

    Add p4gf_config views to git-fusion-reviews--all-gf Reviews:.
    """
    returncode = P4PASS
    # pylint:disable=W0703
    # Catch Exception

    try:
        acquire_counter_lock(P4GF_REVIEWS__ALL_GF, user=user)
        add_repo_views_to_union(change, user=user)
    except Exception as exce:
        print (MSG_PRE_SUBMIT_FAILED)
        print (_("Exception: {0}").format(exce))
        returncode = P4FAIL
    finally:
        release_counter_lock(P4GF_REVIEWS__ALL_GF, user=user)
    return returncode


def change_commit_trigger(change):
    """Post-submit trigger for Git Fusion.

    Cleanup files from reviews for non-GF user.
    """
    returncode = P4PASS
    lock_acquired = False
    # pylint: disable=W0703
    try:
        countername = get_trigger_countername(change, is_submit=True)
        value = get_counter(countername)
        acquire_counter_lock(P4GF_REVIEWS__NON_GF)
        lock_acquired = True
        if str(value) != "0":    # valid non-gf counter
            remove_counter_and_reviews(countername, value.split(SEPARATOR))
        else:
            # counter does not exist - likely a renamed one.
            cleanup_submits()
    except Exception as exce:
        print (MSG_POST_SUBMIT_FAILED)
        print (exce.args)
        returncode = P4FAIL
    finally:
        if lock_acquired:
            release_counter_lock(P4GF_REVIEWS__NON_GF)
    return returncode


def acquire_counter_lock(name, user=P4GF_USER):
    """Get Reviews lock for non-gf user."""
    while True:
        if get_counter_lock(name, user):
            return
        time.sleep(_RETRY_PERIOD)


def reset_all(user):
    """Tool to remove all GF and trigger Reviews and counters"""
    print(_("Removing all non-Git Fusion initiated reviews and counters"))
    # pylint: disable=W0703
    # Catch Exception
    delete_all_counters()
    for counter in [ P4GF_COUNTER_PRE_TRIGGER_VERSION
                   , P4GF_COUNTER_POST_TRIGGER_VERSION ]:
        set_counter( counter,
            "{0} : {1}".format(P4GF_TRIGGER_VERSION, datetime.datetime.now()))
    for user_name in gf_reviews_user_name_list():
        if user_name != P4GF_REVIEWS__ALL_GF:   # preserve the all-gf reviews
            unset_reviews(user_name, p4user=user)
        release_counter_lock(user_name)

def set_version_counter():
    ''' Reset the Git Fusion Trigger version counters.'''
    validate_port()
    _version = "{0} : {1}".format(P4GF_TRIGGER_VERSION, datetime.datetime.now())
    set_counter(P4GF_COUNTER_PRE_TRIGGER_VERSION, _version)
    set_counter(P4GF_COUNTER_POST_TRIGGER_VERSION, _version)
    print (_("Setting '{0}' = '{1}'").format(P4GF_COUNTER_PRE_TRIGGER_VERSION, _version))
    print (_("Setting '{0}' = '{1}'").format(P4GF_COUNTER_POST_TRIGGER_VERSION, _version))
    sys.exit(P4PASS) # Not real failure but trigger should not continue

def validate_port():
    """Calls sys_exit if we cannot connect."""
    colon = re.match(r'(.*)(:{1,1})(.*)', P4PORT)
    if colon:
        port = colon.group(3)
    else:
        port = P4PORT
    if not port.isdigit():
        print(_("Server port '{0}' is not numeric. Stopping.").format(P4PORT))
        print(_("args: {0}").format(sys.argv))
        sys.exit(P4FAIL)
    p4_run(["info"])

def get_user_from_args(option_args, super_user_index=None):
    '''Return P4GF_USER or super user if present'''
    validate_port()  # uses global P4PORT
    user = P4GF_USER
    if super_user_index and len(option_args) == super_user_index+1:
        super_user = option_args[super_user_index]
    else:
        super_user = None
    if super_user:
        if not is_super(super_user):
            print (_("'{0}' is not super user. Exiting.").format(super_user))
            sys.exit(P4FAIL)
        else:
            user = super_user
    return user

class Args:
    '''an argparse-like class to receive arguments from
    getopt parsing.
    '''
    def __init__(self):
        self.reset                    = None
        self.rebuild_all_gf_reviews   = None
        self.set_version_counter      = None
        self.generate_trigger_entries = None
        self.optional_command         = False
        self.oldchangelist            = None
        self.trigger_type             = None
        self.change                   = None
        self.user                     = None
        self.client                   = None
        self.serverport               = None
        self.serverid                 = None
        self.peerhost                 = None
        self.clienthost               = None
        self.parameters               = []

    def __str__(self):
        sb = []
        for key in self.__dict__:
            sb.append("{key}='{value}'".format(key=key, value=self.__dict__[key]))

        return '\n'.join(sb)

    def __repr__(self):
        return self.__str__()


def display_usage_and_exit(mini=False, invalid=False):
    '''Display mini or full usage.'''
    if mini:
        mini_usage(invalid)
    else:
        usage()
    sys.stdout.flush()
    if invalid:
        sys.exit(1)
    else:
        sys.exit(0)


def validate_option_or_exit(minimum, maximum, positional_len):
    '''Validate option count.'''
    if positional_len >= minimum and positional_len <= maximum:
        return True
    else:
        display_usage_and_exit(True, True)

# pylint: disable=R0912
# Too many branches
def parse_argv():
    '''Parse the command line options. '''

    trigger_opt_base_count = 5
    trigger_opt_serverid_count = trigger_opt_base_count + 3

    args = Args()
    short_opt = 'h'
    long_opt = NTR(['reset', 'rebuild-all-gf-reviews',
                'set-version-counter', 'generate-trigger-entries', 'help'])
    try:
        options, positional = getopt.getopt(sys.argv[1:], short_opt, long_opt)
    except getopt.GetoptError as err:
        print(_("Command line options parse error: {0}").format(err))
        display_usage_and_exit(True, True)

    positional_len = len(positional)
    options_len     = len(options)
    if options_len > 1 :
        display_usage_and_exit(True, True)
    elif options_len == 1:
        args.optional_command = True
        opt = options[0][0]
        if opt in ("-h", "--help"):
            display_usage_and_exit(opt == '-h')
        elif opt == "--reset" and validate_option_or_exit(1, 2, positional_len):
            args.reset = positional
        elif opt == "--rebuild-all-gf-reviews" and validate_option_or_exit(1, 2, positional_len):
            args.rebuild_all_gf_reviews = positional
        elif opt == "--set-version-counter" and validate_option_or_exit(1, 1, positional_len):
            args.set_version_counter = positional
        elif  opt == "--generate-trigger-entries"and validate_option_or_exit(2, 3, positional_len):
            args.generate_trigger_entries = positional
    else:  # we have a trigger invocation from the server
        # p4d <= 13.1  do not support the serverid and host parameters
        if positional_len >= trigger_opt_base_count:
            args.parameters = positional
            args.trigger_type = positional[0]
            args.change = positional[1]
            args.user = positional[2]
            args.client = positional[3]
            args.serverport = positional[4]
            idx  = 5
            # the change-commit server contains the %oldchangelist% parameter
            if len(positional) >= 6 and args.trigger_type == 'change-commit':
                args.oldchangelist = positional[5]
                idx = 6

            # p4d >= 13.2  do support the serverid and host parameters
            if positional_len >= trigger_opt_serverid_count:
                # but ignore the %strings% which will not be intpreted on p4d < 13.2
                # this will permit these parameters to pass harmlessly if configured
                # on p4d < 13.2
                if (   positional[idx] != '%serverid%'
                   and positional[idx+1] != '%peerhost%'
                   and positional[idx+2] != '%clienthost%'):
                    args.serverid = positional[idx]
                    args.peerhost = positional[idx+1]
                    args.clienthost = positional[idx+2]
        else:
            display_usage_and_exit(True, True)

    return args
# pylint: enable=R0912



# pylint: disable=R0912
# Too many branches
# pylint: disable=R0915
def main():
    """Execute Git Fusion submit triggers."""
    args = parse_argv()
    global P4PORT
    exitcode = P4PASS
    missing_args = False
    if not args.optional_command:
        # we have been called as a p4d trigger
        if args.trigger_type in TRIGGER_TYPES:
            if len(args.parameters) < 5:
                missing_args = True
            if len(args.parameters) >= 5:
                # Set P4PORT from %serverport% only if not set above to non-empty string
                # See P4PORT global override at top of this file
                if not P4PORT:
                    P4PORT = args.serverport
                # pylint: disable=W0703
                #print("p4gf_submit_trigger args:\n {0}\n".format(args))
                if args.trigger_type == 'change-commit':
                    # the change-commit trigger sets the oldchangelist - use it
                    if args.oldchangelist:
                        args.change = args.oldchangelist
                    exitcode = change_commit_trigger(args.change)
                elif args.trigger_type == 'change-commit-p4gf-config':
                    exitcode = change_commit_p4gf_config(args.change)
                elif args.trigger_type == 'change-submit':
                    exitcode = change_submit_trigger(args.change, args.client, args.trigger_type)
                elif args.trigger_type == 'change-content':
                    exitcode = change_content_trigger(args.change, args.client)
        else:
            print(_("Invalid trigger type: {0}").format(args.trigger_type))
    else:
        # we have been called with optional args to perform a support task
        if (args.set_version_counter):
            P4PORT = args.set_version_counter[0]
            set_version_counter()

        elif (args.generate_trigger_entries):
            if len (args.generate_trigger_entries) == 3:
                P4PORT = args.generate_trigger_entries[2]
            generate_trigger_entries(args.generate_trigger_entries[0],
                                     args.generate_trigger_entries[1])
        elif (args.reset):
            P4PORT = args.reset[0]
            # Check if an optional user arg was passed and whether it is a super user
            user = get_user_from_args(args.reset, super_user_index=1)
            # Remove all the counters and reviews to reset
            reset_all(user)

        elif (args.rebuild_all_gf_reviews):
            P4PORT = args.rebuild_all_gf_reviews[0]
            # Check if an optional user arg was passed and whether it is a super user
            user = get_user_from_args(args.rebuild_all_gf_reviews, super_user_index=1)
            exitcode = rebuild_all_gf_reviews(user=user)

    if missing_args:
        mini_usage(invalid=True)
        exitcode = P4FAIL

    sys.exit(exitcode)


if __name__ == "__main__":
    if sys.hexversion < 0x02060000 or \
            (sys.hexversion > 0x03000000  and sys.hexversion < 0x03020000):
        print(_("Python 2.6+ or Python 3.2+ is required"))
        sys.exit(P4FAIL)
    main()
