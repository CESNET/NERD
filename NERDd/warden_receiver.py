#!/usr/bin/env python3

"""
NERD standalone script (primary module) for receiving IDEA messages about 
detected security events.

Fetches IDEA messages dropped to a specified directory and updates entity
records accordingly.

This module can safely run in multiple instances.
"""

import time
import os
import socket
import json
import logging
import signal
import sys
from datetime import datetime, timedelta
import jsonpath_rw_ext

# Add to path the "one directory above the current file location" to find modules from "common"
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')))

from common.utils import parse_rfc_time
import common.config
import common.eventdb_psql
import common.task_queue

# script global variables

running_flag = True  # read_dir function terminates when this is set to False

db_queue = [] # queue of events waiting to be written do DB in a batch

LOGFORMAT = "%(asctime)-15s,%(name)s [%(levelname)s] %(message)s"
LOGDATEFORMAT = "%Y-%m-%dT%H:%M:%S"
logging.basicConfig(level=logging.INFO, format=LOGFORMAT, datefmt=LOGDATEFORMAT)

log = logging.getLogger('WardenReceiver')

###############################################################################
# Code for reading directory of "filer protocol"

def read_dir(path, call_when_waiting=None):
    """
    Indefinitely watches given directory for new files. Each incoming file is
    read, parsed as JSON, and yield to caller (function behaves as a generator).

    call_when_waiting - function to call before going to "poll wait" when there
        are no new files.
    """

    class NamedFile(object):
        """ Wrapper class for file objects, which allows and tracks filename
            changes.
        """

        def __init__(self, pth, name, fd=None):
            self.name = name
            self.path = pth
            if fd:
                self.f = os.fdopen(fd, "w+b")
            else:
                self.f = None

        def __str__(self):
            return "%s(%s, %s)" % (type(self).__name__, self.path, self.name)

        def get_path(self, basepath=None, name=None):
            return os.path.join(basepath or self.path, name or self.name)

        def open(self, mode):
            return open(self.get_path(), mode)

        def moveto(self, destpath):
            os.rename(self.get_path(), self.get_path(basepath=destpath))
            self.path = destpath

        def rename(self, newname):
            os.rename(self.get_path(), self.get_path(name=newname))
            self.name = newname

        def remove(self):
            os.remove(self.get_path())

    class SafeDir(object):
        """ Maildir like directory for safe file exchange.
            - Producers are expected to drop files into "temp" under globally unique
              filename and rename it into "incoming" atomically (newfile method)
            - Workers pick files in "incoming", rename them into "temp",
              do whatever they want, and either discard them or move into
              "errors" directory
        """

        def __init__(self, p):
            self.path = self._ensure_path(p)
            self.incoming = self._ensure_path(os.path.join(self.path, "incoming"))
            self.errors = self._ensure_path(os.path.join(self.path, "errors-worker"))
            self.temp = self._ensure_path(os.path.join(self.path, "temp-worker"))
            self.hostname = socket.gethostname()
            self.pid = os.getpid()

        def __str__(self):
            return "%s(%s)" % (type(self).__name__, self.path)

        def _ensure_path(self, p):
            os.makedirs(p, exist_ok=True)
            return p

        def get_incoming(self):
            return [NamedFile(self.incoming, n) for n in os.listdir(self.incoming)]

    def get_dir_list(sdir, owait_poll_time, owait_timeout, nfchunk):
        nflist = sdir.get_incoming()
        timeout = time.time() + owait_timeout
        while len(nflist) < nfchunk and time.time() < timeout and running_flag:
            time.sleep(owait_poll_time)
            nflist = sdir.get_incoming()
        return nflist

    #######
    # End of definitions of auxiliary classes and functions.
    # Body of read_dir function follows ...

    sdir = SafeDir(path)
    poll_time = 1  # config.get("poll_time", 5)
    owait_poll_time = 1  # config.get("owait_poll_time", 1)
    owait_timeout = poll_time  # config.get("owait_timeout", poll_time)
    done_dir = None  # config.get("done_dir", None)
    nfchunk = 100  # min number of files read at once by get_dir_list
    oneshot = False

    while running_flag:
        nflist = get_dir_list(sdir, owait_poll_time, owait_timeout, nfchunk)
        while running_flag and not nflist:
            # No new files, wait and try again
            if call_when_waiting is not None:
                call_when_waiting()
            time.sleep(poll_time)
            nflist = get_dir_list(sdir, owait_poll_time, owait_timeout, nfchunk)

        # nfindex = 0
        # count_ok = count_err = count_local = 0
        for nf in nflist:
            if not running_flag:
                break
            # prepare event array from files
            try:
                nf.moveto(sdir.temp)
            except Exception:
                continue  # Silently go to next filename, somebody else might have interfered
            try:
                # Read file and yield record
                with nf.open("r") as fd:
                    data = fd.read()
                event = json.loads(data)
                yield (data, event)
                # Cleanup
                if done_dir:
                    nf.moveto(done_dir)
                else:
                    nf.remove()
            except Exception as e:
                log.exception("Exception during loading event, file={}".format(str(nf)))
                nf.moveto(sdir.errors)
                # count_local += 1


##############################################################################
# Test of read_dir

def read_dir_test():
    path = "./drop_events_here"
    print("Watching for files in {}".format(os.path.join(path, "incoming")))
    for event in read_dir(path):
        print("------------------------------------------------------------")
        print(json.dumps(event, indent=2))


##############################################################################
# Warden filter
class WardenFilterRuleFormatError(Exception):
    pass


class Sample():
    """
    Callable object for WardenFilter, which is used for sampling. For example sample every 100th IDEA message.
    """
    def __init__(self, max_sample_count):
        self.max_sample_count = int(max_sample_count)
        self.current_sample = 0

    def __call__(self):
        self.current_sample += 1
        if self.current_sample >= self.max_sample_count:
            self.current_sample = 0
            return True
        else:
            return False


class WardenFilter():
    """
    Warden filter, which allows to configure, which IDEA messages are allowed to pass to NERD and which are not.
    """
    # '!=' has to be before '='! Because if '=' would be first in case of '!=', then pattern would be split on '=' and
    # remaining '!' in pattern would be unexpected character
    SUPPORTED_OPERATORS = ('!=', "=")
    SUPPORTED_ACTIONS = ("pass", "drop", "sample")

    def __init__(self, rules_list):
        """
        Parses warden filter rules from NERD configuration (/etc/nerdd.yml) and allows to filter IDEA messages based
        on these parsed rules
        :param rules_list: Raw Warden filter rules from configuration
        :raise: WardenFilterRuleFormatError
        """
        # check if default action is used
        self.default_action = WardenFilter._pass
        if rules_list[-1].strip().startswith(";"):
            # pop last element from rules list (name of default action)
            action_name = rules_list.pop().split(';')[1].strip()
            if action_name.startswith("sample"):
                # if default action is 'sample', save it as Sample callable object
                _, max_sample_count = action_name.strip().split(' ')
                self.default_action = Sample(max_sample_count)
            elif action_name in self.SUPPORTED_ACTIONS:
                # else save correct method as default action
                if action_name == "pass":
                    self.default_action = WardenFilter._pass
                elif action_name == "drop":
                    self.default_action = WardenFilter._drop

        # create list of all rules
        self.filter_list = []
        for warden_filter_rule in rules_list:
            try:
                rule, action = warden_filter_rule.split(';')
            except ValueError:
                # no values to unpack or too many values to unpack
                raise WardenFilterRuleFormatError("Zero or more than one action is defined in one rule. Only one "
                                                  "action is allowed in one rule!")
            if "AND" in rule and "OR" not in rule:
                rule_list = self._parse_rule(rule, "AND")
            elif "OR" in rule and "AND" not in rule:
                rule_list = self._parse_rule(rule, "OR")
            elif "OR" not in rule and "AND" not in rule:
                # should be just single rule
                rule_list = self._parse_rule(rule)
            else:
                raise WardenFilterRuleFormatError("Logical operators AND and OR cannot be mixed!")
            # result will be list of rules, compared values and actions -->
            # [ ( [(rule1, operator1, compared_value1), ...], action1 ), ... ]
            if action.strip().startswith("sample"):
                _, max_sample_count = action.strip().split(' ')
                # if the action is sample, save action as Sample callable object
                self.filter_list.append((rule_list, Sample(int(max_sample_count))))
            elif action.strip() in WardenFilter.SUPPORTED_ACTIONS:
                if action.strip() == "pass":
                    self.filter_list.append((rule_list, WardenFilter._pass))
                else:
                    self.filter_list.append((rule_list, WardenFilter._drop))
            else:
                raise WardenFilterRuleFormatError("Rule uses unsupported action! Supported actions "
                                                  "are {}".format(", ".join(WardenFilter.SUPPORTED_ACTIONS)))

    @classmethod
    def _parse_operator(cls, rule_operator_value):
        """
        Parses part of rule, which contains rule, operator and comparison value
        :param rule_operator_value: string which contains rule, operator and comparison value
        :return: pattern, operator, comparison_value, parsed pattern
        :raise Exception in case of wrong pattern or WardenFilterRuleFormatError
        """
        # go through all supported operators and split rule with operator, which was used
        for operator in cls.SUPPORTED_OPERATORS:
            if operator in rule_operator_value:
                # operator found, get pattern and compared value by split and return it with found operator
                pattern, comparison_value = rule_operator_value.split(operator)
                # parse pattern
                parsed_pattern = jsonpath_rw_ext.parse("$." + pattern.strip())
                return parsed_pattern, operator, comparison_value.strip()
        else:
            raise WardenFilterRuleFormatError("Rule uses unsupported operator! Supported opperators "
                                              "are {}!".format(", ".join(cls.SUPPORTED_OPERATORS)))

    @classmethod
    def _parse_rule(cls, rule, logical_operator=None):
        """
        Parses one whole Warden filter rule, which can consist of multiple logical operators and rules
        :param rule: Warden filter rule
        :param logical_operator: AND|OR|None
        :return: parsed rule as list with 3-elem tuples [(pattern, operator, comparison_value), ...) with first index as
                 logical operator if used ["AND|OR", (pattern, ...), ...]
        :raise Exception in case of wrong pattern or WardenFilterRuleFormatError
        """
        if logical_operator is not None:
            # only one logical operator can be used in rule, split it and get all rules
            rule_list_raw = rule.split(logical_operator)
            # save the name of logical operator for future use
            rule_list = [logical_operator]
            for pattern_operator_value in rule_list_raw:
                pattern, operator, comparison_value = cls._parse_operator(pattern_operator_value)
                rule_list.append((pattern, operator, comparison_value))
        else:
            # only one rule is present, there is no need to split on logical operator, just split on normal operator
            pattern, operator, comparison_value = cls._parse_operator(rule)
            rule_list = [(pattern, operator, comparison_value)]
        return rule_list

    @staticmethod
    def _pass():
        return True

    @staticmethod
    def _drop():
        return False

    @staticmethod
    def _evaluate_rule(rule_list, idea_message):
        """
        Evaluates one Warden filter rule
        :param rule_list: list which contains parts of rule (3-elem tuples with logical operator at first index if used)
        :param idea_message: IDEA message against which is the rule evaluated
        :return: True if rule passed else False
        :raise: WardenFilterRuleFormatError
        """
        # if logical operator is used, than rule list has more than one value
        # (["AND/OR", (patt1, val1), (patt2, val2), ...])
        if len(rule_list) > 1:
            # multiple rules with logical operator are used
            if rule_list[0] == "AND" or rule_list[0] == "OR":
                # rule_list[1:] because 0th index is logical operator
                for pattern, operator, compared_value in rule_list[1:]:
                    pattern_values = [match.value for match in pattern.find(idea_message)]
                    # some values in IDEA message can be of type int, but compared value is always string
                    pattern_values = [str(pattern_value) for pattern_value in pattern_values]
                    if operator == "!=":
                        if compared_value in pattern_values:
                            # If operator is '!=' and compared_value was found (means '='), then return false if logic
                            # operator was AND, because when atleast one condition is wrong --> 0 --> False
                            if rule_list[0] == "AND":
                                return False
                        else:
                            # If condition is correct and logic operator is OR, return True immediately
                            if rule_list[0] == "OR":
                                return True
                    elif operator == "=":
                        # same as above applies here
                        if compared_value not in pattern_values:
                            if rule_list[0] == "AND":
                                return False
                        else:
                            if rule_list[0] == "OR":
                                return True
                else:
                    # if all rules were evaluated, return True if AND was used (all rules passed) or return False if
                    # OR was used, because none of the rules passed
                    return True if rule_list[0] == "AND" else False
            else:
                raise WardenFilterRuleFormatError("Unsupported logical operator is used!")
        else:
            # single rule with action
            pattern, operator, compared_value = rule_list[0]
            pattern_values = [match.value for match in pattern.find(idea_message)]
            # some values in IDEA message can be of type int, but compared value is always string
            pattern_values = [str(pattern_value) for pattern_value in pattern_values]
            if operator == "!=":
                if compared_value not in pattern_values:
                    return True
            elif operator == "=":
                if compared_value in pattern_values:
                    return True
            return False

    def should_pass(self, idea_message):
        """
        Main callable method, which defines, if IDEA message should be stored in NERD or not
        :param idea_message: IDEA message against which are all the rule evaluated
        :return: True if any rule passes else False
        :raise WardenFilterRuleFormatError
        """
        # go through every defined rule
        for rule_list, action in self.filter_list:
            try:
                rule_passed = self._evaluate_rule(rule_list, idea_message)
                if rule_passed:
                    # rule matched, do the action
                    return action()
            except Exception:
                raise WardenFilterRuleFormatError("Warden filter rules are not in correct format!")
        else:
            # if no rule matched, then do default action
            return self.default_action()


##############################################################################
# Main module code

def put_to_db_queue(event):
    """
    Function for writing events to EventDB

    Pull new events from Queue and stores them to EventDB.
    """
    #log.debug("IDEA message enqueued".format(len(db_queue)))
    db_queue.append(event)
    if len(db_queue) >= 100:
        put_set_to_database()


def put_set_to_database():
    """
    Function for sending db_queue to database.
    :return:
    """
    if eventdb is None:
        return
    if len(db_queue) > 0:
        log.debug("Writing a set of {} IDEA messages to database.".format(len(db_queue)))
        eventdb.put(db_queue)
        db_queue.clear()


def stop(signal, frame):
    """
    Stop receiving events.

    Will be evoked on catching SIGINT signal.
    """
    global running_flag
    running_flag = False
    put_set_to_database()
    log.info("exiting")


def receive_events(filer_path, eventdb, task_queue_writer, inactive_ip_lifetime, warden_filter=None):
    # Infinite loop reading events as files in given directory
    # This loop stops on SIGINT
    log.info("Reading IDEA files from {}/incoming".format(filer_path))
    life_span = timedelta(days=inactive_ip_lifetime)

    for (rawdata, event) in read_dir(filer_path, call_when_waiting=put_set_to_database):
        # Store the event to EventDB
        if eventdb is not None:
            put_to_db_queue(event)
        try:
            if warden_filter and not warden_filter.should_pass(event):
                log.debug("event {} ignored".format(event["ID"]))
                continue
            for src in event.get("Source", []):
                for ipv4 in src.get("IP4", []):
                    # TODO check IP address validity

                    log.debug("Updating IPv4 record {}".format(ipv4))
                    cat = '+'.join(event["Category"]).replace('.', '')
                    # Parse and reformat detect time
                    detect_time = parse_rfc_time(event["DetectTime"])  # Parse DetectTime
                    date = detect_time.strftime("%Y-%m-%d")  # Get date as a string

                    # Get end time of event
                    if "CeaseTime" in event:
                        end_time = parse_rfc_time(event["CeaseTime"])
                    elif "WinEndTime" in event:
                        end_time = parse_rfc_time(event["WinEndTime"])
                    elif "EventTime" in event:
                        end_time = parse_rfc_time(event["EventTime"])
                    else:
                        end_time = detect_time

                    node = event["Node"][-1]["Name"]

                    # calculate the timestamp, to which the record should be kept
                    live_till = end_time + life_span

                    task_queue_writer.put_task('ip', ipv4,
                        [
                            ('array_upsert', 'events',
                             {'date': date, 'node': node, 'cat': cat},
                             [('add', 'n', 1)]),
                            ('add', 'events_meta.total', 1),
                            ('setmax', 'last_activity', end_time),
                            ('setmax', '_ttl.warden', live_till),
                        ],
                        "warden_receiver"
                    )
                for ipv6 in src.get("IP6", []):
                    log.debug(
                        "IPv6 address in Source found - skipping since IPv6 is not implemented yet.")  # The record follows:\n{}".format(str(event)), file=sys.stderr)
        except Exception as e:
            log.error("ERROR in parsing event '{}': {}".format(event.get('ID', 'no-ID'), str(e)))


if __name__ == "__main__":
    import argparse

    # Parse arguments
    parser = argparse.ArgumentParser(
        prog="warden_receiver.py",
        description="Primary module of the NERD system to read events from Warden system (as stored into a directory by warden_filer)."
    )
    parser.add_argument('-c', '--config', metavar='FILENAME', default='/etc/nerd/nerdd.yml',
        help='Path to configuration file (default: /etc/nerd/nerdd.yml)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose mode')
    args = parser.parse_args()

    if args.verbose:
        log.setLevel('DEBUG')

    # Read config
    log.info("Loading config file {}".format(args.config))
    config = common.config.read_config(args.config)
    
    config_base_path = os.path.dirname(os.path.abspath(args.config))
    common_cfg_file = os.path.join(config_base_path, config.get('common_config'))
    log.info("Loading config file {}".format(common_cfg_file))
    config.update(common.config.read_config(common_cfg_file))

    inactive_ip_lifetime = config.get('record_life_length.warden', 14)
    warden_filter_rules = config.get('warden_filter', None)
    rabbit_config = config.get("rabbitmq")
    filer_path = config.get('warden_filer_path')

    if warden_filter_rules:
        try:
            warden_filter = WardenFilter(warden_filter_rules)
        except Exception as e:
            log.fatal("Error in Warden filter specification: " + str(e))
            sys.exit(1)
    else:
        warden_filter = None

    # Get number of processes from config
    num_processes = config.get('worker_processes')
    assert (isinstance(num_processes,int) and num_processes > 0), "Number of processes ('num_processes' in config) must be a positive integer"

    # Instantiate PSQLEventDatabase if enabled
    eventdb = None # By default, events are not stored anywhere (they are either read from Mentat or not stored at all)
    if config.get('eventdb', None) == 'psql':
        eventdb = common.eventdb_psql.PSQLEventDatabase(config)
    
    # Create main task queue
    task_queue_writer = common.task_queue.TaskQueueWriter(num_processes, rabbit_config)
    task_queue_writer.connect()

    signal.signal(signal.SIGINT, stop)
    receive_events(filer_path, eventdb, task_queue_writer, inactive_ip_lifetime, warden_filter)
