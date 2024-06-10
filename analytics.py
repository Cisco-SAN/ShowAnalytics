#!/usr/bin/env python3

##############################################################
# Copyright (c) 2019-2020, 2023 by cisco Systems, Inc.
# All rights reserved.
# Applicable for NX-OS 8.3(1) and above
##############################################################

import sys

sys.path.append("/isan/bin/cli-scripts/")
import argparse
import json
import datetime
from prettytable import *
import cli
import time
import re
import signal
import os
import math
from email.utils import formatdate
import syslog


global sig_hup_flag
global pline
global error_log
global working_interface
global interface_list
global top_count
global top_limit
global error
global error_flag
global prev_wid

sig_hup_flag = None
max_flow_limit = 20000
working_interface = None
pline = 0
error_log = []

EGLIN_MODEL = [
    "DS-X9648-1536K9",
    "01FT643",
    "01FT644",
    "02JD635",
]
HINDON_MODEL = [
    "DS-X9748-3072K9",
    "03FR149",
    "03FR076",
    "03FR077",
]
ISHAN_MODEL = [
    "DS-C9132U-K9-SUP",
    "DS-C9132T-K9-SUP",
    "01FT563",
    "01FT567",
    "01FT572",
    "03FR065",
    "8977-T32",
]
YUSHAN_MODEL = [
    "DS-C9396T-K9-SUP",
    "02JD719",
    "02JD721",
    "02JD730",
    "02JD731",
    "02JD732",
    "02JD733",
    "02JD734",
    "02JD736",
    "8977-T96",
]
YUSHANMINI_MODEL = [
    "DS-C9148T-K9-SUP",
    "02JD718",
    "02JD720",
    "02JD725",
    "02JD726",
    "02JD727",
    "02JD728",
    "02JD729",
    "02JD735",
    "8977-T48",
]
CREECH_MODEL = [
    "DS-C9124V-K9-SUP",
    "03FR182",
    "03FR184",
    "03FR185",
    "03FR187",
    "03FR188",
    "03FR189",
    "9024-V24",
]
NELLIS_MODEL = [
    "DS-C9148V-K9-SUP",
    "03FR175",
    "03FR177",
    "03FR179",
    "03FR181",
    "03FR190",
    "03FR191",
    "9024-V48",
]
TINKER_MODEL = [
     "DS-C9396V-K9-SUP",
     "9024-V96",
]

analytics_supported_module = (
    EGLIN_MODEL
    + ISHAN_MODEL
    + YUSHAN_MODEL
    + YUSHANMINI_MODEL
    + HINDON_MODEL
    + CREECH_MODEL
    + NELLIS_MODEL
    + TINKER_MODEL
)

npu_modules = EGLIN_MODEL + ISHAN_MODEL + YUSHAN_MODEL + YUSHANMINI_MODEL

interface_list = None
top_count = 10
top_limit = 10
error_flag = False
error = dict()
prev_wid = None
vmid_enabled = False
max_vsan_len = 4
max_fcid_len = 9
max_vmid_len = 3
max_lunid_len = 19
max_nsid_len = 3


def sig_hup_handler(signum, stack):
    """
    **********************************************************************************
    * Function: sig_hup_handler
    *
    * Action: This is built for evaluate option to handle SIG_HUP
    *          i.e, ternination of ssh or telnet session.
    *            - Generates name for output file
    *            - Provides syslog to user with generated filename for output
    *              file
    * Returns: None
    **********************************************************************************
    """
    global sig_hup_flag
    if sig_hup_flag == "Armed":
        sig_hup_flag = (
            "ShowAnalytics_"
            + "_".join(sys.argv[1:]).replace("/", "_")
            + "_"
            + str(time.time()).replace(".", "_")
            + ".txt"
        )
        syslog.syslog(
            2,
            "ShowAnalytics: Remote session is closed.\
This process will keep running in the background.\
Output will be saved in the file {}\
 in bootflash".format(
                sig_hup_flag
            ),
        )
    else:
        syslog.syslog(
            2,
            "ShowAnalytics: Received SIG_HUP. Hence, \
                exiting the utility",
        )
        os._exit(1)


def sig_int_handler(signum, stack):
    """
    **********************************************************************************
    * Function: sig_int_handler
    *
    * Action: to handle ctrl +c operation gracefully instead of printing
    *         traceback and handling some restore operation like:
    *            - disabling analytics on interface if its enabled by this
    *              utility
    *            - Setting back the orignal terminal width if its altered by
    *              this utility
    * Returns: None
    **********************************************************************************
    """
    global working_interface
    global prev_wid
    if working_interface:
        cli.cli(
            "conf t ; interface {} ; no analytics type fc-all\
                ".format(
                working_interface
            )
        )
    if prev_wid is not None:
        cli.cli("conf t ; terminal width {}".format(prev_wid))
    os._exit(1)


signal.signal(signal.SIGINT, sig_int_handler)


def print_status(msgs):
    """
    **********************************************************************************
    * Function: print_status
    *
    * Input: message to be send as status
    * Action: It is built for evaluate funcion to send status as syslog if
    *         script is running in background and just print the message
    *         on terminal if script is running in foreground
    * Returns: None
    **********************************************************************************
    """
    global sig_hup_flag
    global pline
    global error_log
    if sig_hup_flag in ["Armed", None]:
        for msg in msgs:
            print(msg)
            pline += 1
    error_log.extend(msgs)


def cmd_exc(cmd):
    """
    **********************************************************************************
    * Function: cmd_exc
    *
    * Input: command to be executed
    * Returns: Tuple of 2 Element
    *           -  Status: Bool indicating whether command executed without
    *                      error or not i.e True if executed without error
    *           -  Out: if Status is True, then output else error object
    **********************************************************************************
    """
    try:
        cli_out = cli.cli(cmd)
    except Exception as e:
        return (False, e)
    return (True, cli_out)


def is_traffic_running(port):
    """
    **********************************************************************************
    * Function: is_traffic_running
    *
    * Input: interface
    * Returns: Tuple of 2 Element
    *           -  Bool indicating whether traffic is running or not i.e, true
    *                 if traffic is running on the port provided.
    *           -  List of errors encountered , If no errors encoutered during
    *                 check traffic on port then blank list.
    **********************************************************************************
    """
    status, out = cmd_exc("show interface {} | i frame | ex min".format(port))
    out_list = []
    if not status:
        out_list.append(out)
        out_list.append(
            "Unable to find traffic status for interface {}\
                        ".format(
                port
            )
        )
        return (False, out_list)
    status, out1 = cmd_exc("show interface {} | i frame | ex min".format(port))
    if not status:
        out_list.append(out1)
        out_list.append(
            "Unable to fing traffic status for interface {}\
                        ".format(
                port
            )
        )
        return (False, out_list)
    if out1 != out:
        return (True, [])
    else:
        return (False, [])


def clear_previous_lines(number_of_lines):
    """
    **********************************************************************************
    * Function: clear_previous_lines
    *
    * Cleares Previous lines from terminal to support refreshing output on
    * terminal.
    * Returns: None
    **********************************************************************************
    """
    for _ in range(number_of_lines):
        sys.stdout.write("\x1b[1A")
        sys.stdout.write("\x1b[2K")


def check_port_is_analytics_enabled(inte):
    """
    **********************************************************************************
    * Function: check_port_is_analytics_enabled
    *
    * Input: Interface in format fc<module>/<port>
    * Returns: Bool which is True if interface id port of port-sampling
    *          database i.e analytics is enabled on port else False
    **********************************************************************************
    """
    mod = inte.strip().split("/")[0][2:]
    status, sdb_out = cmd_exc(
        "show analytics port-sampling module {} | i '{}'\
                             ".format(
            mod, inte
        )
    )
    if not status:
        return False
    if inte not in sdb_out:
        return False
    return True


def get_analytics_module(swver):
    """
    **********************************************************************************
    * Function: get_analytics_module
    *
    * Returns: set of module numbers which support analytics
    **********************************************************************************
    """
    global analytics_supported_module
    global npu_modules
    ver = int("".join([i for i in swver if i.isdigit()])[:3])
    if int(ver) < 922:
        no_npu_modules = [x for x in analytics_supported_module if x not in npu_modules]
        for m in no_npu_modules:
            analytics_supported_module.remove(m)
    cmd = "show module | i {} | cut -d ' ' -f 1\
          ".format(
        "|".join(analytics_supported_module)
    )
    status, out = cmd_exc(cmd)
    if not status:
        print(out)
        # print 'Unable to find analytics supported module'
        return []
    else:
        return set([i for i in out.split("\n") if i.isdigit()])


def get_analytics_module_with_npu():
    """
    **********************************************************************************
    * Function: get_analytics_module_with_npu
    *
    * Returns: set of module numbers which support analytics and have NPU
    **********************************************************************************
    """
    global npu_modules
    global analytics_supported_module
    cmd = "show module | i {}  | cut -d ' ' -f 1".format("|".join(npu_modules))
    status, out = cmd_exc(cmd)
    if not status:
        print(out)
        # print 'Unable to find analytics supported module'
        return []
    else:
        return set([i for i in out.split("\n") if i.isdigit()])


def get_amc_modules():
    global npu_modules
    cmd = "show module | i {} | exclude {} | cut -d ' ' -f 1\
          ".format(
        "|".join(analytics_supported_module), "|".join(npu_modules)
    )
    status, out = cmd_exc(cmd)
    if not status:
        print(out)
        # print 'Unable to find analytics supported module'
        return []
    else:
        return set([i for i in out.split("\n") if i.isdigit()])


def get_module_name(mod):
    """
    **********************************************************************************
    * Function: get_analytics_module
    *
    * Returns: set of module numbers which support analytics
    **********************************************************************************
    """
    cmd = "show module {}".format(mod)
    status, out = cmd_exc(cmd)
    matchModule = {}
    if not status:
        print(out)
        # print 'Unable to find analytics supported module'
        return []
    else:
        out = out.splitlines()
        for line in out:
            matchModule = re.search(
                r"(?P<modinf>\d+)\s+(?P<ports>\d+)\s+(?P<modtype>.*)\s+(?P<model>\w.+)\s+(?P<status>[\w-]+)",
                line,
            )
            if matchModule:
                break
    if matchModule:
        return matchModule["model"].strip()
    else:
        print("Unable to get model name for module {}".format(mod))
        return ""


def get_up_ints_permodule(module):
    """
    **********************************************************************************
    * Function: get_up_ints_permodule
    *
    * Input: module number
    * Returns: list of interfaces which are up in that module
    **********************************************************************************
    """
    status, out = cmd_exc(
        "show interface brief | i fc{}/ | i 'up|trunking' | cut -d ' ' \
                           -f 1".format(
            module
        )
    )
    if not status:
        print(out)
        print("Unable to find any up interface in module {}".format(module))
        return []
    else:
        return [i for i in out.split("\n") if i.startswith("fc") and "/" in i]


def get_down_intf_list(intf_list):
    """
    **********************************************************************************
    * Function: get_down_intf_list
    *
    * Input: interface list
    * Returns: list of interfaces which are down
    **********************************************************************************
    """
    int_str = normalize_ports(intf_list)
    cmd = "show interface {} brief | exclude 'up|trunking' | cut -d ' '-f 1".format(
        int_str
    )
    status, out = cmd_exc(cmd)
    if not status:
        print(out)
        print("Unable to find any up interface in module {}".format(module))
        return []
    else:
        return [i for i in out.split("\n") if i.startswith("fc") and "/" in i]


def get_fc_ints_permodule(module):
    """
    **********************************************************************************
    * Function: get_fc_ints_permodule
    *
    * Input: module number
    * Returns: list of fc interfaces in that module
    **********************************************************************************
    """
    status, out = cmd_exc(
        "show interface brief | i fc{}/ | cut -d ' ' \
                           -f 1".format(
            module
        )
    )
    if not status:
        print(out)
        print("Unable to find any up interface in module {}".format(module))
        return []
    else:
        return [i for i in out.split("\n") if i.startswith("fc") and "/" in i]


def getModuleInfo():
    """
    **********************************************************************************
    * Function: getModuleInfo
    *
    * Returns: Dictionary having details of modules
    **********************************************************************************
    """
    status, out = cmd_exc("show module")
    if not status:
        print(out)
        print('Unable to run "show module" command')
        return []
    else:
        out = out.splitlines()
        mod_deatils = {}
        flag = False
        for line in out:
            if re.search(r"Mod ", line):
                if flag:
                    break
                else:
                    flag = True
            matchModule = re.search(
                r"(?P<modinf>\d+)\s+(?P<ports>\d+)\s+(?P<modtype>.*)\s+(?P<model>\w.+)\s+(?P<status>[\w-]+)",
                line,
            )
            if matchModule:
                data = matchModule.groupdict()
                mod_deatils[data["modinf"]] = {}
                mod_deatils[data["modinf"]]["ports"] = data["ports"]
                mod_deatils[data["modinf"]]["modtype"] = data["modtype"]
                mod_deatils[data["modinf"]]["model"] = data["model"]
                mod_deatils[data["modinf"]]["status"] = data["status"]
    return mod_deatils


def getTermWid():
    """
    **********************************************************************************
    * Function: getTermWid
    *
    * Returns: Width of terminal
    **********************************************************************************
    """
    try:
        cli_out = cli.cli("show running-config all | section terminal | i width")
        term_wid = int(
            [i for i in cli_out.split("\n") if "alias" not in i][0].split(" ")[-1]
        )
    except cli.cli_syntax_error:
        term_wid = 511
    return term_wid


def getVmidFeature():
    """
    ***********************************************************************************
    * Function: getVmidFeature
    *
    * Returns: Bool which is True if vmid feature is enabled else False
    ***********************************************************************************
    """
    status, out = cmd_exc("show running analytics | inc veid")
    if not status:
        return False
    if out == "":
        return False
    else:
        return True


def writeToFile(file_handler, string):
    global working_interface
    global prev_wid
    try:
        file_name = "/bootflash/" + sig_hup_flag
        file_handler = open(file_name, "a+")
        file_handler.write(string)
        file_handler.close()
    except OSError as err:
        syslog.syslog(
            2,
            "ShowAnalytics: Not able to write to a file in bootflash, \
Hence exiting the utility {}".format(
                err
            ),
        )
        os.remove(file_name)
        if working_interface:
            cli.cli(
                "conf t ; interface {} ; no analytics type fc-all\
                    ".format(
                    working_interface
                )
            )
        if prev_wid is not None:
            cli.cli("conf t ; terminal width {}".format(prev_wid))
        sys.exit(0)


class flogi:
    """
    **********************************************************************************
    * Class for parsing show flogi database output
    **********************************************************************************
    """

    def __init__(self, str_out):
        ints = {}
        vsans = {}
        fcids = []
        pwwns = {}
        wwns = {}
        for line in str_out.split("\n"):
            try:
                inte, vsan, fcid, pwwn, wwn = line.split()
            except ValueError:
                continue
            if inte not in ints.keys():
                ints[inte] = [fcid]
            else:
                ints[inte].append(fcid)
            vsans[fcid] = vsan
            fcids.append(fcid)
            pwwns[fcid] = pwwn
            wwns[fcid] = wwn

        self.ints = ints
        self.vsans = vsans
        self.fcids = fcids
        self.pwwns = pwwns
        self.wwns = wwns

    def get_fcids(self, interface):
        if interface in self.ints.keys():
            return self.ints[interface]
        else:
            return []

    def get_vsan(self, fcidd):
        if fcidd in self.vsans.keys():
            return self.vsans[fcidd]
        else:
            return None

    def get_pwwn(self, fcidd):
        if fcidd in self.pwwns.keys():
            return self.pwwns[fcidd]
        else:
            return None


def fcid_Normalizer(fcid):
    """
    **********************************************************************************
    * Function: fcid_Normalizer
    *
    * Input: fcid
    * Returns: fcid in 0xDDAAPP format
    **********************************************************************************
    """
    if len(fcid) == 8:
        return fcid
    elif len(fcid) == 7:
        return fcid[0:2] + "0" + fcid[2:9]
    else:
        return fcid


def getDalias():
    """
    **********************************************************************************
    * Function: getDalias
    *
    * Returns: Dictonary with key as pwwn and value as device-alias
    **********************************************************************************
    """
    pwwn2alias = {}
    try:
        cli_out = cli.cli("show device-alias database")
    except cli.cli_syntax_error:
        return {}

    for line in cli_out.split("\n"):
        line_split = line.split(" ")
        try:
            pwwn2alias[line_split[4]] = line_split[2]
        except (TypeError, IndexError):
            continue
    return pwwn2alias


def getfcid2pwwn():
    """
    **********************************************************************************
    * Function: getfcid2pwwn
    *
    * Returns: Dictonary with key as fcid and value as pwwn
    **********************************************************************************
    """
    fcid2pwwn = {}
    vsan = 1
    try:
        cli_out = cli.cli("show fcns database")
        cli_out = cli_out.strip()
        if ":" not in cli_out:
            return {}
    except (cli.cli_syntax_error, ValueError, IndexError):
        return {}
    for line in cli_out.split("\n"):
        if ":" not in line:
            continue
        if "VSAN" in line:
            vsan = int(line.split(" ")[-1][:-1])
            continue
        line_split = line.split(" ")
        try:
            fcid2pwwn[(line_split[0], vsan)] = line_split[9]
        except (ValueError, IndexError):
            continue
    return fcid2pwwn


def alias_maker(init_fcid, targ_fcid, f2p, p2a, vsan):
    """
    **********************************************************************************
    * Function: alias_maker
    *
    * Returns: List of the following:
    *       string: initiator device alias name (or null) + '::' + target
    *               device alias name (or null).
    *       bool: True if either or both device alias were found,
    *             False if niether device alias was found.
    **********************************************************************************
    """

    iav = False
    alias_str = ""
    for fcid in [init_fcid, targ_fcid]:
        val = "  "
        if (str(fcid), int(vsan)) in f2p:
            pwn = f2p[(str(fcid), int(vsan))]
            if pwn in p2a:
                iav = True
                val = p2a[pwn]
        alias_str = alias_str + "::" + val
    return [alias_str, iav]


def parse_module(module_str):
    """
    **********************************************************************************
    * Function: parse_module
    *
    * Input: module string like 1-9,11
    * Returns: list of module numbers like [1,2,3,4,5,6,7,8,9,11]
    **********************************************************************************
    """
    module = []
    for mod in module_str.split(","):
        if "-" in mod:
            try:
                st, en = [i for i in mod.split("-") if i.isdigit()]
            except (IndexError, ValueError):
                print("Invalid module {}".format(mod))
                return []
            module.extend(range(int(st), int(en) + 1))
            module = list(map(str, module))
        else:
            if mod.isdigit():
                module.append(mod)
            else:
                print("Invalid module {}".format(mod))
    return module


def parse_intlist(intlist_str):
    """
    **********************************************************************************
    * Function: parse_intlist
    *
    * Input: interface string like fc1/9-12,fc2/13,fc3/14
    * Returns: List of interfaces like ['fc1/9', 'fc1/10', 'fc1/11',
    *                                   'fc1/12', 'fc2/13', 'fc3/14']
    **********************************************************************************
    """
    intlist = []
    if "port-channel" in intlist_str:
        print("port-channel is not supported for --evaluate-npuload option")
        return []
    for inte in intlist_str.split(","):
        if "-" in inte:
            start_int, end_int = [i.strip() for i in inte.split("-")]
            if not start_int.startswith("fc"):
                print("Invalid interface {}".format(start_int))
                return []
            try:
                start_mod, start_port = [
                    i for i in start_int[2:].split("/") if i.isdigit()
                ]
            except (IndexError, ValueError):
                print("Invalid interface {}".format(start_int))
                return []
            if end_int.startswith("fc"):
                try:
                    end_mod, end_port = [
                        i for i in end_int[2:].split("/") if i.isdigit()
                    ]
                except (IndexError, ValueError):
                    print("Invalid interface {}".format(end_int))
                    return []
                if start_mod != end_mod:
                    print(
                        "Invalid interface range {} as start and end \
module number are different".format(
                            inte
                        )
                    )
                    return []
                intlist.extend(
                    [
                        "fc" + str(start_mod) + "/" + str(i)
                        for i in range(int(start_port), int(end_port) + 1)
                    ]
                )

            else:
                if not end_int.isdigit():
                    print("Invalid Interface range {}".format(inte))
                    return []
                else:
                    intlist.extend(
                        [
                            "fc" + str(start_mod) + "/" + str(i)
                            for i in range(int(start_port), int(end_int) + 1)
                        ]
                    )

        else:
            if re.match(r"fc\d+\/\d+", inte):
                intlist.append(inte)
            else:
                print("Invalid interface {}".format(inte))
                return []

    return intlist


def time_formator(sec_count):
    """
    **********************************************************************************
    * Function: time_formator
    *
    * Input: Int number of seconds
    * Returns: String in format of seconds , minutes and hours
    *          like - 2 hours 10 minutes 30 seconds
    **********************************************************************************
    """
    out = ""
    if sec_count > 3600:
        out += "{} hours ".format(sec_count // 3600)
        sec_count = sec_count % 3600
    if sec_count > 60:
        out += "{} minutes ".format(sec_count // 60)
        sec_count = sec_count % 60
    out += "{} seconds".format(sec_count)
    return out


def calculate_max_sample_window(iops_list, flow_list):
    """
    **********************************************************************************
    * Function: calculate_max_sample_window
    *
    * Input: It takes 2 lists as input which are as follows:
    *          - iops_list : List of active iops for each port
               - flow_list : List of ITL+ITN flows for ports
    * Returns: Maximum number of flows that can supported in 1 sampling window
    **********************************************************************************
    """
    iops_list.sort(reverse=True)
    flow_list.sort(reverse=True)
    for i in range(1, len(iops_list) + 1):
        if sum(iops_list[:i]) == 100:
            return i
        if sum(flow_list[:i]) == 20000:
            return i
        if sum(iops_list[:i]) > 100:
            return i - 1
        if sum(flow_list[:i]) > 20000:
            return i - 1
    return "default"


def check_analytics_conf_per_module(mod, mod_details):
    """
    **********************************************************************************
    * Function: check_analytics_conf_per_module
    *
    * Input: Int module number
    * Returns: Bool which is True if not even single interface on that
    *          module has analytics configured and else False
    **********************************************************************************
    """
    ports = mod_details[str(mod)]["ports"]
    cmd = "show running-config interface fc{0}/1-{1} | i 'analytics type'".format(
        mod, ports
    )
    status, out = cmd_exc(
        "show running-config interface fc{0}/1-{1} | i 'analytics type'".format(
            mod, ports
        )
    )
    if not status:
        print(out)
        print("Unable to get analytics configuration for module {}".format(mod))
        return True
    if out != "":
        return True
    return False


def check_port_sampling_per_module(mod, amc_modules, mod_details):
    """
    **********************************************************************************
    * Function: check_port_sampling_per_module
    *
    * Input: Int module number
    * Returns: Bool which is True sampling window size is less than 4
    *          else False
    **********************************************************************************
    """
    ports = mod_details[str(mod)]["ports"]
    if str(mod) not in amc_modules:
        status, out = cmd_exc(
            "show analytics port-sampling module {} | \
i 'Sampling Window Size:'".format(
                mod
            )
        )
        if not status:
            print(out)
            print("Unable to get analytics configuration for module {}".format(mod))
            return True
        samplingWindow = int(out.split(":")[1])
        if samplingWindow != int(ports):
            return True
    return False


def verifyAnalyticsFeature():
    """
    **********************************************************************************
    * Function: verifyAnalyticsFeature
    *
    * Returns: Bool which is True if feature analytics is enabled
    *          else False
    **********************************************************************************
    """
    status, out = cmd_exc("show feature | i analytics")
    if not status:
        print(out)
        print("Unable to get feature details")
        return False
    if "disabled" in out:
        return False
    return True


def extract_module_from_port(inte):
    """
    **********************************************************************************
    * Function: extract_module_from_port
    *
    * Input: String Describing the interface like fc1/2
    * Returns: Int describing the module number of that interface like 1
    **********************************************************************************
    """
    if "/" in inte:
        return int(inte.split("/")[0].split("c")[1])
    else:
        return 0


def validateArgs(arg, swver):
    """
    **********************************************************************************
    * Function: validateArgs
    *
    * Input: Object of argparse constructed by :
    *           - command line arguments
    *           - software_version_str
    * Returns: Bool which is True if validation of argument passes and
    *          False otherwise.
    **********************************************************************************
    """

    if args.initiator_itn or args.target_itn or args.nvme:
        ver1 = "".join([i for i in swver if i.isdigit()])
        if int(ver1) < 841 or len(ver1) < 3:
            print("NVMe is not compatible with NXOS version {0}".format(swver))
            return False

    if (
        not args.info
        and not args.errors
        and not args.errorsonly
        and not args.minmax
        and not args.evaluate_npuload
        and not args.vsan_thput
        and not args.top
        and not args.outstanding_io
        and not args.systemload_active
        and not args.histogram
    ):
        print(
            "\n Please choose an action via --info or \
--minmax or --errors or --errorsonly or --evaluate-npuload or \
--vsan-thput or --top or --outstanding-io or --systemload-active or --histogram option\n"
        )
        return False

    if (
        int(args.info)
        + int(args.minmax)
        + int(args.errors)
        + int(args.errorsonly)
        + int(args.evaluate_npuload)
        + int(args.vsan_thput)
        + int(args.top)
        + int(args.outstanding_io)
        + int(args.systemload_active)
        + int(args.histogram)
        > 1
    ):
        print(
            "\nPlease choose a single option out of --info,\
--errors, --errorsonly, --minmax, --evaluate-npuload, \
--vsan-thput, --top, --outstanding-io and --systemload-active and --histogram\n"
        )
        return False

    if (
        not args.initiator_itl
        and not args.target_itl
        and not args.initiator_it
        and not args.target_it
        and not args.initiator_itn
        and not args.target_itn
        and not args.evaluate_npuload
        and not args.vsan_thput
        and not args.top
        and not args.outstanding_io
        and not args.systemload_active
        and not args.histogram
    ):
        print(
            "\n Please choose a table type via --initiator-itl \
or --target-itl or --initiator-it or --target-it or \
--initiator-itn or --target-itn option\n"
        )
        return False

    if (
        int(args.initiator_itl)
        + int(args.target_itl)
        + int(args.initiator_it)
        + int(args.target_it)
        + int(args.initiator_itn)
        + int(args.target_itn)
        > 1
    ):
        print(
            "\n Please choose a single table type via --initiator-itl \
or --target-itl or --initiator-it or --target-it or --initiator-itn \
or --target-itn\n"
        )
        return False

    if args.nvme and args.evaluate_npuload:
        print(
            "--nvme option is not required for --evaluate-npuload. \
It by default consider both scsi and nvme"
        )
        return False

    if args.nvme and (args.initiator_itl or args.target_itl):
        print("To get NVMe stats select --initiator-itn or --target-itn option")
        return False

    if args.namespace:
        if not args.nvme:
            print(
                "--namespace argument is only supported with --nvme or \
--initiator-itn or --target-itn"
            )
            return False
        if not (
            args.initiator_itn or args.target_itn or args.top or args.outstanding_io
        ):
            print("--namespace argument is not supported with current option")
            return False

    if args.initiator:
        try:
            initiator_id = int(args.initiator, 16)
            if initiator_id >> 32:
                print("Please enter a valid initiator id in hexadecimal format")
                return False
        except ValueError:
            print("Please enter a valid initiator id in hexadecimal format")
            return False

    if args.target:
        try:
            target_id = int(args.target, 16)
            if target_id >> 32:
                print("Please enter a valid target id in hexadecimal format")
                return False
        except ValueError:
            print("Please enter a valid target id in hexadecimal format")
            return False

    if args.alias:
        if not (
            args.errors
            or args.errorsonly
            or args.info
            or args.minmax
            or args.top
            or args.outstanding_io
        ):
            print(
                "\n Alias option is only supported with --errors or \
--errorsonly or --info or --minmax or --top or --outstanding-io\n"
            )
            return False
    if args.lun:
        lun = "0x" + ((args.lun).replace("-", ""))[::-1]
        try:
            lun_id = int(lun, 16)
            if lun_id >> 64:
                print(
                    "Please enter a valid lun id in \
xxxx-xxxx-xxxx-xxxx format"
                )
                return False
        except ValueError:
            print("Please enter a valid lun id in xxxx-xxxx-xxxx-xxxx format")
            return False

    if (
        args.initiator_itl
        or args.target_itl
        or args.initiator_it
        or args.target_it
        or args.target_itn
        or args.initiator_itn
    ) and (
        not (
            args.info or args.errors or args.minmax or args.errorsonly or args.histogram
        )
    ):
        print(
            "--initiator-itl or --target-itl or --initiator-itn or --target-itn or --initiator-it or \
--target-it is only supported with --info or --errors or \
--errorsonly or --minmax or --histogram"
        )
        return False

    if args.limit:
        try:
            args.limit = int(args.limit)
        except ValueError:
            print(
                "--limit supports integer value from 1 to {}\
".format(
                    max_flow_limit
                )
            )
            return False
        if args.top:
            if args.limit >= 1 and args.limit <= 50:
                global top_limit
                top_limit = args.limit
                args.limit = 20000
            elif args.limit != 20000:
                print("--limit supports integer value from 1 to 50")
                return False
        if (args.limit > int(max_flow_limit)) or (args.limit < 1):
            print(
                "--limit supports integer value from 1 to {}\
".format(
                    max_flow_limit
                )
            )
            return False

    if args.key:
        if not args.top:
            print("--key only works with --top option")
            return False
        try:
            args.key = args.key.upper()
        except AttributeError:
            print("--key can only take thput or iops or ect")
            return False
        ver2 = int("".join([i for i in swver if i.isdigit()])[:3])
        if int(ver2) >= 922:
            keyList = ["IOPS", "THPUT", "ECT", "IOSIZE", "BUSY"]
        else:
            keyList = ["IOPS", "THPUT", "ECT", "IOSIZE"]
        if args.key not in keyList:
            print(" {0}  is not a valid key".format(args.key))
            return False
    if args.progress or args.noclear:
        if not args.top:
            print("--progress and --noclear only work with --top option")
            return False
    if args.top:
        if int(args.it_flow) + int(args.initiator_flow) + int(args.target_flow) > 1:
            print(
                "\nPlease choose a single option out of --it-flow, --initiator-flow, --target-flow \
with --top"
            )
            return False
    if args.it_flow or args.initiator_flow or args.target_flow:
        if not args.top:
            print(
                "--it-flow, --initiator-flow, --target-flow work only with --top option"
            )
            return False
        if args.lun or args.namespace:
            print(
                "--lun or --namespace not supported with --it-flow, --initiator-flow, --target-flow"
            )
            return False
        if args.initiator_flow:
            if args.target:
                print("--target not supported with --initiator-flow")
                return False
        if args.target_flow:
            if args.initiator:
                print("--initiator not supported with --target-flow")
                return False
    if args.module:
        if not (args.evaluate_npuload or args.systemload_active):
            print("--module only works with --evaluate-npuload and --systemload-active")
            return False
        if args.interface:
            print("--module is not supported with --interface")
            return False
        module = parse_module(args.module)
        if args.evaluate_npuload:
            analytics_mods = get_analytics_module(swver)
            invalid_module = [i for i in module if i not in analytics_mods]
            if invalid_module != []:
                print(
                    "Module {} does not support analytics or module not present\
".format(
                        ",".join(invalid_module)
                    )
                )
                module = [i for i in module if i not in invalid_module]
        if args.systemload_active:
            analytics_mods = get_analytics_module(swver)
            invalid_module = [i for i in module if i not in analytics_mods]
            if invalid_module != []:
                print(
                    "Module {} does not support analytics or module not present\
".format(
                        ",".join(invalid_module)
                    )
                )
                module = [i for i in module if i not in invalid_module]
        if module == []:
            print("Please provide valid module list")
            return False
        args.module = module

    if args.interface:

        global interface_list

        if args.systemload_active:
            print("--interface not supported with --systemload-active")
            return False
        if not args.evaluate_npuload:
            if "," in args.interface:
                print("Please provide Single interface only")
                return False
            if not re.match(r"fc\d+\/\d+", args.interface):
                if (not args.vsan_thput) or (
                    not re.match(r"port-channel\d+", args.interface)
                ):
                    print("Please provide Valid Interface")
                    return False

        if args.module:
            print("--interface is not supported with --module")
            return False
        if args.evaluate_npuload:
            intlist = parse_intlist(args.interface)
        else:
            intlist = [args.interface]
        if args.vsan_thput:
            pcre = re.match(r"port-channel(\d+)", args.interface)
            if pcre is not None:
                pc_num = int(pcre.group(1))
                po_mem_out = cli.cli(
                    "show port-channel database interface \
                                     port-channel {0} | i up".format(
                        pc_num
                    )
                )
                intlist = re.findall(r"fc\d+\/\d+", po_mem_out)
                if intlist == []:
                    print(
                        "Port-channel {0} has no operational member\
".format(
                            pc_num
                        )
                    )
                    return False
                intlist1 = [k for k in intlist if check_port_is_analytics_enabled(k)]
                if intlist1 != intlist:
                    print(
                        "Some members of {} does not support analytics or \
analytics is not enabled on them".format(
                            args.interface
                        )
                    )
                    return False
        if args.evaluate_npuload:
            analytics_mods = get_analytics_module(swver)
            invalid_intlist = [
                i for i in intlist if i.strip().split("/")[0][2:] not in analytics_mods
            ]
            if invalid_intlist != []:
                print(
                    "Interface {} does not support analytics\
".format(
                        ",".join(invalid_intlist)
                    )
                )
            intlist = [i for i in intlist if i not in invalid_intlist]
            if intlist == []:
                print("Please provide valid interface")
                return False

            interface_list = intlist
            args.interface = None

        elif args.vsan_thput:
            if pcre:
                interface_list = [args.interface, intlist]
                args.interface = None

    if args.vsan_thput:
        if args.alias or args.initiator or args.target or args.module:
            print("--vsan-thput only supports --interface argument")
            return False

    if args.outstanding_io:
        if args.interface is None:
            print(
                "--outstanding-io is interface specific option .. \
Please specify interface and try again"
            )
            return False

    if args.refresh:
        if not args.outstanding_io:
            print("--refresh is only supported with --outstanding-io")
            return False

    if args.outfile and args.appendfile:
        print("Please use either --outfile or --appendfile")
        return False

    if args.histogram:
        if (
            not args.initiator_itl
            and not args.target_itl
            and not args.initiator_it
            and not args.target_it
            and not args.initiator_itn
            and not args.target_itn
            and not args.initiator
            and not args.target
            and not args.show_sessions
            and not args.stop_session
            and not args.sessionId
        ):
            print(
                "\n Please choose a table type via --initiator-itl or --target-itl \
or --initiator-it or --target-it or --initiator-itn or  --target-itn or --initiator \
or --target or --show-sessions or --stop-session option\n"
            )
            return False
        if args.stop_session:
            if not args.sessionId:
                print(
                    "Please provide histogram monitor session ID\n \
Use histogram --show-session to get the session IDs"
                )
                return False
            else:
                if args.sessionId.upper() == "ALL":
                    args.sessionId = "ALL"
                else:
                    args.sessionId = args.sessionId.split(",")
                    for sessionId in args.sessionId:
                        try:
                            ssession_id = int(sessionId)
                        except ValueError:
                            print(
                                "sessionId can take either 'ALL' or histogram session id(s)"
                            )
                            return False
        if args.sessionId:
            if not args.stop_session:
                try:
                    ssession_id = int(args.sessionId)
                except ValueError:
                    print("--sessionId takes single histogram sessionId")
                    return False
        if args.initiator_itl or args.target_itl:
            if not args.initiator or not args.target or not args.lun:
                print("Please provide all three Initiator , Target and Lun")
                return False
        if args.initiator_itn or args.target_itn:
            if not args.initiator or not args.target or not args.namespace:
                print("Please provide all three Initiator , Target and Namespace")
                return False
        if args.initiator_it or args.target_it:
            if not args.initiator or not args.target:
                print("Please provide Initiator and Target")
                return False
        if args.initiator and args.target and args.lun:
            if not args.initiator_itl and not args.target_itl:
                print(
                    "\n Please choose a table type via --initiator-itl or --target-itl"
                )
                return False
        elif args.initiator and args.target and args.namespace:
            if not args.initiator_itn and not args.target_itn:
                print(
                    "\n Please choose a table type via --initiator-itn or --target-itn"
                )
        elif args.initiator and args.target:
            if not args.initiator_it and not args.target_it:
                print("\n Please choose a table type via --initiator-it or --target-it")
                return False
    if args.interval:
        if not args.histogram:
            print("--interval only works with --histogram option")
            return False
        # durList = ['1hr','2hr','6hr','12hr','18hr','24hr']
        try:
            if int(args.interval) > 120 or int(args.interval) < 5:
                print(
                    "--interval  supports integer value from 5 to 120 (in minutes). Default = 5"
                )
                return False
        except ValueError:
            print(
                "--interval  supports integer value from 5 to 120 (in minutes). Default = 5"
            )
            return False

    if args.metric:
        if not args.histogram:
            print("--metric only works with --histogram option")
            return False
        try:
            metricList = ["IOPS", "ECT", "DAL", "ERRORS", "ALL"]
            args.metric = [x.upper() for x in args.metric.split(",")]
            for metric in args.metric:
                if metric not in metricList:
                    print(" {0} is not a valid metric".format(metric))
                    print(" Valid inputs - {0}".format(", ".join(metricList)))
                    return False
        except AttributeError:
            print("--metric can only take iops or ect or dal or errors")
            return False

    return True


def thput_conv(thput_val):
    """
    **********************************************************************************
    * Function: thput_conv
    *
    * Input: Int read from analytics metrics
    * Returns: String showing throughput in format of GB/s or MB/s or KB/s
    *          or B/s
    **********************************************************************************
    """

    try:
        out1 = float(thput_val)
    except ValueError:
        return "NA"

    if out1 == 0.000:
        return "0 B/s"
    elif out1 >= 1073741824:
        return "{0:3.1f} GB/s".format(float(out1 / 1073741824))
    elif out1 >= 1048576:
        return "{0:3.1f} MB/s".format(float(out1 / 1048576))
    elif out1 >= 1024:
        return "{0:3.1f} KB/s".format(float(out1 / 1024))
    else:
        return "{0:3.1f} B/s".format(float(thput_val))


def size_conv(size_val):
    """
    **********************************************************************************
    * Function: size_conv
    *
    * Input: Int read from analytics metrics
    * Returns: String showing size in format of GB or MB or KB
    *          or B
    **********************************************************************************
    """

    try:
        out1 = float(size_val)
    except ValueError:
        return "NA"

    if out1 == 0.000:
        return "0 B"
    elif out1 >= 1073741824:
        return "{0:3.1f} GB".format(float(out1 / 1073741824))
    elif out1 >= 1048576:
        return "{0:3.1f} MB".format(float(out1 / 1048576))
    elif out1 >= 1024:
        return "{0:3.1f} KB".format(float(out1 / 1024))
    else:
        return "{0:3.1f} B".format(float(size_val))


def time_conv(time_val):
    """
    **********************************************************************************
    * Function: time_conv
    *
    * Input: Int number of seconds
    * Returns: String showing time in format '120.0 ns' or '120.1 us'
    *          or '120.1 ms' or '120.1 s'
    **********************************************************************************
    """

    try:
        out1 = float(time_val)
    except ValueError:
        return "NA"

    if out1 == 0.000:
        if args.top:
            return "0 ns "
        return "0 ns "
    elif out1 < 1:
        return "{0:3.1f} ns".format(float(out1 * 1000))
    elif out1 >= 1000000:
        return "{0:3.1f} s".format(float(out1 / 1000000))
    elif out1 >= 1000:
        return "{0:3.1f} ms".format(float(out1 / 1000))
    else:
        return "{0:3.1f} us".format(float(out1))


def tick_to_time(tick):
    """
    **********************************************************************************
    * Function: tick_to_time
    *
    * Input: Int number of ticks
    * Returns: Int number of microseconds
    **********************************************************************************
    """
    out1 = float(tick) / 256
    return time_conv(out1)


def getMinMaxAvg(min_col, max_col, total_col, count_col):
    """
    **********************************************************************************
    * Function: getMinMaxAvg
    *
    * Input: This function takes 4 arguments
    *            - min_col : minimum io time
    *            - max_col : maximum io time
    *            - total_col : total io time
    *            - count_col : number of io
    * Returns: String which is '/' seperated minimum_time, maximum_time,
    *          average_time.
    **********************************************************************************
    """
    min_val = 0
    max_val = 0
    avg_val = 0
    if min_col in json_out["values"]["1"]:
        min_val = json_out["values"]["1"][min_col]

    if max_col in json_out["values"]["1"]:
        max_val = json_out["values"]["1"][max_col]

    if (
        total_col in json_out["values"]["1"]
        and count_col in json_out["values"]["1"]
        and int(float(json_out["values"]["1"][count_col])) > 0
    ):
        try:
            avg_val = int(float(json_out["values"]["1"][total_col])) / int(
                float(json_out["values"]["1"][count_col])
            )
        except ZeroDivisionError:
            avg_val = 0

    return str(min_val) + "/" + str(max_val) + "/" + str(avg_val)


def getAnalyticsEnabledPorts():
    """
    **********************************************************************************
    * Function: getAnalyticsEnabledPorts
    *
    * Returns: List of interfaces on which analytics is enabled
    **********************************************************************************
    """
    out = []
    j_s = ""
    if args.nvme:
        qry = "select port from fc-nvme.logical_port"
    else:
        qry = "select port from fc-scsi.logical_port"
    try:
        j_s = cli.cli("show analytics query '" + qry + "'")
        j_s = json.loads(j_s)
    except json.decoder.JSONDecodeError:
        j_s = None
        pass
    sizeJson = len(j_s["values"])
    counter = 1
    while counter <= sizeJson:
        for key, value in j_s["values"][str(counter)].items():
            if str(key) == "port":
                if value not in out:
                    out.append(str(value))
        counter += 1
    return out


def getEPorts():
    """
    **********************************************************************************
    * Function: getEPorts
    *
    * Returns: List of all the interface which are in mode E as per
    *          show interface brief output.
    **********************************************************************************
    """
    eports_out = cli.cli("show interface brief | i fc | i E | i trunk")
    eports = re.findall(r"fc\d+\/\d+|vfc\d+\/\d+|vfc\d+", eports_out)
    return eports


def getNPSDPorts():
    """
    **********************************************************************************
    * Function: getNPSDPorts
    *
    * Returns: List of all the interface which are in mode NP or SD as per
    *          show interface brief output.
    **********************************************************************************
    """
    npports_out = cli.cli('show interface brief | i fc | i "NP|SD"')
    npports = re.findall(r"fc\d+\/\d+|vfc\d+\/\d+|vfc\d+", npports_out)
    return npports


def getPureFPorts():
    """
    **********************************************************************************
    * Function: getPureFPorts
    *
    * Returns: List of all the interface which are in mode F as per
    *          show interface brief output
    **********************************************************************************
    """
    fports_out = cli.cli("show interface brief | ex not | ex TF | i F | i up")
    fports = re.findall(r"fc\d+\/\d+|vfc\d+\/\d+|vfc\d+", fports_out)
    return fports


def getFPorts():
    """
    **********************************************************************************
    * Function: getFPorts
    *
    * Returns: List of all the interface which are in mode F as per
    *          show interface brief output
    **********************************************************************************
    """
    fports_out = cli.cli("show interface brief | ex not | i F | i up|trunk")
    fports = re.findall(r"fc\d+\/\d+|vfc\d+\/\d+|vfc\d+", fports_out)
    return fports


def getInterfaceStats(inte_list):
    """
    **********************************************************************************
    * Function: getInterfaceStats
    *
    * Returns: in/out rate, in/out frames and %Txwait for all interfaces
    **********************************************************************************
    """
    # int_str = ",".join(inte_list)
    int_str = normalize_ports(inte_list)
    # print(inte_list)
    # print(int_str)
    out = cli.cli("show interface {} counters".format(int_str))
    pattern1 = r"5 minutes input rate (\d+) bits/sec, (\d+) bytes/sec, (\d+) frames/sec"
    pattern2 = (
        r"5 minutes output rate (\d+) bits/sec, (\d+) bytes/sec, (\d+) frames/sec"
    )
    pattern3 = r"TxWait for last 1s/1m/1h/72h: (\S+)"
    pattern4 = r"(\d+)\s+frames input"
    pattern5 = r"(\d+)\s+frames output"

    rxUtil, rxUtil = 0, 0
    retDict = {}
    intDict = {}

    for line in out.splitlines():
        pat = r"(^fc\d+(?:\/\d+)*)"
        match = re.search(pat, line)
        if match:
            intf = match.group(1)
            inrate, outrate, txwait, inputframes, outputframes = "", "", "", "", ""
        match = re.search(pattern1, line)
        if match:
            inrate = match.group(2)
        match = re.search(pattern2, line)
        if match:
            outrate = match.group(2)
        match = re.search(pattern3, line)
        if match:
            txwait = match.group(1)
        match = re.search(pattern4, line)
        if match:
            inputframes = match.group(1)
        match = re.search(pattern5, line)
        if match:
            outputframes = match.group(1)
        intDict[intf] = {
            "inrate": inrate,
            "outrate": outrate,
            "txWait": txwait,
            "inframes": inputframes,
            "outframes": outputframes,
        }

    return intDict


def getInterfaceSpeeds(inte_list):
    """
    **********************************************************************************
    * Function: getInterfaceSpeeds
    *
    * Returns: Operating speed for all interfaces
    **********************************************************************************
    """
    int_str = normalize_ports(inte_list)
    out1 = cli.cli("show interface {}".format(int_str))
    pattern4 = r"Operating Speed is (\d+) Gbps"
    intDict = {}
    for line in out1.splitlines():
        pat = r"(^fc\d+(?:\/\d+)*)"
        match = re.search(pat, line)
        if match:
            intf = match.group(1)
            opspeed = ""
        match = re.search(pattern4, line)
        if match:
            opspeed = match.group(1)
        intDict[intf] = {"opspeed": opspeed}

    return intDict


def getIntedetails(inte_list, intstatsDict, intspeedDict):
    """
    **********************************************************************************
    * Function: getIntedetails
    *
    * Returns: Rx/Tx utilisation, txWait for each interface
    **********************************************************************************
    """

    # speedDict = {'2':200,'4':400,'8':800,'16':1600,'32':3200,'64':6400}

    retDict = {}
    for inte in inte_list:
        retDict[inte] = {}
        # 1 Gbit = 125 MB.
        # Max throughput is 80% of bandwidth
        max_thput = int(intspeedDict[inte]["opspeed"]) * 125 * 0.8
        rxUtil = ((float(intstatsDict[inte]["inrate"]) / 1000000) / max_thput) * 100
        txUtil = ((float(intstatsDict[inte]["outrate"]) / 1000000) / max_thput) * 100
        retDict[inte]["rxUtil"] = str(round(rxUtil, 2))
        retDict[inte]["txUtil"] = str(round(txUtil, 2))
        retDict[inte]["txWait"] = intstatsDict[inte]["txWait"]

    return retDict


def vsanNormalizer(vsan_str):
    """
    Parse Vsan Range and convert it into list
    1-10   => [1,2,3,4,5,6,7,8,9,10]
    20,30  => [10, 30]
    """
    out = []
    split1 = vsan_str.split(",")
    for vsan_ins in split1:
        if "-" in vsan_ins:
            vsan_range = vsan_ins.split("-")
            try:
                start_vsan, end_vsan = map(int, vsan_range)
                out.extend(range(start_vsan, end_vsan + 1))
            except (TypeError, ValueError, IndexError):
                print("Unable to Parse Vsan range {}".format(vsan_ins))
                continue
        else:
            try:
                out.append(int(vsan_ins))
            except (TypeError, AttributeError, ValueError):
                print("Unable to Parse Vsan range {}".format(vsan_ins))
                continue
    return out


def getVsansPerEPort(prt):
    """
    **********************************************************************************
    * Function: getVsansPerEPort
    *
    * Input: String describing the interface like fc1/1
    * Returns: List of all the vsans that are allowed on that interface
    **********************************************************************************
    """
    out = []
    try:
        upvsan_out = cli.cli("show interface " + str(prt) + " | i up")
        out1 = re.search(r"\(up\)\s+\(([0-9-,]+)\)", upvsan_out)
    except Exception:
        print("Unknown Interface " + str(prt))
        exit()
    if out1 is not None:
        out.extend(vsanNormalizer(out1.group(1)))
    return out


def read_write_stats(read_thput, write_thput, rios, wios, rir, wir):

    """
    This Function add control part also to the rate
    read/write_thput : read/write rate in bytes/s
    rios/wios : read/write io size
    rir/wir : read/write rate in iops
    For each io if block size is > 2048 then more frames are required
    Each Frame has header payload also

    Fc Header + Footer : 36 Bytes
    Average Write Command scsi payload : 32 Bytes
    Average Read Command scsi payload : 32 Bytes
    Status Scsi Payload : 12 Bytes
    XRDY Payload : 12 Bytes
    Idle Full : 4 Bytes
    FC4XRdy Full : 48 Bytes

    affected_read = (number_of_frames_per_cmd * fc_header_footer_size +
    (scsi_cmd_payload + 2*fc_header_footer_size
     + scsi_status_payload))*read_iops + read_data_thput

                  = (number_of_frames_per_cmd*36 + (32+72+12))*read_iops
                  + read_data_thput

                  = (number_of_frames_per_cmd*36 + 116)*read_iops
                  + read_data_thput



    affected_write = (number_of_frames_per_cmd * fc_header_footer_size +
    (scsi_cmd_payload + 3*fc_header_footer_size + scsi_status_payload
     + xrdy_payload))*read_iops + write_data_thput

                   = (number_of_frames_per_cmd*36
                      + (32+108+12+12))*write_iops + write_data_thput

                   = (number_of_frames_per_cmd*36 + 164)*write_iops
                   + write_data_thput

    """

    if int(read_thput) != 0:
        rd_pkt_cnt_pr_cmd = rios / 2048
        if rios % 2048 != 0:
            rd_pkt_cnt_pr_cmd += 1
        affected_read = (((rd_pkt_cnt_pr_cmd * 36) + 116) * rir) + read_thput
        # affected_read = (((rd_pkt_cnt_pr_cmd*36) + (52)) * rir) + read_thput
    else:
        affected_read = 0
    if int(write_thput) != 0:
        wr_pkt_cnt_pr_cmd = wios / 2048
        if wios % 2048 != 0:
            wr_pkt_cnt_pr_cmd += 1
        affected_write = (((wr_pkt_cnt_pr_cmd * 36) + 164) * wir) + write_thput
    else:
        affected_write = 0

    return [affected_read, affected_write]


def displayDetailOverlay(json_out, ver=None):
    """
    **********************************************************************************
    * Function: displayDetailOverlay
    *
    * Input: json_out is the json data returned by switch as response for
    *           querry
    *        ver is software version of switch
    * Action: Displays detailed statistics of a particular ITL/N
    * Returns: None
    **********************************************************************************
    """

    col_names = ["Metric", "Min  ", "Max  ", "Avg  "]

    t = PrettyTable(col_names)
    t.align["Metric"] = "l"
    t.align["Min  "] = "r"
    t.align["Max  "] = "r"
    t.align["Avg  "] = "r"
    ver1 = int("".join([i for i in ver if i.isdigit()])[:3])

    print()
    print("B: Bytes, s: Seconds, Avg: Average, Acc: Accumulative,")
    print("ns: Nano Seconds, ms: Milli Seconds, us: Micro Seconds,")
    print("GB: Giga Bytes, MB: Mega Bytes, KB: Killo Bytes,")
    print("ECT: Exchange Completion Time, DAL: Data Access Latency")
    print()
    if args.outfile or args.appendfile:
        try:
            fh.write("B: Bytes, s: Seconds, Avg: Average, Acc: Accumulative," + "\n")
            fh.write("ns: Nano Seconds, ms: Milli Seconds, us: Micro Seconds," + "\n")
            fh.write("GB: Giga Bytes, MB: Mega Bytes, KB: Killo Bytes," + "\n")
            fh.write("ECT: Exchange Completion Time, DAL: Data Access Latency" + "\n")
        except OSError as err:
            print("Not able to write to a file, No space left on device")
            sys.exit(0)
    if "port" in json_out["values"]["1"]:
        print("\nInterface : " + json_out["values"]["1"]["port"])
        if args.outfile or args.appendfile:
            try:
                fh.write("\nInterface : " + json_out["values"]["1"]["port"] + "\n")
            except OSError as err:
                print("Not able to write to a file, No space left on device")
                sys.exit(0)

    if args.alias:
        vsan = json_out["values"]["1"]["vsan"]
        fcid2pwwn = getfcid2pwwn()
        pwwn2alias = getDalias()
        if (str(args.initiator), int(vsan)) in fcid2pwwn:
            init_pwwn = fcid2pwwn[(str(args.initiator), int(vsan))]
            if init_pwwn in pwwn2alias:
                print(
                    "Initiator Device-alias : {}\
".format(
                        pwwn2alias[init_pwwn]
                    )
                )
        if (str(args.target), int(vsan)) in fcid2pwwn:
            tar_pwwn = fcid2pwwn[(str(args.target), int(vsan))]
            if tar_pwwn in pwwn2alias:
                print("Target Device-alias : {}".format(pwwn2alias[tar_pwwn]))

    conv = {
        "read_io_rate": "Read  IOPS",
        "write_io_rate": "Write IOPS",
        "read_io_bandwidth": "Read  Throughput",
        "write_io_bandwidth": "Write Throughput",
    }
    for key in [
        "read_io_rate",
        "write_io_rate",
        "read_io_bandwidth",
        "write_io_bandwidth",
    ]:
        if key in json_out["values"]["1"]:
            col_values = []
            salt = "       "
            if "rate" not in key:
                salt = " "
            col_values.append("{0} {1} {2}".format(conv[key], salt, "(4sec Avg)"))
            col_values.append("NA")
            col_values.append("NA")
            out_val = json_out["values"]["1"][key]
            if "rate" not in key:
                if int(out_val) != 0:
                    out_val = thput_conv(out_val)
            col_values.append(out_val)
            t.add_row(col_values)

    trib, twib, tric, twic = (
        "total_time_metric_based_read_io_bytes",
        "total_time_metric_based_write_io_bytes",
        "total_time_metric_based_read_io_count",
        "total_time_metric_based_write_io_count",
    )
    if ver == "8.3(1)":
        trib, twib, tric, twic = (
            "total_read_io_bytes",
            "total_write_io_bytes",
            "total_read_io_count",
            "total_write_io_count",
        )

    # io size
    col_values = []
    col_values.append("Read  Size         (Acc Avg)")
    miin, maax, avg = getMinMaxAvg(
        "read_io_size_min", "read_io_size_max", trib, tric
    ).split("/")
    col_values.extend(
        map(
            lambda x: "{} B".format(x) if int(float(x)) != 0 else 0,
            [miin, maax, math.ceil(float(avg))],
        )
    )
    t.add_row(col_values)

    col_values = []
    col_values.append("Write Size         (Acc Avg)")
    miin, maax, avg = getMinMaxAvg(
        "write_io_size_min", "write_io_size_max", twib, twic
    ).split("/")
    col_values.extend(
        map(
            lambda x: "{} B".format(x) if int(float(x)) != 0 else 0,
            [miin, maax, math.ceil(float(avg))],
        )
    )
    t.add_row(col_values)

    # io initiation time
    col_values = []
    col_values.append("Read  DAL          (Acc Avg)")
    miin, maax, avg = getMinMaxAvg(
        "read_io_initiation_time_min",
        "read_io_initiation_time_max",
        "total_read_io_initiation_time",
        "total_time_metric_based_read_io_count",
    ).split("/")
    col_values.extend(map(time_conv, [miin, maax, avg]))
    t.add_row(col_values)

    col_values = []
    col_values.append("Write DAL          (Acc Avg)")
    miin, maax, avg = getMinMaxAvg(
        "write_io_initiation_time_min",
        "write_io_initiation_time_max",
        "total_write_io_initiation_time",
        twic,
    ).split("/")
    col_values.extend(map(time_conv, [miin, maax, avg]))
    t.add_row(col_values)

    # io completion time
    col_values = []
    col_values.append("Read  ECT          (Acc Avg)")
    miin, maax, avg = getMinMaxAvg(
        "read_io_completion_time_min",
        "read_io_completion_time_max",
        "total_read_io_time",
        tric,
    ).split("/")
    col_values.extend(map(time_conv, [miin, maax, avg]))
    t.add_row(col_values)

    col_values = []
    col_values.append("Write ECT          (Acc Avg)")
    miin, maax, avg = getMinMaxAvg(
        "write_io_completion_time_min",
        "write_io_completion_time_max",
        "total_write_io_time",
        twic,
    ).split("/")
    col_values.extend(map(time_conv, [miin, maax, avg]))
    t.add_row(col_values)

    if ver1 < 922:
        # io inter gap time
        col_values = []
        col_values.append("Read  Inter-IO-Gap (Acc Avg)")
        min_read_io_gap, max_read_io_gap, avg_read_io_gap = [
            tick_to_time(int(float(i)))
            for i in getMinMaxAvg(
                "read_io_inter_gap_time_min",
                "read_io_inter_gap_time_max",
                "total_read_io_inter_gap_time",
                tric,
            ).split("/")
        ]
        col_values.extend(
            [
                "{}".format(min_read_io_gap),
                "{}".format(max_read_io_gap),
                "{}".format(avg_read_io_gap),
            ]
        )
        t.add_row(col_values)

        col_values = []
        col_values.append("Write Inter-IO-Gap (Acc Avg)")
        min_write_io_gap, max_write_io_gap, avg_write_io_gap = [
            tick_to_time(int(float(i)))
            for i in getMinMaxAvg(
                "write_io_inter_gap_time_min",
                "write_io_inter_gap_time_max",
                "total_write_io_inter_gap_time",
                twic,
            ).split("/")
        ]
        col_values.extend(
            [
                "{}".format(min_write_io_gap),
                "{}".format(max_write_io_gap),
                "{}".format(avg_write_io_gap),
            ]
        )
        t.add_row(col_values)
    else:
        col_values = []
        col_values.append("Write Host Delay   (Acc Avg)")
        miin, maax, avg = getMinMaxAvg(
            "write_io_host_delay_time_min",
            "write_io_host_delay_time_max",
            "total_write_io_host_delay_time",
            "total_write_io_sequences_count",
        ).split("/")
        col_values.extend(map(time_conv, [miin, maax, avg]))
        t.add_row(col_values)

        col_values = []
        col_values.append("Write Array Delay  (Acc Avg)")
        miin, maax, avg = getMinMaxAvg(
            "NA",
            "write_io_array_delay_time_max",
            "total_write_io_array_delay_time",
            "total_write_io_sequences_count",
        ).split("/")
        col_values.extend(map(time_conv, ["NA", maax, avg]))
        t.add_row(col_values)

        col_values = []
        col_values.append("Write IO Seq count (Acc Avg)")
        miin, maax, avg = getMinMaxAvg(
            "multisequence_exchange_write_io_sequences_max",
            "multisequence_exchange_write_io_sequences_min",
            "total_write_io_sequences_count",
            twic,
        ).split("/")
        col_values.extend([miin, maax, math.ceil(float(avg))])
        t.add_row(col_values)

    print(t)
    if args.outfile or args.appendfile:
        data = t.get_string()
        try:
            fh.write(data + "\n")
        except OSError as err:
            print("Not able to write to a file, No space left on device")
            sys.exit(0)
        try:
            fh.close()
        except OSError as err:
            print("Not able to write to a file, No space left on device")
            sys.exit(0)


def displayFlowInfoOverlay(json_out, ver=None):
    """
    **********************************************************************************
    * Function: displayFlowInfoOverlay
    *
    * Input: json_out is the json data returned by switch as response for
    *        query
    * Action: Displays statistics of a ITLs from json_out
    * Returns: None
    **********************************************************************************
    """

    global prev_wid, max_fcid_len
    if args.alias:
        fcid2pwwn = getfcid2pwwn()
        pwwn2alias = getDalias()
        max_fcid_len = 20

    vmid_enabled = getVmidFeature()
    ver1 = int("".join([i for i in ver if i.isdigit()])[:3])

    lun_str = "Namespace" if args.nvme else "LUN"
    lun_str_len = max_nsid_len if args.nvme else max_lunid_len
    if vmid_enabled:
        if args.initiator_it or args.target_it:
            col_names = [
                "{0:^{w1}} | {1:^{w2}} | {2:^{w3}} | {3:^{w4}} ".format(
                    "VSAN",
                    "Initiator",
                    "VMID",
                    "Target",
                    w1=max_vsan_len,
                    w2=max_fcid_len,
                    w3=max_vmid_len,
                    w4=max_fcid_len,
                ),
                "Avg IOPS",
                "Avg Throughput",
                "Avg ECT",
                "Avg DAL",
                "Avg IO Size",
            ]
        else:
            col_names = [
                "{0:^{w1}} | {1:^{w2}} | {2:^{w3}} | {3:^{w4}} | {4:^{w5}} ".format(
                    "VSAN",
                    "Initiator",
                    "VMID",
                    "Target",
                    lun_str,
                    w1=max_vsan_len,
                    w2=max_fcid_len,
                    w3=max_vmid_len,
                    w4=max_fcid_len,
                    w5=lun_str_len,
                ),
                "Avg IOPS",
                "Avg Throughput",
                "Avg ECT",
                "Avg DAL",
                "Avg IO Size",
            ]
    else:
        if args.initiator_it or args.target_it:
            col_names = [
                "{0:^{w1}} | {1:^{w2}} | {2:^{w3}} ".format(
                    "VSAN",
                    "Initiator",
                    "Target",
                    w1=max_vsan_len,
                    w2=max_fcid_len,
                    w3=max_fcid_len,
                ),
                "Avg IOPS",
                "Avg Throughput",
                "Avg ECT",
                "Avg DAL",
                "Avg IO Size",
            ]
        else:
            col_names = [
                "{0:^{w1}} | {1:^{w2}} | {2:^{w3}} | {3:^{w4}} ".format(
                    "VSAN",
                    "Initiator",
                    "Target",
                    lun_str,
                    w1=max_vsan_len,
                    w2=max_fcid_len,
                    w3=max_fcid_len,
                    w4=lun_str_len,
                ),
                "Avg IOPS",
                "Avg Throughput",
                "Avg ECT",
                "Avg DAL",
                "Avg IO Size",
            ]
    if ver1 >= 922:
        col_names.extend([" Avg Host Delay ", " Avg Array Delay "])
    metrics = []
    port, vsan, initiator, lun, target, vmid = "0/0", "", "", "", "", ""
    (
        totalread,
        totalwrite,
        readCount,
        writeCount,
        readIoIntTime,
        writeIoIntTime,
        readIoB,
        writeIoB,
        writeArrayDelay,
        writeHostDelay,
        totalWriteIoSeq,
    ) = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    sizeJson = len(json_out["values"])
    counter = 1
    max_iops = 0

    if args.minmax:
        if vmid_enabled:
            if not (args.initiator_it or args.target_it):
                col_names = [
                    "{0:^{w1}} | {1:^{w2}} | {2:^{w3}} | {3:^{w4}} | {4:^{w5}} ".format(
                        "VSAN",
                        "Initiator",
                        "VMID",
                        "Target",
                        lun_str,
                        w1=max_vsan_len,
                        w2=max_fcid_len,
                        w3=max_vmid_len,
                        w4=max_fcid_len,
                        w5=lun_str_len,
                    ),
                    "Peak IOPS*",
                    "Peak Throughput*",
                    "Read ECT*",
                    "Write ECT*",
                ]
            else:
                col_names = [
                    "{0:^{w1}} | {1:^{w2}} | {2:^{w3}} | {3:^{w4}} ".format(
                        "VSAN",
                        "Initiator",
                        "VMID",
                        "Target",
                        w1=max_vsan_len,
                        w2=max_fcid_len,
                        w3=max_vmid_len,
                        w4=max_fcid_len,
                        w5=lun_str_len,
                    ),
                    "Peak IOPS*",
                    "Peak Throughput*",
                    "Read ECT*",
                    "Write ECT*",
                ]
        else:
            if not (args.initiator_it or args.target_it):
                col_names = [
                    "{0:^{w1}} | {1:^{w2}} | {2:^{w3}} | {3:^{w4}} ".format(
                        "VSAN",
                        "Initiator",
                        "Target",
                        lun_str,
                        w1=max_vsan_len,
                        w2=max_fcid_len,
                        w3=max_fcid_len,
                        w4=lun_str_len,
                    ),
                    "Peak IOPS*",
                    "Peak Throughput*",
                    "Read ECT*",
                    "Write ECT*",
                ]
            else:
                col_names = [
                    "{0:^{w1}} | {1:^{w2}} | {2:^{w3}} ".format(
                        "VSAN",
                        "Initiator",
                        "Target",
                        w1=max_vsan_len,
                        w2=max_fcid_len,
                        w3=max_fcid_len,
                    ),
                    "Peak IOPS*",
                    "Peak Throughput*",
                    "Read ECT*",
                    "Write ECT*",
                ]
        if ver1 >= 922:
            col_names.extend(
                [" Host Delay* ", " Array Delay* ", " Write IO sequence* "]
            )
    else:
        pre_a = {}
        while counter <= sizeJson:
            for key, value in json_out["values"][str(counter)].items():
                if str(key) == "port":
                    port = value
                    continue
                if str(key) == "vsan":
                    vsan = value
                    continue
                if str(key) == "vmid":
                    vmid = value
                    continue
                if str(key) == "initiator_id":
                    initiator = value
                    continue
                if str(key) == "target_id":
                    target = value
                    continue
                if str(key) == "lun":
                    lun = value
                    continue
                if str(key) == "namespace_id":
                    lun = value
                    continue
                if str(key) == "total_read_io_time" and value != 0:
                    totalread = int(value)
                    continue
                if str(key) == "total_write_io_time" and value != 0:
                    totalwrite = int(value)
                    continue
                if (
                    str(key) == "total_time_metric_based_read_io_count"
                    and value != 0
                    and ver != "8.3(1)"
                ):
                    readCount = int(value)
                    continue
                if (
                    str(key) == "total_time_metric_based_write_io_count"
                    and value != 0
                    and ver != "8.3(1)"
                ):
                    writeCount = int(value)
                    continue
                if str(key) == "total_read_io_count" and value != 0 and ver == "8.3(1)":
                    readCount = int(value)
                    continue
                if (
                    str(key) == "total_write_io_count"
                    and value != 0
                    and ver == "8.3(1)"
                ):
                    writeCount = int(value)
                    continue
                if str(key) == "total_read_io_initiation_time" and value != 0:
                    readIoIntTime = int(value)
                    continue
                if str(key) == "total_write_io_initiation_time" and value != 0:
                    writeIoIntTime = int(value)
                    continue
                if str(key) == "total_read_io_bytes" and value != 0:
                    readIoB = int(value)
                    continue
                if str(key) == "total_write_io_bytes" and value != 0:
                    writeIoB = int(value)
                    continue
                if (
                    str(key) == "total_write_io_array_delay_time"
                    and value != 0
                    and ver1 >= 922
                ):
                    writeArrayDelay = int(value)
                    continue
                if (
                    str(key) == "total_write_io_host_delay_time"
                    and value != 0
                    and ver1 >= 922
                ):
                    writeHostDelay = int(value)
                    continue
                if (
                    str(key) == "total_write_io_sequences_count"
                    and value != 0
                    and ver1 >= 922
                ):
                    totalWriteIoSeq = int(value)
                    continue
            counter = counter + 1
            if vmid_enabled:
                pre_a[
                    str(port)
                    + "::"
                    + str(vsan)
                    + "::"
                    + str(initiator)
                    + "::"
                    + str(vmid)
                    + "::"
                    + str(target)
                    + "::"
                    + str(lun)
                ] = (
                    str(totalread)
                    + "::"
                    + str(totalwrite)
                    + "::"
                    + str(readCount)
                    + "::"
                    + str(writeCount)
                    + "::"
                    + str(readIoIntTime)
                    + "::"
                    + str(writeIoIntTime)
                    + "::"
                    + str(readIoB)
                    + "::"
                    + str(writeIoB)
                    + "::"
                    + str(writeArrayDelay)
                    + "::"
                    + str(writeHostDelay)
                    + "::"
                    + str(totalWriteIoSeq)
                )
            else:
                pre_a[
                    str(port)
                    + "::"
                    + str(vsan)
                    + "::"
                    + str(initiator)
                    + "::"
                    + str(target)
                    + "::"
                    + str(lun)
                ] = (
                    str(totalread)
                    + "::"
                    + str(totalwrite)
                    + "::"
                    + str(readCount)
                    + "::"
                    + str(writeCount)
                    + "::"
                    + str(readIoIntTime)
                    + "::"
                    + str(writeIoIntTime)
                    + "::"
                    + str(readIoB)
                    + "::"
                    + str(writeIoB)
                    + "::"
                    + str(writeArrayDelay)
                    + "::"
                    + str(writeHostDelay)
                    + "::"
                    + str(totalWriteIoSeq)
                )

        if len(pre_a) < 200:
            # adding sleep for more accurate results CSCvp66699
            time.sleep(1)

        json_out = getData(args, misc=1)
        counter = 1

    while counter <= sizeJson:
        vmid = ""
        iopsR, thputR, ectR, dalR, IoSizeR = 0, 0, 0, 0, 0
        iopsW, thputW, ectW, dalW, IoSizeW, hostDelay, arrayDelay = 0, 0, 0, 0, 0, 0, 0
        if args.minmax:
            (
                peak_read_iops,
                peak_write_iops,
                peak_read_thput,
                peak_write_thput,
                read_ect_min,
                read_ect_max,
                write_ect_min,
                write_ect_max,
                write_host_delay_min,
                write_host_delay_max,
                write_array_delay_max,
                write_io_seq_count_max,
                write_io_seq_count_min,
            ) = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        for key, value in json_out["values"][str(counter)].items():
            if str(key) == "port":
                port = value
                continue
            if str(key) == "vsan":
                vsan = value
                continue
            if str(key) == "initiator_id":
                initiator = value
                continue
            if str(key) == "target_id":
                target = value
                continue
            if str(key) == "lun":
                lun = value
                continue
            if str(key) == "namespace_id":
                lun = value
                continue
            if str(key) == "vmid":
                vmid = value
                continue
            if str(key) == "read_io_rate" and value != 0:
                iopsR = int(value)
                continue
            if str(key) == "write_io_rate" and value != 0:
                iopsW = int(value)
                continue
            if str(key) == "read_io_bandwidth" and value != 0:
                thputR = value
                continue
            if str(key) == "write_io_bandwidth" and value != 0:
                thputW = value
                continue
            if str(key) == "total_read_io_time" and value != 0:
                totalread = int(value)
                continue
            if str(key) == "total_write_io_time" and value != 0:
                totalwrite = int(value)
                continue
            if (
                str(key) == "total_time_metric_based_read_io_count"
                and value != 0
                and ver != "8.3(1)"
            ):
                readCount = int(value)
                continue
            if (
                str(key) == "total_time_metric_based_write_io_count"
                and value != 0
                and ver != "8.3(1)"
            ):
                writeCount = int(value)
                continue
            if str(key) == "total_read_io_count" and value != 0 and ver == "8.3(1)":
                readCount = int(value)
                continue
            if str(key) == "total_write_io_count" and value != 0 and ver == "8.3(1)":
                writeCount = int(value)
                continue
            if str(key) == "peak_read_io_rate" and value != 0:
                peak_read_iops = int(value)
                continue
            if str(key) == "peak_write_io_rate" and value != 0:
                peak_write_iops = int(value)
                continue
            if str(key) == "peak_read_io_bandwidth" and value != 0:
                peak_read_thput = value
                continue
            if str(key) == "peak_write_io_bandwidth" and value != 0:
                peak_write_thput = value
                continue
            if str(key) == "read_io_completion_time_min" and value != 0:
                read_ect_min = value
                continue
            if str(key) == "read_io_completion_time_max" and value != 0:
                read_ect_max = value
                continue
            if str(key) == "write_io_completion_time_min" and value != 0:
                write_ect_min = value
                continue
            if str(key) == "write_io_completion_time_max" and value != 0:
                write_ect_max = value
                continue
            if str(key) == "total_read_io_initiation_time" and value != 0:
                readIoIntTime = int(value)
                continue
            if str(key) == "total_write_io_initiation_time" and value != 0:
                writeIoIntTime = int(value)
                continue
            if str(key) == "total_read_io_bytes" and value != 0:
                readIoB = int(value)
                continue
            if str(key) == "total_write_io_bytes" and value != 0:
                writeIoB = int(value)
                continue
            if (
                str(key) == "total_write_io_array_delay_time"
                and value != 0
                and ver1 >= 922
            ):
                writeArrayDelay = int(value)
                continue
            if (
                str(key) == "total_write_io_host_delay_time"
                and value != 0
                and ver1 >= 922
            ):
                writeHostDelay = int(value)
                continue
            if (
                str(key) == "write_io_host_delay_time_max"
                and value != 0
                and ver1 >= 922
            ):
                write_host_delay_max = int(value)
                continue
            if (
                str(key) == "write_io_host_delay_time_min"
                and value != 0
                and ver1 >= 922
            ):
                write_host_delay_min = int(value)
                continue
            if (
                str(key) == "write_io_array_delay_time_max"
                and value != 0
                and ver1 >= 922
            ):
                write_array_delay_max = int(value)
                continue
            if (
                str(key) == "total_write_io_sequences_count"
                and value != 0
                and ver1 >= 922
            ):
                totalWriteIoSeq = int(value)
                continue
            if (
                str(key) == "multisequence_exchange_write_io_sequences_max"
                and value != 0
                and ver1 >= 922
            ):
                write_io_seq_count_max = int(value)
                continue
            if (
                str(key) == "multisequence_exchange_write_io_sequences_min"
                and value != 0
                and ver1 >= 922
            ):
                write_io_seq_count_min = int(value)
                continue

        if args.alias:
            if (str(initiator), int(vsan)) in fcid2pwwn:
                init_pwwn = fcid2pwwn[(str(initiator), int(vsan))]
                if init_pwwn in pwwn2alias:
                    initiator = pwwn2alias[init_pwwn]
            if len(initiator) > 20:
                initiator = initiator[0:20]
            if (str(target), int(vsan)) in fcid2pwwn:
                tar_pwwn = fcid2pwwn[(target, int(vsan))]
                if tar_pwwn in pwwn2alias:
                    target = pwwn2alias[tar_pwwn]
            if len(target) > 20:
                target = target[0:20]

        if args.minmax:
            if vmid_enabled:
                a = (
                    str(port)
                    + "::"
                    + str(vsan)
                    + "::"
                    + str(initiator)
                    + "::"
                    + str(vmid)
                    + "::"
                    + str(target)
                    + "::"
                    + str(lun)
                    + "::"
                    + str(peak_read_iops)
                    + "::"
                    + str(peak_write_iops)
                    + "::"
                    + str(peak_read_thput)
                    + "::"
                    + str(peak_write_thput)
                    + "::"
                    + str(read_ect_min)
                    + "::"
                    + str(read_ect_max)
                    + "::"
                    + str(write_ect_min)
                    + "::"
                    + str(write_ect_max)
                )
            else:
                a = (
                    str(port)
                    + "::"
                    + str(vsan)
                    + "::"
                    + str(initiator)
                    + "::"
                    + str(target)
                    + "::"
                    + str(lun)
                    + "::"
                    + str(peak_read_iops)
                    + "::"
                    + str(peak_write_iops)
                    + "::"
                    + str(peak_read_thput)
                    + "::"
                    + str(peak_write_thput)
                    + "::"
                    + str(read_ect_min)
                    + "::"
                    + str(read_ect_max)
                    + "::"
                    + str(write_ect_min)
                    + "::"
                    + str(write_ect_max)
                )
            if ver1 >= 922:
                a = (
                    a
                    + "::"
                    + str(write_host_delay_min)
                    + "::"
                    + str(write_host_delay_max)
                    + "::"
                    + str(write_array_delay_max)
                    + "::"
                    + str(write_io_seq_count_min)
                    + "::"
                    + str(write_io_seq_count_max)
                )

            max_iops = max(
                [int(i) for i in (peak_write_iops, peak_read_thput, max_iops)]
            )
        else:
            if vmid_enabled:
                itl_id = (
                    str(port)
                    + "::"
                    + str(vsan)
                    + "::"
                    + str(initiator)
                    + "::"
                    + str(vmid)
                    + "::"
                    + str(target)
                    + "::"
                    + str(lun)
                )
            else:
                itl_id = (
                    str(port)
                    + "::"
                    + str(vsan)
                    + "::"
                    + str(initiator)
                    + "::"
                    + str(target)
                    + "::"
                    + str(lun)
                )
            try:
                (
                    prev_totalread,
                    prev_totalwrite,
                    prev_readcount,
                    prev_writecount,
                    prev_readIoIntTime,
                    prev_writeIoIntTime,
                    pre_readIoB,
                    pre_writeIoB,
                    pre_writeArrayDelay,
                    pre_writeHostDelay,
                    pre_totalWriteIoSeq,
                ) = pre_a[itl_id].split("::")
            except Exception:
                (
                    prev_totalread,
                    prev_totalwrite,
                    prev_readcount,
                    prev_writecount,
                    prev_readIoIntTime,
                    prev_writeIoIntTime,
                    pre_readIoB,
                    pre_writeIoB,
                    pre_writeArrayDelay,
                    pre_writeHostDelay,
                    pre_totalWriteIoSeq,
                ) = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
            a = (
                itl_id
                + "::"
                + str(iopsR)
                + "::"
                + str(iopsW)
                + "::"
                + str(thputR)
                + "::"
                + str(thputW)
            )
            diff_readCount = int(readCount) - int(prev_readcount)
            diff_writeCount = int(writeCount) - int(prev_writecount)
            diff_readIoIntTime = int(readIoIntTime) - int(prev_readIoIntTime)
            diff_writeIoIntTime = int(writeIoIntTime) - int(prev_writeIoIntTime)
            diff_readIoB = int(readIoB) - int(pre_readIoB)
            diff_writeIoB = int(writeIoB) - int(pre_writeIoB)
            diff_writeHostDelay = int(writeHostDelay) - int(pre_writeHostDelay)
            diff_writeArrayDelay = int(writeArrayDelay) - int(pre_writeArrayDelay)
            diff_totalWriteIoSeq = int(totalWriteIoSeq) - int(pre_totalWriteIoSeq)
            if diff_totalWriteIoSeq != 0:
                hostDelay = diff_writeHostDelay // diff_totalWriteIoSeq
                arrayDelay = diff_writeArrayDelay // diff_totalWriteIoSeq
            if diff_readCount != 0:
                ectR = abs(int(totalread) - int(prev_totalread)) // diff_readCount
            if diff_writeCount != 0:
                ectW = abs(int(totalwrite) - int(prev_totalwrite)) // diff_writeCount
            if diff_readCount != 0:
                dalR = diff_readIoIntTime // diff_readCount
            if diff_writeCount != 0:
                dalW = diff_writeIoIntTime // diff_writeCount
            if diff_readCount != 0:
                IoSizeR = diff_readIoB // diff_readCount
            if diff_writeCount != 0:
                IoSizeW = diff_writeIoB // diff_writeCount

            a = (
                a
                + "::"
                + str(ectR)
                + "::"
                + str(ectW)
                + "::"
                + str(dalR)
                + "::"
                + str(dalW)
                + "::"
                + str(IoSizeR)
                + "::"
                + str(IoSizeW)
            )
            if ver1 >= 922:
                a = a + "::" + str(hostDelay) + "::" + str(arrayDelay)
            max_iops = max([int(i) for i in (max_iops, iopsR, iopsW)])
        counter = counter + 1

        metrics.append(a)

    port_metrics = {}
    for l in metrics:
        parts = l.split("::")
        port = str(parts[0])
        if port in port_metrics:
            port_metrics[port].append(l)
        else:
            port_metrics[port] = []
            port_metrics[port].append(l)

    for port in sorted(
        port_metrics, key=lambda x: tuple([int(i) for i in x[2:].split("/")])
    ):
        t = PrettyTable(col_names)
        if ver1 < 922:
            col_names_empty = (
                ["", "", "", "", "", ""] if not args.minmax else ["", "", "", "", ""]
            )
        else:
            col_names_empty = (
                ["", "", "", "", "", "", "", ""]
                if not args.minmax
                else ["", "", "", "", "", "", "", ""]
            )

        max_iops_len = len(str(max_iops))

        col_names_desc = [
            "",
            " {0:^{w}} | {1:^{w}} ".format("Read", "Write", w=max_iops_len),
            "   Read   |   Write   ",
            "  Read   |   Write  ",
            "  Read   |   Write  ",
            "  Read   |   Write  ",
        ]
        if ver1 >= 922:
            col_names_desc.extend(["Write", "Write"])
        if args.minmax:
            col_names_desc = [
                "",
                "{0:^{w}} | {1:^{w}} ".format("Read", "Write", w=max_iops_len),
                "   Read   |   Write   ",
                "   Min   |    Max   ",
                "  Min    |    Max   ",
            ]
            if ver1 >= 922:
                col_names_desc.extend(
                    [
                        "  Min    |    Max   ",
                        "  Min    |    Max   ",
                        "  Min    |    Max   ",
                    ]
                )
        t.add_row(col_names_desc)
        t.add_row(col_names_empty)

        if args.nvme:
            t.align[col_names[0]] = "l"

        print("\n Interface " + port)
        if args.outfile or args.appendfile:
            try:
                fh.write("\n Interface " + port + "\n")
            except OSError as err:
                print("Not able to write to a file, No space left on device")
                sys.exit(0)

        for l in port_metrics[port]:
            col_values = []
            parts = l.split("::")
            if vmid_enabled:
                if not (args.initiator_it or args.target_it):
                    col_values.append(
                        "{0:>{w1}} | {1:^{w2}} | {2:>{w3}} | {3:^{w4}} | {4:>{w5}} ".format(
                            parts[1],
                            parts[2],
                            parts[3],
                            parts[4],
                            parts[5],
                            w1=max_vsan_len,
                            w2=max_fcid_len,
                            w3=max_vmid_len,
                            w4=max_fcid_len,
                            w5=lun_str_len,
                        )
                    )
                else:
                    col_values.append(
                        "{0:>{w1}} | {1:^{w2}} | {2:>{w3}} | {3:^{w4}} ".format(
                            parts[1],
                            parts[2],
                            parts[3],
                            parts[4],
                            w1=max_vsan_len,
                            w2=max_fcid_len,
                            w3=max_vmid_len,
                            w4=max_fcid_len,
                        )
                    )
                col_values.append(
                    " {0:^{w}} | {1:^{w}} ".format(parts[6], parts[7], w=max_iops_len)
                )
                col_values.append(
                    " {0:>10} | {1:^11} ".format(
                        thput_conv(float(parts[8])), thput_conv(float(parts[9]))
                    )
                )
                col_values.append(
                    " {0:>7} | {1:>8} ".format(
                        time_conv(float(parts[10])), time_conv(float(parts[11]))
                    )
                )
                col_values.append(
                    " {0:>7} | {1:>8} ".format(
                        time_conv(float(parts[12])), time_conv(float(parts[13]))
                    )
                )
                if not args.minmax:
                    col_values.append(
                        " {0:>8} | {1:^9} ".format(
                            size_conv(float(parts[14])), size_conv(float(parts[15]))
                        )
                    )
                    if ver1 >= 922:
                        col_values.append(
                            " {0:>7} ".format(time_conv(float(parts[16])))
                        )
                        col_values.append(
                            " {0:>7} ".format(time_conv(float(parts[17])))
                        )
                elif ver1 >= 922:
                    col_values.append(
                        " {0:>7} | {1:>8} ".format(
                            time_conv(float(parts[14])), time_conv(float(parts[15]))
                        )
                    )
                    col_values.append(
                        " {0:^7} | {1:>8} ".format("NA", time_conv(float(parts[16])))
                    )
                    col_values.append(" {0:^7} | {1:^8} ".format(parts[17], parts[18]))

            else:
                if not (args.initiator_it or args.target_it):
                    col_values.append(
                        "{0:>{w1}} | {1:^{w2}} | {2:^{w3}} | {3:^{w4}} ".format(
                            parts[1],
                            parts[2],
                            parts[3],
                            parts[4],
                            w1=max_vsan_len,
                            w2=max_fcid_len,
                            w3=max_fcid_len,
                            w4=lun_str_len,
                        )
                    )
                else:
                    col_values.append(
                        "{0:>{w1}} | {1:^{w2}} | {2:^{w3}} ".format(
                            parts[1],
                            parts[2],
                            parts[3],
                            w1=max_vsan_len,
                            w2=max_fcid_len,
                            w3=max_fcid_len,
                        )
                    )
                col_values.append(
                    " {0:^{w}} | {1:^{w}} ".format(parts[5], parts[6], w=max_iops_len)
                )
                col_values.append(
                    " {0:>10} | {1:^11} ".format(
                        thput_conv(float(parts[7])), thput_conv(float(parts[8]))
                    )
                )
                col_values.append(
                    " {0:>7} | {1:>8} ".format(
                        time_conv(float(parts[9])), time_conv(float(parts[10]))
                    )
                )
                col_values.append(
                    " {0:>7} | {1:>8} ".format(
                        time_conv(float(parts[11])), time_conv(float(parts[12]))
                    )
                )
                if not args.minmax:
                    col_values.append(
                        " {0:>8} | {1:^9} ".format(
                            size_conv(float(parts[13])), size_conv(float(parts[14]))
                        )
                    )
                    if ver1 >= 922:
                        col_values.append(
                            " {0:>7} ".format(time_conv(float(parts[15])))
                        )
                        col_values.append(
                            " {0:>7} ".format(time_conv(float(parts[16])))
                        )
                elif ver1 >= 922:
                    col_values.append(
                        " {0:>7} | {1:>8} ".format(
                            time_conv(float(parts[13])), time_conv(float(parts[14]))
                        )
                    )
                    col_values.append(
                        " {0:^7} | {1:>8} ".format("NA", time_conv(float(parts[15])))
                    )
                    col_values.append(" {0:^7} | {1:^8} ".format(parts[16], parts[17]))

            t.add_row(col_values)
        t.padding_width = 0
        print(t)
        if args.initiator_it or args.target_it:
            print("Total number of ITs: {}".format(len(port_metrics[port])))
        elif args.nvme:
            print("Total number of ITNs: {}".format(len(port_metrics[port])))
        else:
            print("Total number of ITLs: {}".format(len(port_metrics[port])))
        if args.outfile or args.appendfile:
            data = t.get_string()
            try:
                fh.write(data + "\n")
            except OSError as err:
                print("Not able to write to a file, No space left on device")
                sys.exit(0)

    if args.outfile or args.appendfile:
        if not args.minmax:
            try:
                fh.close()
            except OSError as err:
                print("Not able to write to a file, No space left on device")
                sys.exit(0)

    if args.minmax:
        print(
            "*These values are calculated since the metrics were last \
cleared."
        )
        if args.outfile or args.appendfile:
            try:
                fh.write(
                    "*These values are calculated since the metrics were last \
cleared."
                    + "\n"
                )
            except OSError as err:
                print("Not able to write to a file, No space left on device")
                sys.exit(0)
            try:
                fh.close()
            except OSError as err:
                print("Not able to write to a file, No space left on device")
                sys.exit(0)


def displayErrorsOverlay(json_out, date, ver=None):
    """
    **********************************************************************************
    * Function: displayErrorsOverlay
    *
    * Input: It takes 3 arguments:
    *          - json_out is the json data returned by switch as response for
    *             querry
    *          - date is String format system date
    *          - ver is software version of switch
    * Action: Displays error statistics of a ITLs from json_out
    * Returns: None
    **********************************************************************************
    """

    global max_fcid_len
    vmid_enabled = getVmidFeature()
    if args.alias:
        fcid2pwwn = getfcid2pwwn()
        pwwn2alias = getDalias()
        max_fcid_len = 20

    displaydateFlag = False

    lun_str = "Namespace" if args.nvme else "LUN"
    lun_str_len = max_nsid_len if args.nvme else max_lunid_len
    failure_str = "Total NVMe Failures" if args.nvme else "Total SCSI Failures"
    if vmid_enabled:
        if not (args.initiator_it or args.target_it):
            col_names = [
                "{0:^{w1}} | {1:^{w2}} | {2:^{w3}} | {3:^{w4}} | {4:^{w5}} ".format(
                    "VSAN",
                    "Initiator",
                    "VMID",
                    "Target",
                    lun_str,
                    w1=max_vsan_len,
                    w2=max_fcid_len,
                    w3=max_vmid_len,
                    w4=max_fcid_len,
                    w5=lun_str_len,
                ),
                failure_str,
                "Total FC Aborts",
            ]
        else:
            col_names = [
                "{0:^{w1}} | {1:^{w2}} | {2:^{w3}} | {3:^{w4}} ".format(
                    "VSAN",
                    "Initiator",
                    "VMID",
                    "Target",
                    w1=max_vsan_len,
                    w2=max_fcid_len,
                    w3=max_vmid_len,
                    w4=max_fcid_len,
                ),
                failure_str,
                "Total FC Aborts",
            ]
    else:
        if not (args.initiator_it or args.target_it):
            col_names = [
                "{0:^{w1}} | {1:^{w2}} | {2:^{w3}} | {3:^{w4}} ".format(
                    "VSAN",
                    "Initiator",
                    "Target",
                    lun_str,
                    w1=max_vsan_len,
                    w2=max_fcid_len,
                    w3=max_fcid_len,
                    w4=lun_str_len,
                ),
                failure_str,
                "Total FC Aborts",
            ]
        else:
            col_names = [
                "{0:^{w1}} | {1:^{w2}} | {2:^{w3}} ".format(
                    "VSAN",
                    "Initiator",
                    "Target",
                    w1=max_vsan_len,
                    w2=max_fcid_len,
                    w3=max_fcid_len,
                ),
                failure_str,
                "Total FC Aborts",
            ]
    col_names_desc = ["", "Read | Write", "Read | Write"]
    metrics = []
    vsan, initiator, lun, target, vmid = "", "", "", "", ""
    max_failures, max_aborts = 0, 0
    sizeJson = len(json_out["values"])
    counter = 1
    while counter <= sizeJson:
        failR, abortsR = 0, 0
        failW, abortsW = 0, 0
        for key, value in json_out["values"][str(counter)].items():
            # print key,value
            if str(key) == "port":
                port = value
                continue
            if str(key) == "vsan":
                vsan = value
                continue
            if str(key) == "vmid":
                vmid = value
                continue
            if str(key) == "initiator_id":
                initiator = value
                continue
            if str(key) == "target_id":
                target = value
                continue
            if str(key) == "lun":
                lun = value
                continue
            if str(key) == "namespace_id":
                lun = value
                continue
            if str(key) == "read_io_aborts" and value != 0:
                abortsR = int(value)
                continue
            if str(key) == "write_io_aborts" and value != 0:
                abortsW = int(value)
                continue
            if str(key) == "read_io_failures" and value != 0:
                failR = int(value)
                continue
            if str(key) == "write_io_failures" and value != 0:
                failW = int(value)
        counter = counter + 1
        if args.alias:
            if (str(initiator), int(vsan)) in fcid2pwwn:
                init_pwwn = fcid2pwwn[(str(initiator), int(vsan))]
                if init_pwwn in pwwn2alias:
                    initiator = pwwn2alias[init_pwwn]
            if len(initiator) > 20:
                initiator = initiator[0:20]

            if (str(target), int(vsan)) in fcid2pwwn:
                tar_pwwn = fcid2pwwn[(target, int(vsan))]
                if tar_pwwn in pwwn2alias:
                    target = pwwn2alias[tar_pwwn]
            if len(target) > 20:
                target = target[0:20]

        # for errorsonly
        if args.errors or (failR != 0 or failW != 0 or abortsR != 0 or abortsW != 0):
            if vmid_enabled:
                a = (
                    str(port)
                    + "::"
                    + str(vsan)
                    + "::"
                    + str(initiator)
                    + "::"
                    + str(vmid)
                    + "::"
                    + str(target)
                    + "::"
                    + str(lun)
                    + "::"
                    + str(failR)
                    + "::"
                    + str(failW)
                    + "::"
                    + str(abortsR)
                    + "::"
                    + str(abortsW)
                )
            else:
                a = (
                    str(port)
                    + "::"
                    + str(vsan)
                    + "::"
                    + str(initiator)
                    + "::"
                    + str(target)
                    + "::"
                    + str(lun)
                    + "::"
                    + str(failR)
                    + "::"
                    + str(failW)
                    + "::"
                    + str(abortsR)
                    + "::"
                    + str(abortsW)
                )
            max_failures = max(max_failures, failR, failW)
            max_aborts = max(max_aborts, abortsR, abortsW)
            metrics.append(a)
            if vmid_enabled:
                cols = (
                    str(vsan)
                    + "|"
                    + str(initiator)
                    + "|"
                    + str(vmid)
                    + "|"
                    + str(target)
                    + "|"
                    + str(lun)
                )
            else:
                cols = (
                    str(vsan)
                    + "|"
                    + str(initiator)
                    + "|"
                    + str(target)
                    + "|"
                    + str(lun)
                )
            displaydateFlag = True

    itl_str = "ITNs" if args.nvme else "ITLs"
    if args.errorsonly:
        if displaydateFlag:
            print(date)
        else:
            print("\n No {0} with errors found\n".format(itl_str))

    port_metrics = {}
    for l in metrics:
        parts = l.split("::")

        port = str(parts[0])
        if port in port_metrics:
            port_metrics[port].append(l)
        else:
            port_metrics[port] = []
            port_metrics[port].append(l)

    # aligning o/p
    failure_width = len(str(max_failures)) + 2
    abort_width = len(str(max_aborts)) + 2

    for port in sorted(
        port_metrics, key=lambda x: tuple([int(i) for i in x[2:].split("/")])
    ):
        t = PrettyTable(col_names)
        t.add_row(col_names_desc)
        col_names_empty = ["", "", ""]
        t.add_row(col_names_empty)
        # t.align = "l"

        if args.nvme:
            t.align[col_names[0]] = "l"

        print("\n Interface " + port)
        if args.outfile or args.appendfile:
            try:
                fh.write("\n Interface " + port + "\n")
            except OSError as err:
                print("Not able to write to a file, No space left on device")
                sys.exit(0)
        for l in port_metrics[port]:
            col_values = []
            parts = l.split("::")
            if vmid_enabled:
                if not (args.initiator_it or args.target_it):
                    col_values.append(
                        "{0:>{w1}} | {1:^{w2}} | {2:>{w3}} | {3:^{w4}} | {4:>{w5}} ".format(
                            parts[1],
                            parts[2],
                            parts[3],
                            parts[4],
                            parts[5],
                            w1=max_vsan_len,
                            w2=max_fcid_len,
                            w3=max_vmid_len,
                            w4=max_fcid_len,
                            w5=lun_str_len,
                        )
                    )
                else:
                    col_values.append(
                        "{0:>{w1}} | {1:^{w2}} | {2:>{w3}} | {3:^{w4}} ".format(
                            parts[1],
                            parts[2],
                            parts[3],
                            parts[4],
                            w1=max_vsan_len,
                            w2=max_fcid_len,
                            w3=max_vmid_len,
                            w4=max_fcid_len,
                        )
                    )
                col_values.append(
                    "{0:^{w}}|{1:^{w}}".format(parts[6], parts[7], w=failure_width)
                )
                col_values.append(
                    "{0:^{w}}|{1:^{w}}".format(parts[8], parts[9], w=abort_width)
                )
            else:
                if not (args.initiator_it or args.target_it):
                    col_values.append(
                        "{0:>{w1}} | {1:^{w2}} | {2:^{w3}} | {3:>{w4}} ".format(
                            parts[1],
                            parts[2],
                            parts[3],
                            parts[4],
                            w1=max_vsan_len,
                            w2=max_fcid_len,
                            w3=max_fcid_len,
                            w4=lun_str_len,
                        )
                    )
                else:
                    col_values.append(
                        "{0:>{w1}} | {1:^{w2}} | {2:^{w3}} ".format(
                            parts[1],
                            parts[2],
                            parts[3],
                            w1=max_vsan_len,
                            w2=max_fcid_len,
                            w3=max_fcid_len,
                        )
                    )
                col_values.append(
                    "{0:^{w}}|{1:^{w}}".format(parts[5], parts[6], w=failure_width)
                )
                col_values.append(
                    "{0:^{w}}|{1:^{w}}".format(parts[7], parts[8], w=abort_width)
                )
            t.add_row(col_values)
        print(t)
        if args.outfile or args.appendfile:
            data = t.get_string()
            try:
                fh.write(data + "\n")
            except OSError as err:
                print("Not able to write to a file, No space left on device")
                sys.exit(0)

    if args.outfile or args.appendfile:
        try:
            fh.close()
        except OSError as err:
            print("Not able to write to a file, No space left on device")
            sys.exit(0)


def func(X):
    r = X.strip().split("/")[1]
    return int(r)


def enableAnalyticsOnPorts(inft_dict, amc_modules=[]):
    global working_interface
    i_list = []
    for mod in inft_dict:
        i_list.extend(inft_dict[mod])

    # inte_str = ",".join(i_list)
    inte_str = normalize_ports(i_list)
    working_interface = inte_str
    # print("Interfaces.... {}".format(inte_str))
    cmd = "configure terminal ; interface {0} ; analytics type fc-all ; \
    show clock".format(
        inte_str
    )
    status, out = cmd_exc(cmd)
    if not status:
        print_status(
            [out, "Unable to enable analytics on interface {0}".format(inte_str)]
        )
        return (False, "")
    sampling_start_time = ""
    time.sleep(10)
    start_time = datetime.datetime.now()
    x = 0
    final_fail_list = []
    for mod in inft_dict:
        if mod in amc_modules:
            sampling_start_time = start_time
            continue
        for x in range(30):
            fail_list = []
            # print("Iterarion {} mod {}".format(x,mod))
            status, sdb_out = cmd_exc(
                "show analytics port-sampling module {0}".format(mod)
            )
            if not status:
                if x == 29:
                    print_status(
                        [sdb_out, "Unable to get sdb data for module {}".format(mod)]
                    )
                    final_fail_list.extend(inft_dict[mod])
                    break
                else:
                    continue
            # print(sdb_out)
            for inte in inft_dict[mod]:
                pat = inte + "*"
                if pat not in sdb_out:
                    fail_list.append(inte)
                else:
                    if sampling_start_time == "":
                        try:
                            status, sdb_out = cmd_exc(
                                "show analytics port-sampling module \
                                  {0} | i '{1}'".format(
                                    mod, inte
                                )
                            )
                            sdb_out = " ".join(
                                [
                                    i
                                    for i in sdb_out.split(" ")
                                    if i != "" and i != "-" and i != "\n"
                                ][1:]
                            )
                            sampling_start_time = datetime.datetime.strptime(
                                sdb_out.split("*")[-1].strip(), "%m/%d/%y %H:%M:%S"
                            )
                            # print("sampling_start_time {}".format(sampling_start_time))
                        except Exception as e:
                            continue
            if fail_list:
                if x == 29:
                    final_fail_list.extend(fail_list)
                    break
                else:
                    time.sleep(1)
            else:
                break

    if final_fail_list:
        error_data = "Analytics is still not enabled \
for interface {0}".format(
            final_fail_list
        )
        print_status([error_data])
        cmd = "configure terminal ; interface {0} ; no analytics \
            type fc-all ; show clock".format(
            ",".join(final_fail_list)
        )
        status, out = cmd_exc(cmd)
        if not status:
            print_status(
                [out, "Unable to disable analytics on interface {0}".format(inte)]
            )
        for inte in final_fail_list:
            i_list.remove(inte)
        if i_list:
            return (True, sampling_start_time)
        else:
            return (False, "")
    return (True, sampling_start_time)


def get_npuload_data(inte_list, ver, start_time):
    data_dict = {}
    mod_iops_list = []
    data_scsi = {}
    data_nvme = {}
    global working_interface
    # print("Start getting data for interfaces {} {}".format(inte_list,datetime.datetime.now()))
    data_scsi = getData(args, "scsi", ver)
    data_nvme = getData(args, "nvme", ver)
    # int_str = ",".join(inte_list)
    int_str = normalize_ports(inte_list)
    cmd = "configure terminal ; interface {0} ; no analytics \
            type fc-all ; show clock".format(
        int_str
    )
    status, out = cmd_exc(cmd)
    end_time = out.split("\n")[-2].split(" ")[0][:-4]
    if not status:
        print_status(
            [out, "Unable to disable analytics on interface {0}".format(int_str)]
        )
    # print("Start preparing data for {} interfaces {}".format(len(inte_list),datetime.datetime.now()))
    working_interface = None
    if data_scsi:
        sizeJson = len(data_scsi["values"])
    else:
        sizeJson = 0
    # for inte in inte_list:
    #    itl_count, itn_count, scsi_iops, nvme_iops, init_count, tar_count = 0, 0, 0, 0, '0', '0'
    sdata = {}
    counter = 1
    while counter <= sizeJson:
        itl_count, scsi_iops, init_count, tar_count = 0, 0, 0, 0
        for key, value in data_scsi["values"][str(counter)].items():
            if str(key) == "port":
                port = value
                continue
            if key == "sampling_start_time":
                scsi_sampling_start_time = int(value)
                start_time = datetime.datetime.fromtimestamp(int(value)).strftime(
                    "%H:%M:%S"
                )
                continue
            if key == "sampling_end_time":
                end_time = datetime.datetime.fromtimestamp(int(value)).strftime(
                    "%H:%M:%S"
                )
                continue
            if key == "scsi_initiator_itl_flow_count":
                itl_count += int(value)
                continue
            if key == "scsi_target_itl_flow_count":
                itl_count += int(value)
                continue
            if key == "read_io_rate":
                scsi_iops += int(value)
                continue
            if key == "write_io_rate":
                scsi_iops += int(value)
                continue
            if key == "scsi_initiator_count":
                init_count = value
                continue
            if key == "scsi_target_count":
                tar_count = value
                continue
        counter += 1
        scsi_iops = scsi_iops / 5000.0
        sdata[port] = {
            "itls": str(itl_count),
            "iops": str(scsi_iops),
            "start_time": str(start_time),
            "end_time": str(end_time),
            "init_count": int(init_count),
            "tar_count": int(tar_count),
        }
    # print(sdata)

    if data_nvme:
        sizeJson = len(data_nvme["values"])
    else:
        sizeJson = 0
    ndata = {}
    counter = 1
    while counter <= sizeJson:
        itn_count, nvme_iops, init_count, tar_count = 0, 0, 0, 0
        for key, value in data_nvme["values"][str(counter)].items():
            if str(key) == "port":
                port = value
                continue
            if key == "sampling_start_time":
                start_time = datetime.datetime.fromtimestamp(int(value)).strftime(
                    "%H:%M:%S"
                )
                continue
            if key == "sampling_end_time":
                end_time = datetime.datetime.fromtimestamp(int(value)).strftime(
                    "%H:%M:%S"
                )
                continue
            if key == "nvme_initiator_itn_flow_count":
                itn_count += int(value)
                continue
            if key == "nvme_target_itn_flow_count":
                itn_count += int(value)
                continue
            if key == "read_io_rate":
                nvme_iops += int(value)
                continue
            if key == "write_io_rate":
                nvme_iops += int(value)
                continue
            if key == "nvme_initiator_count":
                init_count = value
                continue
            if key == "nvme_target_count":
                tar_count = value
                continue

        counter += 1
        nvme_iops = nvme_iops / 5000.0
        ndata[port] = {
            "itns": str(itn_count),
            "iops": str(nvme_iops),
            "start_time": str(start_time),
            "end_time": str(end_time),
            "init_count": int(init_count),
            "tar_count": int(tar_count),
        }

    f_ports = getFPorts()
    e_ports = getEPorts()
    intstatsDict = getInterfaceStats(inte_list)
    intspeedDict = getInterfaceSpeeds(inte_list)
    inteDict = getIntedetails(inte_list, intstatsDict, intspeedDict)
    for inte in inte_list:
        if inte not in sdata and inte not in ndata:
            data_dict[inte] = None
            continue
        elif inte not in sdata:
            sdata[inte] = {
                "itls": "0",
                "iops": "0",
                "start_time": ndata[inte]["start_time"],
                "end_time": "0",
                "init_count": 0,
                "tar_count": 0,
            }
        elif inte not in ndata:
            ndata[inte] = {
                "itns": "0",
                "iops": "0",
                "start_time": "0",
                "end_time": sdata[inte]["end_time"],
                "init_count": 0,
                "tar_count": 0,
            }

        inte_type = "NA"

        if inte in f_ports:
            tar_count = sdata[inte]["tar_count"] + ndata[inte]["tar_count"]
            init_count = sdata[inte]["init_count"] + ndata[inte]["init_count"]

            if tar_count != 0 and init_count != 0:
                inte_type = "Both"
            elif tar_count > 0:
                inte_type = "Target"
            elif init_count > 0:
                inte_type = "Initiator"
        elif inte in e_ports:
            inte_type = "E"

        # Get Txwait values
        port_iops_count = round(float(sdata[inte]["iops"]), 1) + round(
            float(ndata[inte]["iops"]), 1
        )
        data = (
            inte
            + "-"
            + inte_type
            + "-"
            + sdata[inte]["itls"]
            + "-"
            + sdata[inte]["iops"]
            + "-"
            + ndata[inte]["itns"]
            + "-"
            + ndata[inte]["iops"]
            + "-"
            + sdata[inte]["start_time"]
            + "-"
            + ndata[inte]["end_time"]
            + "-"
            + inteDict[inte]["txWait"]
            + "-"
            + inteDict[inte]["rxUtil"]
            + "-"
            + inteDict[inte]["txUtil"]
            + "-"
            + str(port_iops_count)
        )
        data_dict[inte] = data

    # print()
    # if len(inte_list) == 1:
    #    return data_dict
    # else:
    #    if sum(mod_iops_list) >= 90:
    #        return {}
    #    else:
    #        return data_dict
    # print("End preparing data for interfaces {} {}".format(inte_list,datetime.datetime.now()))
    # print()
    return data_dict


def normalize_ports(ports_list):
    modwise_ports = {}
    ports_str = ""
    for port in ports_list:
        mod = extract_module_from_port(port)
        portnum = int(port.split("/")[-1])
        if mod not in modwise_ports:
            modwise_ports[mod] = [portnum]
        else:
            modwise_ports[mod].append(portnum)
    mod_list = list(modwise_ports.keys())
    mod_list.sort()
    for mod in mod_list:
        port_range = numberUnrange(modwise_ports[mod])
        for r in port_range:
            ports_str = ports_str + "fc" + str(mod) + "/" + str(r)
            ports_str = ports_str + ","
    return ports_str.rstrip(",")


def numberUnrange(numList):
    """Take a list of numbers and produce ranges
    numberUnrange [1, 2, 3, 5] returns str 1-3,5
    """
    numList = sorted(set(numList))
    length = len(numList)
    if not numList:
        return ""
    elif length == 1:
        return numList
    i = 0
    j = 1
    strRange = ""
    ele_to_range = numList[0]
    flag = 0
    while j < length:
        if (
            numList[i] + 1 == numList[j]
        ):  # check if current element+1 is equal to the next element
            i += 1
            j += 1
            flag = 1  # if yes set flag and go to next iteration
            if j < length:
                continue
        if flag == 1:  # if flag is set that means we have a range of values
            strRange += str(
                ele_to_range
            )  # add the range of values to the return string
            strRange += "-"
            strRange += str(numList[i])
            i += 1
            j += 1
            flag = 0
            if (
                j < length
            ):  # if not end of list , set next element in the list to be considered as current element
                ele_to_range = numList[i]
                strRange += ","
                continue
        if (
            j < length
        ):  # if we do not have a range of values , just add element to the return string
            strRange += str(ele_to_range)
            flag = 0
            i += 1
            j += 1
            if (
                j < length
            ):  # if not end of list , set the next element in the list to be considered as current element
                ele_to_range = numList[i]
                strRange += ","

        if (
            j == length
        ):  # if the current element is the last element and it is not part of a range of values
            strRange += ","  # add the element to the return string
            strRange += str(numList[i])
    return strRange.split(",")


def get_terminal_size():
    rows, cols = os.popen("stty size", "r").read().split()
    return int(rows)


def get_f64_mods():
    """
    **********************************************************************************
    * Function: get_f64_mods
    *
    * Returns: set of module numbers which are 64G
    **********************************************************************************
    """
    cmd = "show mod | i '64 Gbps' | cut -d ' ' -f 1"
    status, out = cmd_exc(cmd)
    if not status:
        print(out)
        return []
    else:
        return set([i for i in out.split("\n") if i.isdigit()])


def get_amc_port_groups(mods):
    amcPortGroups = {}
    f64Mods = get_f64_mods()
    for mod in mods:
        if mod in f64Mods:
            out = cli.cli("slot {} show hardware internal f64_amc sw-state".format(mod))
            pattern = r"(?P<fpPort>\d+)\s+(?P<hwport>\d+)\s+(?P<amcinst>\d+)"
            flag = 0
            incr = 0
            port_group = {}
            for line in out.splitlines():
                if "FP port " in line:
                    flag = 1
                if "Instance Data Structures" in line:
                    if flag:
                        incr = incr + max(port_group.keys())
                        flag = 0
                entry = re.search(pattern, line)
                if entry:
                    if flag:
                        data = entry.groupdict()
                        pg = (int(data["amcinst"]) + 1) + incr
                        port_group.setdefault(pg, []).append(int(data["fpPort"]))
            amcPortGroups[mod] = port_group
    return amcPortGroups


def displayNpuloadEvaluation(json_out, ver=None):
    """
    **********************************************************************************
    * Function: displayNpuloadEvaluation
    *
    * Input: json_out is the json data returned by switch as response for
    *        querry.
    *        ver is software version of switch
    * Action: Enable Analytics on  Analytics Capable ports selected via
    *         args global object , collect NpuLoad added by each port
    *         and disable analytics on that port.
    * Returns: None
    **********************************************************************************
    """

    global interface_list
    global error_log
    global pline
    error_log = []
    global sig_hup_flag
    global working_interface
    interface_list_flag = False
    hind_interface_list = []
    npu_interface_list = []
    h_module = []
    npu_module = []
    no_traffic_ports = []
    err_out = []

    signal.signal(signal.SIGHUP, sig_hup_handler)
    amc_module = get_amc_modules()
    np_ports = getNPSDPorts()
    mod_details = getModuleInfo()

    if interface_list:
        interface_list_flag = True
    else:
        interface_list = []

    if (not (args.module)) and (interface_list == []):
        # complete chassis option
        module = get_analytics_module(ver)
        h_module = amc_module
    if args.module:
        module = args.module
    if "module" in dir():
        if module == []:
            print("\nNo analytics enabled module found.\n")
            sys.exit(1)
        else:
            analytics_interface_configured_modules = [
                k for k in module if check_analytics_conf_per_module(k, mod_details)
            ]
            if analytics_interface_configured_modules != []:
                print(
                    "Execution terminated as analytics is configured on \
interface of following module:"
                )
                for mod in analytics_interface_configured_modules:
                    print(" Module {0}".format(mod))
                print(
                    "Note: --evaluate-npuload option should only be run \
prior to configuring analytics"
                )
                sys.exit(1)
            port_sampling_configured_modules = [
                k
                for k in module
                if check_port_sampling_per_module(k, amc_module, mod_details)
            ]
            if port_sampling_configured_modules != []:
                print(
                    "Execution terminated as port-sampling is \
enabled for following module:"
                )
                for mod in port_sampling_configured_modules:
                    print(" Module {0}".format(mod))
                print(
                    "Note: --evaluate-npuload option cannot be run if \
port-sampling is enabled"
                )
                sys.exit(1)
            npu_interface_list = []
            for mod in module:
                npu_interface_list.extend(get_up_ints_permodule(mod))
    else:
        if interface_list != []:

            passed_modules = []
            for inte in interface_list:
                mod = extract_module_from_port(inte)
                if mod not in passed_modules:
                    if not check_analytics_conf_per_module(mod, mod_details):
                        passed_modules.append(mod)
                    else:
                        print(
                            "Execution terminated as analytics is \
configured on interface of module {}".format(
                                mod
                            )
                        )
                        print(
                            "Note: --evaluate-npuload option should only be \
run prior to configuring analytics"
                        )
                        sys.exit(1)
            passed_modules = []
            for inte in interface_list:
                mod = extract_module_from_port(inte)
                npu_interface_list.append(inte)
                if mod not in passed_modules:
                    if not check_port_sampling_per_module(mod, amc_module, mod_details):
                        passed_modules.append(mod)
                    else:
                        print(
                            "Execution terminated as port-sampling is \
enabled for module {}".format(
                                mod
                            )
                        )
                        print(
                            "Note: --evaluate-npuload option cannot be run if \
port-sampling is enabled"
                        )
                        sys.exit(1)
            down_intfs = get_down_intf_list(npu_interface_list)
            if down_intfs != []:
                int_str = normalize_ports(down_intfs)
                print("Interfaces {} are not up".format(int_str))
                npu_interface_list = [
                    i for i in npu_interface_list if i not in down_intfs
                ]

    mod_matrix = {}
    if npu_interface_list != []:
        np_inte = [i for i in npu_interface_list if i in np_ports]
        if np_inte != []:
            np_inte_str = normalize_ports(np_inte)
            error_log.append(
                "Unsupported Port mode (SD/NP) of interfaces {}".format(np_inte_str)
            )
            npu_interface_list = [i for i in npu_interface_list if i not in np_inte]

    if npu_interface_list != []:
        int_iterator = 0
        pline = 0

        # Segregating interfaces based on modules
        mod_dict = {}
        for inte in npu_interface_list:
            mod = inte.strip().split("/")[0][2:]
            if mod not in mod_dict:
                mod_dict[mod] = [inte]
            else:
                mod_dict[mod].append(inte)

        for mod in mod_dict:
            mod_dict[mod].sort()

        for mod in mod_dict:
            mod_dict[mod] = sorted(mod_dict[mod], key=func)

        # Creating batch of 4 interaces per module
        batch_list = {}

        for mod in mod_dict:
            batch = [mod_dict[mod][i : i + 4] for i in range(0, len(mod_dict[mod]), 4)]
            batch_list[mod] = batch

        len_list = []
        for mod in batch_list:
            len_list.append(len(batch_list[mod]))
            # print(batch_list[mod])
        max_len = max(len_list)
        # expected_time = ((len(batch_list.keys())*4)*4+40)*max_len
        expected_time = (30 + 30) * max_len

        int_count = len(npu_interface_list)
        print(
            "{} interfaces will be evaluated in {} batches. Expected time is {}".format(
                int_count, max_len, time_formator(expected_time)
            )
        )
        if args.outfile or args.appendfile:
            try:
                fh.write(
                    "{} interfaces will be evaluated in {} batches. Expected time is {}".format(
                        int_count, max_len, time_formator(expected_time)
                    )
                )
            except OSError as err:
                print("Not able to write to a file, No space left on device")
                sys.exit(0)

        conf_response = str(input("Do you want to continue [Yes|No]? [n]"))
        if args.outfile or args.appendfile:
            try:
                fh.write(
                    "\nDo you want to continue [Yes|No]? [n]" + conf_response + "\n"
                )
            except OSError as err:
                print("Not able to write to a file, No space left on device")
                sys.exit(0)
        if conf_response not in ["Y", "y", "Yes", "yes", "YES"]:
            return False
        # print(formatdate(localtime=True))

        # arming the sighup handler
        sig_hup_flag = "Armed"

        if sig_hup_flag == "Armed":
            status, out = cmd_exc(
                "configure terminal ;  terminal session-timeout \
                0"
            )
            if not status:
                print(out)
                print("Unable to set session timeout")

        # int_iterator = 0
        eval_again = {}
        for i in range(max_len):
            if i != 0:
                if sig_hup_flag == "Armed":
                    clear_previous_lines(pline)
                    pline = 0
            if sig_hup_flag in [None, "Armed"]:
                print(
                    "Evaluating batch {} ({} out of {} batch)".format(
                        i + 1, i + 1, max_len
                    )
                )
                pline = 1
            else:
                syslog.syslog(
                    2,
                    "Evaluating batch {} ({} out of {} batch)".format(
                        i + 1, i + 1, max_len
                    ),
                )

            intf_dict = {}
            for mod in batch_list:
                try:
                    intf_dict[mod] = batch_list[mod][i]
                except IndexError:
                    pass

            status, start_time = enableAnalyticsOnPorts(intf_dict, amc_module)
            if not status:
                continue
            current_time = datetime.datetime.now()
            time_drift = current_time - start_time
            time_drift = time_drift.seconds
            if time_drift < 30:
                sleep_time = 31 - time_drift
                time.sleep(sleep_time)
            inte_list = []
            for mod in batch_list:
                try:
                    inte_list.extend(batch_list[mod][i])
                except IndexError:
                    pass
            data_dct = get_npuload_data(inte_list, ver, start_time)
            for mod in batch_list:
                try:
                    inte_list = batch_list[mod][i]
                    iopssum = 0
                    if mod not in amc_module:
                        for inte in inte_list:
                            if data_dct[inte]:
                                (
                                    tport,
                                    ttype,
                                    t_itl_count,
                                    t_scsi_iops,
                                    t_itn_count,
                                    t_nvme_iops,
                                    t_start_time,
                                    t_end_time,
                                    txwait,
                                    rx_util,
                                    tx_util,
                                    tot_iops,
                                ) = data_dct[inte].split("-")
                                iopssum += float(tot_iops)
                    if iopssum >= 90:
                        if mod not in eval_again:
                            eval_again[mod] = inte_list
                        else:
                            eval_again[mod].extend(inte_list)
                    else:
                        for inte in inte_list:
                            if data_dct[inte]:
                                if mod not in mod_matrix:
                                    mod_matrix[mod] = [data_dct[inte]]
                                else:
                                    mod_matrix[mod].append(data_dct[inte])
                            else:
                                no_traffic_ports.append(inte)
                except IndexError:
                    pass
        inte_list = []

        for mod in eval_again:
            inte_list.extend(eval_again[mod])
        if inte_list != []:
            if sig_hup_flag in [None, "Armed"]:
                clear_previous_lines(pline)
                print("Interface batches found to be consuming more than 90% npu")
                print("Evaluating interfaces {} again".format(",".join(inte_list)))
                pline = 0
            else:
                syslog.syslog(
                    2,
                    "ShowAnalytics: Interface batches found to be consuming more than 90% npu",
                )
                syslog.syslog(
                    2,
                    "ShowAnalytics: Evaluating interfaces {} again".format(
                        ",".join(inte_list)
                    ),
                )
        inte_list = []
        intf_dict = {}
        batch_list = {}

        for mod in eval_again:
            batch = [
                eval_again[mod][i : i + 1] for i in range(0, len(eval_again[mod]), 1)
            ]
            batch_list[mod] = batch

        len_list = []
        max_len = 0
        for mod in batch_list:
            len_list.append(len(batch_list[mod]))
            max_len = max(len_list)

        for i in range(max_len):
            batch_ints = []
            intf_dict = {}
            for mod in batch_list:
                try:
                    intf_dict[mod] = batch_list[mod][i]
                    batch_ints.extend(batch_list[mod][i])
                except IndexError:
                    pass
            if sig_hup_flag in [None, "Armed"]:
                clear_previous_lines(pline)
                print("Evaluating interfaces {}".format(",".join(batch_ints)))
                pline = 1
            else:
                syslog.syslog(
                    2,
                    "ShowAnalytics: Evaluating interfaces {}".format(
                        ",".join(batch_ints)
                    ),
                )

            status, start_time = enableAnalyticsOnPorts(intf_dict)
            if not status:
                continue
            current_time = datetime.datetime.now()
            time_drift = current_time - start_time
            time_drift = time_drift.seconds
            if time_drift < 30:
                sleep_time = 31 - time_drift
                time.sleep(sleep_time)

            data_dct = get_npuload_data(batch_ints, ver, start_time)
            for mod in batch_list:
                try:
                    inte_list = batch_list[mod][i]
                    for inte in inte_list:
                        if data_dct[inte]:
                            if mod not in mod_matrix:
                                mod_matrix[mod] = [data_dct[inte]]
                            else:
                                mod_matrix[mod].append(data_dct[inte])
                        else:
                            no_traffic_ports.append(inte)
                except IndexError:
                    pass

        col_empty = [""] * 12
        if sig_hup_flag not in [None, "Armed"]:
            file_name = "/bootflash/" + sig_hup_flag
            try:
                file_handler = open(file_name, "w+")
            except Exception as e:
                syslog.syslog(
                    2,
                    "ShowAnalytics: Unable to save output in \
                        bootflash with name {0} as {1}".format(
                        sig_hup_flag, e
                    ),
                )
                sys.exit(1)
        else:
            clear_previous_lines(pline)
        mod_list = mod_matrix.keys()
        mod_list = list(map(int, mod_list))
        mod_list.sort()
        mod_list = list(map(str, mod_list))

        for mod in mod_list:
            mod_iops_list = []
            mod_flow_list = []
            if int(mod) < 50:
                if sig_hup_flag not in [None, "Armed"]:
                    writeToFile(file_handler, "Module {}\n".format(mod))
                else:
                    print("Module {}".format(mod))
                    if args.outfile or args.appendfile:
                        try:
                            fh.write("Module {}".format(mod) + "\n")
                        except OSError as err:
                            print(
                                "Not able to write to a file, No space left on device"
                            )
                            sys.exit(0)

            m_itl_count, m_scsi_iops, m_itn_count, m_nvme_iops = 0, 0, 0, 0

            # if args.alias:
            t = PrettyTable(
                [
                    "",
                    "  ",
                    " SCSI ",
                    " NVMe ",
                    " Total ",
                    "SCSI",
                    "NVMe",
                    "Total",
                    "1s/1m/1h/72h",
                    "Utilization",
                    "Start Time",
                    "End Time",
                ],
                headers_misc=[
                    [
                        "above",
                        [
                            "Interface",
                            "Type",
                            "ITL/N Count",
                            " NPU Load %",
                            "TxWait",
                            "Rx/Tx",
                            "Analyis",
                            "Analysis",
                        ],
                        [1, 1, 3, 3, 1, 1, 1, 1],
                    ]
                ],
            )

            mod_matrix[mod] = sorted(
                mod_matrix[mod], key=lambda st: int(st.split("-")[0].split("/")[-1])
            )
            for port_metrix in mod_matrix[mod]:
                (
                    tport,
                    ttype,
                    t_itl_count,
                    t_scsi_iops,
                    t_itn_count,
                    t_nvme_iops,
                    t_start_time,
                    t_end_time,
                    txwait,
                    rx_util,
                    tx_util,
                    tot_iops,
                ) = port_metrix.split("-")
                t_itl_count, t_itn_count = [int(i) for i in [t_itl_count, t_itn_count]]
                t_scsi_iops, t_nvme_iops = [
                    float(i) for i in [t_scsi_iops, t_nvme_iops]
                ]
                m_itl_count += t_itl_count
                m_scsi_iops += round(t_scsi_iops, 1)
                m_itn_count += t_itn_count
                m_nvme_iops += round(t_nvme_iops, 1)
                port_flow_count = t_itl_count + t_itn_count
                port_iops_count = round(t_scsi_iops, 1) + round(t_nvme_iops, 1)
                mod_iops_list.append(port_iops_count)
                mod_flow_list.append(port_flow_count)

                if mod in amc_module:
                    t.add_row(
                        [
                            tport,
                            ttype,
                            t_itl_count,
                            t_itn_count,
                            port_flow_count,
                            "n/a",
                            "n/a",
                            "n/a",
                            txwait,
                            "{:.1f}%/{:.1f}%".format(float(rx_util), float(tx_util)),
                            t_start_time,
                            t_end_time,
                        ]
                    )
                else:
                    t.add_row(
                        [
                            tport,
                            ttype,
                            t_itl_count,
                            t_itn_count,
                            port_flow_count,
                            "{:.1f}".format(t_scsi_iops),
                            "{:.1f}".format(t_nvme_iops),
                            "{:.1f}".format(port_iops_count),
                            txwait,
                            "{:.1f}%/{:.1f}%".format(float(rx_util), float(tx_util)),
                            t_start_time,
                            t_end_time,
                        ]
                    )
            t.add_row(col_empty)
            # if args.alias:
            if mod in amc_module:
                t.add_row(
                    [
                        "*Total",
                        "",
                        m_itl_count,
                        m_itn_count,
                        (m_itl_count + m_itn_count),
                        "n/a",
                        "n/a",
                        "n/a",
                        "",
                        "",
                        "",
                        "",
                    ]
                )
            else:
                t.add_row(
                    [
                        "*Total",
                        "",
                        m_itl_count,
                        m_itn_count,
                        (m_itl_count + m_itn_count),
                        "{:.1f}".format(m_scsi_iops),
                        "{:.1f}".format(m_nvme_iops),
                        "{:.1f}".format(m_scsi_iops + m_nvme_iops),
                        "",
                        "",
                        "",
                        "",
                    ]
                )
            if mod in amc_module:
                psString = "Port sampling is not applicable\n"
            else:
                psString = "Recommended port sampling size: {0}\n \
                        ".format(
                    calculate_max_sample_window(mod_iops_list, mod_flow_list)
                )
            if sig_hup_flag not in [None, "Armed"]:
                writeToFile(file_handler, str(t.get_string()))
                if not interface_list_flag:
                    writeToFile(file_handler, "\n")
                    writeToFile(file_handler, psString)
            else:
                print(t)
                if args.outfile or args.appendfile:
                    data = t.get_string()
                    try:
                        fh.write(data + "\n")
                    except OSError as err:
                        print("Not able to write to a file, No space left on device")
                        sys.exit(0)

                if not interface_list_flag:
                    print(psString)
                    if args.outfile or args.appendfile:
                        try:
                            fh.write(psString)
                        except OSError as err:
                            print(
                                "Not able to write to a file, No space left on device"
                            )
                            sys.exit(0)
    if mod_matrix:
        if sig_hup_flag not in [None, "Armed"]:
            writeToFile(file_handler, "\n")
            writeToFile(
                file_handler,
                "* This total is an indicative reference \
based on evaluated ports",
            )
        else:
            print(
                "* This total is an indicative reference based on \
evaluated ports"
            )
            if args.outfile or args.appendfile:
                try:
                    fh.write(
                        "* This total is an indicative reference based on \
evaluated ports"
                        + "\n"
                    )
                except OSError as err:
                    print("Not able to write to a file, No space left on device")
                    sys.exit(0)

    if no_traffic_ports:
        no_traffic_ports_str = normalize_ports(no_traffic_ports)
        # print (no_traffic_ports)
        if err_out == []:
            err_out.append(
                "Traffic is not running on port {0}".format(no_traffic_ports_str)
            )
        error_log.extend(err_out)
    if npu_interface_list == []:
        print("No Up port found on device capable for analytics")
        sys.exit(1)
    else:
        if sig_hup_flag not in [None, "Armed"]:
            if error_log != []:
                writeToFile(file_handler, "\nErrors:\n------\n")
                for msg in error_log:
                    writeToFile(file_handler, msg)
            file_handler.close()
        else:
            if error_log != []:
                print("\nErrors:\n------\n")
                if args.outfile or args.appendfile:
                    try:
                        fh.write("\nErrors:\n------\n" + "\n")
                    except OSError as err:
                        print("Not able to write to a file, No space left on device")
                        sys.exit(0)
                for msg in error_log:
                    print(msg)
                    if args.outfile or args.appendfile:
                        try:
                            fh.write(msg + "\n")
                        except OSError as err:
                            print(
                                "Not able to write to a file, No space left on device"
                            )
                            sys.exit(0)
                if args.outfile or args.appendfile:
                    try:
                        fh.close()
                    except OSError as err:
                        print("Not able to write to a file, No space left on device")
                        sys.exit(0)
    # print(formatdate(localtime=True))

    syslog.syslog(2, "ShowAnalytics: Task Completed")


def displayVsanOverlay(json_out, ver=None):
    """
    **********************************************************************************
    * Function: displayVsanOverlay
    *
    * Input: json_out is the json data returned by switch as response for
    *         querry.
    *        ver is software version of the switch
    * Action: Displays per vsan throughput for the interface pointed by
    *          global args object
    * Returns: None
    **********************************************************************************
    """

    # have to write that

    metrics = {}
    sizeJson = len(json_out["values"])
    counter = 1
    while counter <= sizeJson:
        port, vsan, read, write, rios, wios, rir, wir = ("", "", "", "", "", "", "", "")
        for key, value in json_out["values"][str(counter)].items():
            if str(key) == "port":
                port = str(value)
                continue
            elif str(key) == "vsan":
                vsan = int(value)
                continue
            elif str(key) == "read_io_bandwidth":
                read = int(value)
                continue
            elif str(key) == "write_io_bandwidth":
                write = int(value)
                continue
            elif str(key) == "read_io_size_min":
                rios = int(value)
                continue
            elif str(key) == "write_io_size_min":
                wios = int(value)
                continue
            elif str(key) == "read_io_rate":
                rir = int(value)
                continue
            elif str(key) == "write_io_rate":
                wir = int(value)
            else:
                pass

        counter += 1
        if port not in metrics.keys():
            metrics[port] = {}
        metrics[port][vsan] = read_write_stats(read, write, rios, wios, rir, wir)

    port_metrics = {}
    f_ports = None
    global interface_list
    if interface_list is None:
        eports_to_consider = getAnalyticsEnabledPorts()
        if args.interface is None:
            f_ports = getPureFPorts()
    else:
        eports_to_consider = interface_list[1]
        port_metrics[interface_list[0]] = {}

    considered_port_count = 0
    for port in eports_to_consider:
        if port in metrics.keys():
            if f_ports is not None and (port in f_ports):
                port_metrics[port] = metrics[port]
                continue
            enabled_vsans = getVsansPerEPort(port)
            if interface_list is None:
                port_metrics[port] = metrics[port]
                port1 = port
            else:
                for vsan in metrics[port].keys():
                    a, b = metrics[port][vsan]
                    if vsan in port_metrics[interface_list[0]].keys():
                        c, d = port_metrics[interface_list[0]][vsan]
                        port_metrics[interface_list[0]][vsan] = [(a + c), (b + d)]
                    else:
                        port_metrics[interface_list[0]][vsan] = [a, b]
                if considered_port_count < (len(interface_list[1]) - 1):
                    considered_port_count += 1
                    continue
                else:
                    port1 = interface_list[0]

            evsan = [
                int(i)
                for i in enabled_vsans
                if int(i) not in [int(j) for j in port_metrics[port1].keys()]
            ]
            if evsan != []:
                for vsan in evsan:
                    port_metrics[port1][vsan] = [0, 0]

    col_names = ["", "Read", "Write", "Total"]

    for port in sorted(
        port_metrics,
        key=lambda x: tuple([int(i) for i in x[2:].split("/")])
        if not x.startswith("port-channel")
        else int(x[12:]),
    ):
        if port_metrics[port] == {}:
            if interface_list:
                print("\n\t Table is empty\n")
                sys.exit(1)
            else:
                continue

        t = PrettyTable(
            col_names,
            headers_misc=[
                ["above", ["VSAN", "Throughput (4s avg)"], [1, 3]],
                ["below", ["", "(MBps)", "(MBps)", "(MBps)"], [1, 1, 1, 1]],
            ],
        )
        # t.add_row(col_names_desc)
        t.align = "l"
        for vsan in sorted(port_metrics[port].keys()):
            col = []
            col.append("%d" % int(vsan))
            port_metrics[port][vsan] = [
                float(i) / 1000000 for i in port_metrics[port][vsan]
            ]
            col.append("{0:.1f}".format(port_metrics[port][vsan][0]))
            col.append("{0:.1f}".format(port_metrics[port][vsan][1]))
            tmp_tb = float(port_metrics[port][vsan][0]) + float(
                port_metrics[port][vsan][1]
            )
            col.append("{0:.1f}".format(tmp_tb))
            t.add_row(col)
        print("\n Interface " + port)
        print(t)
        if args.outfile or args.appendfile:
            data = t.get_string()
            try:
                fh.write("\n Interface " + port + "\n")
                fh.write(data + "\n")
            except OSError as err:
                print("Not able to write to a file, No space left on device")
                sys.exit(0)

    proto = "NVMe" if args.nvme else "SCSI"
    print("Note: This data is only for {0}\n".format(proto))
    if args.outfile or args.appendfile:
        try:
            fh.write("Note: This data is only for {0}\n".format(proto))
        except OSError as err:
            print("Not able to write to a file, No space left on device")
            sys.exit(0)
        try:
            fh.close()
        except OSError as err:
            print("Not able to write to a file, No space left on device")
            sys.exit(0)


def displayTop(args, json_out, return_vector, ver=None):
    """
    **********************************************************************************
    * Function: displayTop
    *
    * Input: It takes 3 input
    *           - json_out is the json data returned by switch as response for
    *              querry
    *           - return_vector is the list of 3 elements described as
    *             [<lines to be deleted before printing new iteration result>,
    *              <time to sleep between 2 iteration>,
    *              <data from previous iteration>]
    *           - ver is software version of switch
    * Action: Displays top 10 ITLs based on the key provided via args
    *         global object, by default key is ECT
    * Returns: return_vector is the same one as described in Input
    **********************************************************************************
    """

    global top_count
    global error
    global error_flag
    global max_fcid_len
    global top_limit
    terminal_size_msg = False

    vmid_enabled = getVmidFeature()

    if args.progress:
        sys.stdout.write("#")
        sys.stdout.flush()

    if args.alias:
        fcid2pwwn = getfcid2pwwn()
        pwwn2alias = getDalias()
        max_fcid_len = 20

    line_count = 0
    str1 = None
    str2 = None
    if error_flag:
        str1 = error["getData_str"]
        if "empty" in str1 or str1 == "":
            str1 = None
        else:
            line_count += error["line_count"]
            line_count += 1

    if args.initiator_flow or args.target_flow:
        json_out1 = None
    else:
        json_out1 = getData(args, 1)
    if error_flag:
        str2 = error["getData_str"]
        if "empty" in str2 or str2 == "":
            str2 = None
        else:
            line_count += error["line_count"]
            line_count += 1
    # print json_out
    # print return_vector[0]

    if json_out == " ":
        if json_out1 is None:
            tmp_clr_line_count = 2
            if return_vector[0] is not None:
                time.sleep(return_vector[1])
                if not args.noclear:
                    clear_previous_lines(return_vector[0])
            else:
                if not args.noclear:
                    clear_previous_lines(1)
            print()
            print("Data collected at : {}".format(formatdate(localtime=True)))
            if str1 is not None:
                print()
                print(str1)
            if (str2 is not None) and (str1 != str2):
                print()
                print(str2)
            if str1 == str2 and (str1 is not None):
                line_count -= error["line_count"] + 1
            tmp_clr_line_count += line_count
            if (str1 is None) and (str2 is None):
                print("\n\t Table is empty\n")
                tmp_clr_line_count = 5
            return [tmp_clr_line_count, return_vector[1], ""]
        else:
            json_out = json_out1
            json_out1 = None

    # clear_previous_lines(1)
    if args.progress:
        sys.stdout.write("##")
        sys.stdout.flush()

    tric, twic = (
        "total_time_metric_based_read_io_count",
        "total_time_metric_based_write_io_count",
    )
    if ver == "8.3(1)" or args.key == "IOSIZE":
        tric, twic = "total_read_io_count", "total_write_io_count"

    tlen = get_terminal_size()
    extra_lines = 14
    if args.key == "BUSY":
        extra_lines = 13
    if (tlen - extra_lines) < top_limit:
        top_count = tlen - extra_lines
        terminal_size_msg = True
    else:
        top_count = top_limit
        terminal_size_msg = False

    metrics = []
    pdata = {}
    dontPrintFlag = False
    while json_out:
        sizeJson = len(json_out["values"])
        counter = 1
        while counter <= sizeJson:

            iter_itl = json_out["values"][str(counter)]
            lun_id_str = "namespace_id" if args.nvme else "lun"
            if args.it_flow:
                port, initiator, vmid, target = [
                    str(iter_itl.get(unicode(i), ""))
                    for i in ["port", "initiator_id", "vmid", "target_id"]
                ]
            elif args.initiator_flow:
                port, initiator, vmid = [
                    str(iter_itl.get(unicode(i), ""))
                    for i in ["port", "initiator_id", "vmid"]
                ]
            elif args.target_flow:
                port, target = [
                    str(iter_itl.get(unicode(i), "")) for i in ["port", "target_id"]
                ]
            else:
                port, initiator, vmid, target, lun = [
                    str(iter_itl.get(unicode(i), ""))
                    for i in ["port", "initiator_id", "vmid", "target_id", lun_id_str]
                ]
            vsan = str(iter_itl.get("vsan", 0))
            (
                read,
                write,
                rb,
                wb,
                totalread,
                totalwrite,
                readCount,
                writeCount,
                tbp,
                readIoB,
                writeIoB,
            ) = [
                int(iter_itl.get(unicode(i), 0))
                for i in [
                    "read_io_rate",
                    "write_io_rate",
                    "read_io_bandwidth",
                    "write_io_bandwidth",
                    "total_read_io_time",
                    "total_write_io_time",
                    tric,
                    twic,
                    "total_busy_period",
                    "total_read_io_bytes",
                    "total_write_io_bytes",
                ]
            ]

            counter += 1
            if args.alias:
                if not args.target_flow:
                    if (str(initiator), int(vsan)) in fcid2pwwn:
                        init_pwwn = fcid2pwwn[(str(initiator), int(vsan))]
                        if init_pwwn in pwwn2alias:
                            initiator = pwwn2alias[init_pwwn]
                    if len(initiator) > 20:
                        initiator = initiator[0:20]
                if not args.initiator_flow:
                    if (str(target), int(vsan)) in fcid2pwwn:
                        tar_pwwn = fcid2pwwn[(target, int(vsan))]
                        if tar_pwwn in pwwn2alias:
                            target = pwwn2alias[tar_pwwn]
                    if len(target) > 20:
                        target = target[0:20]
            if vmid_enabled:
                if args.it_flow:
                    itl_id = (
                        port
                        + "::"
                        + vsan
                        + "::"
                        + initiator
                        + "::"
                        + vmid
                        + "::"
                        + target
                    )
                elif args.initiator_flow:
                    itl_id = port + "::" + vsan + "::" + initiator + "::" + vmid
                elif args.target_flow:
                    itl_id = port + "::" + vsan + "::" + target
                else:
                    itl_id = (
                        port
                        + "::"
                        + vsan
                        + "::"
                        + initiator
                        + "::"
                        + vmid
                        + "::"
                        + target
                        + "::"
                        + lun
                    )
            else:
                if args.it_flow:
                    itl_id = port + "::" + vsan + "::" + initiator + "::" + target
                elif args.initiator_flow:
                    itl_id = port + "::" + vsan + "::" + initiator
                elif args.target_flow:
                    itl_id = port + "::" + vsan + "::" + target
                else:
                    itl_id = (
                        port
                        + "::"
                        + vsan
                        + "::"
                        + initiator
                        + "::"
                        + target
                        + "::"
                        + lun
                    )
            if args.key is None or args.key == "IOPS":
                a = (
                    itl_id
                    + "::"
                    + str(read)
                    + "::"
                    + str(write)
                    + "::"
                    + str(read + write)
                )
            elif args.key == "THPUT":
                a = itl_id + "::" + str(rb) + "::" + str(wb) + "::" + str(rb + wb)
            elif args.key == "BUSY":
                pdata[itl_id] = str(tbp)
                if (return_vector[2] is not None) and (
                    itl_id in return_vector[2].keys()
                ):
                    bp = int(return_vector[2][itl_id])
                    # print("itl_id, tbp, bp ======> {}, {}  :   {}".format(itl_id,tbp,bp))
                    diffBp = abs(tbp - bp)
                else:
                    if return_vector[2] is None:
                        dontPrintFlag = True
                    diffBp = 0
                a = itl_id + "::" + " " + "::" + " " + "::" + str(diffBp)
            elif args.key == "ECT":
                pdata[itl_id] = (
                    str(readCount)
                    + "::"
                    + str(totalread)
                    + "::"
                    + str(writeCount)
                    + "::"
                    + str(totalwrite)
                )
                ectR, ectW = 0, 0
                if (return_vector[2] is not None) and (
                    itl_id in return_vector[2].keys()
                ):
                    rc, tr, wc, tw = [
                        int(i) for i in return_vector[2][itl_id].split("::")
                    ]
                    ectR = (
                        abs((tr - totalread) // (rc - readCount))
                        if rc != readCount
                        else 0
                    )
                    ectW = (
                        abs((tw - totalwrite) // (wc - writeCount))
                        if wc != writeCount
                        else 0
                    )
                else:
                    ectR = (totalread // readCount) if readCount != 0 else 0
                    ectW = (totalwrite // writeCount) if writeCount != 0 else 0

                a = (
                    itl_id
                    + "::"
                    + str(ectR)
                    + "::"
                    + str(ectW)
                    + "::"
                    + str(ectW + ectR)
                )
            elif args.key == "IOSIZE":
                pdata[itl_id] = (
                    str(readCount)
                    + "::"
                    + str(readIoB)
                    + "::"
                    + str(writeCount)
                    + "::"
                    + str(writeIoB)
                )
                iosizeR, iosizeW = 0, 0
                if (return_vector[2] is not None) and (
                    itl_id in return_vector[2].keys()
                ):
                    rc, tr, wc, tw = [
                        int(i) for i in return_vector[2][itl_id].split("::")
                    ]
                    iosizeR = (
                        abs((tr - readIoB) // (rc - readCount))
                        if rc != readCount
                        else 0
                    )
                    iosizeW = (
                        abs((tw - writeIoB) // (wc - writeCount))
                        if wc != writeCount
                        else 0
                    )
                else:
                    if return_vector[2] is None:
                        dontPrintFlag = True
                    iosizeR, iosizeW = 0, 0
                    # iosizeR = (readIoB // readCount) if readCount != 0 else 0
                    # iosizeW = (writeIoB // writeCount) if writeCount != 0 else 0

                a = (
                    itl_id
                    + "::"
                    + str(iosizeR)
                    + "::"
                    + str(iosizeW)
                    + "::"
                    + str(iosizeW + iosizeR)
                )

            metrics.append(a)

        json_out = None

        if json_out1 is not None:
            json_out = json_out1
            json_out1 = None

    if dontPrintFlag:
        clear_previous_lines(1)
        return [None, 2, pdata]
    # clear_previous_lines(1)
    if args.progress:
        sys.stdout.write("###")
        sys.stdout.flush()
    out_metrics = []
    sTep = 1000
    lm = len(metrics)
    if args.it_flow:
        sort_on = 6
    elif args.initiator_flow or args.target_flow:
        sort_on = 5
    else:
        sort_on = 7
    if vmid_enabled:
        if not args.target_flow:
            sort_on = sort_on + 1
    if lm > sTep:
        d_l, r_l = [int(i) for i in [lm // sTep, lm % sTep]]
        for c_li in range(1, d_l + 1):
            out_metrics.extend(
                sorted(
                    metrics[(c_li - 1) * sTep : (c_li * sTep)],
                    key=lambda st: int(st.split("::")[sort_on]),
                    reverse=True,
                )[:top_count]
            )
        if args.progress:
            # sys.stdout.write("###%d"%c_li)
            # sys.stdout.flush()
            pass
        out_metrics.extend(
            sorted(
                metrics[d_l * sTep : lm + 1],
                key=lambda st: int(st.split("::")[sort_on]),
                reverse=True,
            )[:top_count]
        )
        port_metrics = sorted(
            out_metrics, key=lambda st: int(st.split("::")[sort_on]), reverse=True
        )[:top_count]
    else:
        port_metrics = sorted(
            metrics, key=lambda st: int(st.split("::")[sort_on]), reverse=True
        )[:top_count]
    # clear_previous_lines(1)
    lun_str = "Namespace" if args.nvme else "LUN"
    lun_str_len = max_nsid_len if args.nvme else max_lunid_len
    if args.progress:
        sys.stdout.write("####")
        sys.stdout.flush()
    if args.it_flow:
        if vmid_enabled:
            col_names = [
                "PORT",
                "{0:^{w1}} | {1:^{w2}} | {2:^{w3}} | {3:^{w4}} ".format(
                    "VSAN",
                    "Initiator",
                    "VMID",
                    "Target",
                    w1=max_vsan_len,
                    w2=max_fcid_len,
                    w3=max_vmid_len,
                    w4=max_fcid_len,
                ),
            ]
        else:
            col_names = [
                "PORT",
                "{0:^{w1}} | {1:^{w2}} | {2:^{w3}} ".format(
                    "VSAN",
                    "Initiator",
                    "Target",
                    w1=max_vsan_len,
                    w2=max_fcid_len,
                    w3=max_fcid_len,
                ),
            ]
    elif args.initiator_flow:
        if vmid_enabled:
            col_names = [
                "PORT",
                "{0:^{w1}} | {1:^{w2}} | {2:^{w3}} ".format(
                    "VSAN",
                    "Initiator",
                    "VMID",
                    w1=max_vsan_len,
                    w2=max_fcid_len,
                    w3=max_vmid_len,
                ),
            ]
        else:
            col_names = [
                "PORT",
                "{0:^{w1}} | {1:^{w2}} ".format(
                    "VSAN", "Initiator", w1=max_vsan_len, w2=max_fcid_len
                ),
            ]
    elif args.target_flow:
        # if vmid_enabled:
        #   col_names = ["PORT", "{0:^{w1}} | {1:^{w2}} | {2:^{w3}} ".
        #               format('VSAN','Target','VMID',w1=max_vsan_len, \
        #               w2=max_fcid_len, w3=max_vmid_len)]
        # else:
        col_names = [
            "PORT",
            "{0:^{w1}} | {1:^{w2}} ".format(
                "VSAN", "Target", w1=max_vsan_len, w2=max_fcid_len
            ),
        ]

    else:
        if vmid_enabled:
            col_names = [
                "PORT",
                "{0:^{w1}} | {1:^{w2}} | {2:^{w3}} | {3:^{w4}} | {4:^{w5}} ".format(
                    "VSAN",
                    "Initiator",
                    "VMID",
                    "Target",
                    lun_str,
                    w1=max_vsan_len,
                    w2=max_fcid_len,
                    w3=max_vmid_len,
                    w4=max_fcid_len,
                    w5=lun_str_len,
                ),
            ]
        else:
            col_names = [
                "PORT",
                "{0:^{w1}} | {1:^{w2}} | {2:^{w3}} | {3:^{w4}} ".format(
                    "VSAN",
                    "Initiator",
                    "Target",
                    lun_str,
                    w1=max_vsan_len,
                    w2=max_fcid_len,
                    w3=max_fcid_len,
                    w4=lun_str_len,
                ),
            ]

    if args.key is None or args.key == "IOPS":
        col_names.append("Avg IOPS")
    elif args.key == "THPUT":
        col_names.append("Avg Throughput")
    elif args.key == "BUSY":
        col_names.append("Total Busy Period")
    elif args.key == "ECT":
        col_names.append("ECT")
    elif args.key == "IOSIZE":
        col_names.append("Avg IO Size")
    t = PrettyTable(col_names)
    line_count = 4
    if args.key == "THPUT":
        t = PrettyTable(col_names)
        row_val = [" ", " ", " Read   |   Write"]
    else:
        row_val = [" ", " ", "Read  |  Write"]

    if args.key != "BUSY":
        line_count = 4
        t.add_row(row_val)
    else:
        line_count = 3

    if args.nvme:
        t.align[col_names[1]] = "l"

    for data in port_metrics:
        if vmid_enabled:
            if args.it_flow:
                p, v, i, vmid, ta, r, w, to = data.split("::")
                col_values = [
                    p,
                    "{0:>{w1}} | {1:^{w2}} | {2:>{w3}} | {3:^{w4}} ".format(
                        v,
                        i,
                        vmid,
                        ta,
                        w1=max_vsan_len,
                        w2=max_fcid_len,
                        w3=max_vmid_len,
                        w4=max_fcid_len,
                    ),
                ]
            elif args.initiator_flow:
                p, v, i, vmid, r, w, to = data.split("::")
                col_values = [
                    p,
                    "{0:>{w1}} | {1:^{w2}} | {2:>{w3}} ".format(
                        v, i, vmid, w1=max_vsan_len, w2=max_fcid_len, w3=max_vmid_len
                    ),
                ]
            elif args.target_flow:
                p, v, ta, r, w, to = data.split("::")
                col_values = [
                    p,
                    "{0:>{w1}} | {1:^{w2}}".format(
                        v, ta, w1=max_vsan_len, w2=max_fcid_len
                    ),
                ]
            else:
                p, v, i, vmid, ta, l, r, w, to = data.split("::")
                col_values = [
                    p,
                    "{0:>{w1}} | {1:^{w2}} | {2:>{w3}} | {3:^{w4}} | {4:>{w5}} ".format(
                        v,
                        i,
                        vmid,
                        ta,
                        l,
                        w1=max_vsan_len,
                        w2=max_fcid_len,
                        w3=max_vmid_len,
                        w4=max_fcid_len,
                        w5=lun_str_len,
                    ),
                ]
        else:
            if args.it_flow:
                p, v, i, ta, r, w, to = data.split("::")
                col_values = [
                    p,
                    "{0:>{w1}} | {1:^{w2}} | {2:>{w3}} ".format(
                        v, i, ta, w1=max_vsan_len, w2=max_fcid_len, w3=max_fcid_len
                    ),
                ]
            elif args.initiator_flow:
                p, v, i, r, w, to = data.split("::")
                col_values = [
                    p,
                    "{0:>{w1}} | {1:^{w2}} ".format(
                        v, i, w1=max_vsan_len, w2=max_fcid_len
                    ),
                ]
            elif args.target_flow:
                p, v, ta, r, w, to = data.split("::")
                col_values = [
                    p,
                    "{0:>{w1}} | {1:^{w2}} ".format(
                        v, ta, w1=max_vsan_len, w2=max_fcid_len
                    ),
                ]
            else:
                p, v, i, ta, l, r, w, to = data.split("::")
                col_values = [
                    p,
                    "{0:>{w1}} | {1:^{w2}} | {2:^{w3}} | {3:>{w4}} ".format(
                        v,
                        i,
                        ta,
                        l,
                        w1=max_vsan_len,
                        w2=max_fcid_len,
                        w3=max_fcid_len,
                        w4=lun_str_len,
                    ),
                ]

        if args.key == "THPUT":
            col_values.append("{0:^11}| {1:^10}".format(thput_conv(r), thput_conv(w)))
        elif args.key == "ECT":
            col_values.append("{0:>8} |{1:^10}".format(time_conv(r), time_conv(w)))
        elif args.key == "BUSY":
            col_values.append("{0:^8}".format(time_conv(to)))
        elif args.key == "IOSIZE":
            col_values.append("{0:>8} |{1:^10}".format(size_conv(r), size_conv(w)))
        else:
            col_values.append("{0:^8}|{1:^8}".format(r, w))

        t.add_row(col_values)
        line_count += 1

    if args.progress:
        sys.stdout.write("")
        sys.stdout.flush()
    if return_vector[0] is not None:
        time.sleep(return_vector[1])
        if not args.noclear:
            clear_previous_lines(return_vector[0])
    line_count += 5
    if return_vector == [None, 2, None]:
        clear_previous_lines(1)
    if str1:
        print()
        print(str1)
    if str2:
        print()
        print(str2)
    if terminal_size_msg and line_count >= tlen - 5:
        print()
        print(
            "Only top {} entries are shown based on your terminal size.".format(
                top_count
            )
        )
        print(
            "Please adjust the terminal size and restart the command to see more entries"
        )
        line_count += 3
    print()
    print("Data collected at : {}".format(formatdate(localtime=True)))
    print()
    print(t)
    if args.outfile or args.appendfile:
        data = t.get_string()
        try:
            try:
                fh.write(data + "\n")
            except OSError as err:
                print("Not able to write to a file, No space left on device")
                sys.exit(0)
        except:
            if args.appendfile:
                outfile = args.appendfile
            if args.outfile:
                outfile = args.outfile
            os.chdir("/bootflash")
            try:
                fh = open(outfile, "a+")
            except OSError as err:
                print("Not able to write to a file, No space left on device")
                sys.exit(0)
            try:
                fh.write(
                    "Data collected at : {}".format(formatdate(localtime=True)) + "\n"
                )
                fh.write(data + "\n")
            except OSError as err:
                print("Not able to write to a file, No space left on device")
                sys.exit(0)
        try:
            fh.close()
        except OSError as err:
            print("Not able to write to a file, No space left on device")
            sys.exit(0)

    print()
    if args.key == "ECT" or args.key == "BUSY" or args.key == "IOSIZE":
        return [line_count, return_vector[1], pdata]
    else:
        return [line_count, return_vector[1], ""]


def displayOutstandingIo(json_out, return_vector, ver=None):
    """
    **********************************************************************************
    * Function: displayOutstandingIo
    *
    * Input: It takes 3 input
    *           - json_out is the json data returned by switch as response
    *              for querry
    *           - return_vector is the list of 3 elements described as :
    *             [<lines to be deleted before printing new iteration result>,
    *              <time to sleep between 2 iteration>,
    *              <data from previous iteration>]
    *           - ver is software version of switch
    * Action: Displays Outstanding io per interface
    * Returns: return_vector is the same one as described in Input
    **********************************************************************************
    """

    global error
    global error_flag
    global max_fcid_len

    vmid_enabled = getVmidFeature()

    if args.alias:
        fcid2pwwn = getfcid2pwwn()
        pwwn2alias = getDalias()
        max_fcid_len = 20

    f_ports = getPureFPorts()
    port = args.interface
    if port not in f_ports:
        print("--outstanding-io is only supported on F Ports")
        return [None, return_vector[1], None]
        exit()

    line_count = 0
    str1 = None
    str2 = None
    if error_flag:
        str1 = error["getData_str"]
        if "empty" in str1 or str1 == "":
            str1 = None
        else:
            line_count += error["line_count"]
            line_count += 1

    lun_str = "Namespace" if args.nvme else "LUN"
    lun_str_len = max_nsid_len if args.nvme else max_lunid_len
    if vmid_enabled:
        col_names = [
            "{0:^{w1}} | {1:^{w2}} | {2:^{w3}} | {3:^{w4}} ".format(
                "Initiator",
                "VMID",
                "Target",
                lun_str,
                w1=max_fcid_len,
                w2=max_vmid_len,
                w3=max_fcid_len,
                w4=lun_str_len,
            ),
            "Outstanding IO",
        ]
    else:
        col_names = [
            "{0:^{w1}} | {1:^{w2}} | {2:^{w3}} ".format(
                "Initiator",
                "Target",
                lun_str,
                w1=max_fcid_len,
                w2=max_fcid_len,
                w3=lun_str_len,
            ),
            "Outstanding IO",
        ]
    json_out1 = getData(args, 1, ver)
    # print json_out

    if error_flag:
        str2 = error["getData_str"]
        if "empty" in str2 or str2 == "":
            str2 = None
        else:
            line_count += error["line_count"]
            line_count += 1

    if json_out == " ":
        if json_out1 is None:
            tmp_clr_line_count = 2
            if return_vector[0] is not None:
                time.sleep(return_vector[1])
                clear_previous_lines(return_vector[0])
            else:
                clear_previous_lines(1)
            print()
            print("Data collected at : {}".format(formatdate(localtime=True)))
            if str1 is not None:
                print()
                print(str1)
            if (str2 is not None) and (str1 != str2):
                print()
                print(str2)
            if str1 == str2 and str1 is not None:
                line_count -= error["line_count"] + 1
            tmp_clr_line_count += line_count
            if (str1 is None) and (str2 is None):
                print("\n\t Table is empty\n")
                tmp_clr_line_count = 5
            return [tmp_clr_line_count, return_vector[1], ""]
        else:
            json_out = json_out1
            json_out1 = None

    metrics = []
    while json_out:
        sizeJson = len(json_out["values"])
        counter = 1
        while counter <= sizeJson:
            iter_itl = json_out["values"][str(counter)]
            lun_id_str = "namespace_id" if args.nvme else "lun"
            port, initiator, vmid, target, lun = [
                str(iter_itl.get(unicode(i), ""))
                for i in ["port", "initiator_id", "vmid", "target_id", lun_id_str]
            ]
            vsan = str(iter_itl.get("vsan", 0))
            read, write = [
                int((iter_itl.get(unicode(i), 0)))
                for i in ["active_io_read_count", "active_io_write_count"]
            ]
            counter += 1

            if args.alias:
                if (str(initiator), int(vsan)) in fcid2pwwn:
                    init_pwwn = fcid2pwwn[(str(initiator), int(vsan))]
                    if init_pwwn in pwwn2alias:
                        initiator = pwwn2alias[init_pwwn]
                if len(initiator) > 20:
                    initiator = initiator[0:20]

                if (str(target), int(vsan)) in fcid2pwwn:
                    tar_pwwn = fcid2pwwn[(target, int(vsan))]
                    if tar_pwwn in pwwn2alias:
                        target = pwwn2alias[tar_pwwn]
                if len(target) > 20:
                    target = target[0:20]

            if vmid_enabled:
                a = (
                    str(port)
                    + "::"
                    + str(vsan)
                    + "::"
                    + str(initiator)
                    + "::"
                    + str(vmid)
                    + "::"
                    + str(target)
                    + "::"
                    + str(lun)
                    + "::"
                    + str(read)
                    + "::"
                    + str(write)
                )
            else:
                a = (
                    str(port)
                    + "::"
                    + str(vsan)
                    + "::"
                    + str(initiator)
                    + "::"
                    + str(target)
                    + "::"
                    + str(lun)
                    + "::"
                    + str(read)
                    + "::"
                    + str(write)
                )

            metrics.append(a)
        json_out = None

        if json_out1 is not None:
            json_out = json_out1
            json_out1 = None

    port_metrics = metrics

    if not return_vector[0]:
        try:
            flogis = [
                str(i)
                for i in flogi(
                    cli.cli(
                        r"show flogi database interface {0} | ex '\-\-' | ex '^\s*$' | ex Tot | ex PORT ".format(
                            port
                        )
                    )
                ).get_fcids(port)
            ]
        except Exception as e:
            print("Unable to check flogi database. This might be NPV device")
            os._exit(1)
        if vmid_enabled:
            i, vid, ta = [fcid_Normalizer(z) for z in port_metrics[0].split("::")[2:5]]
        else:
            i, ta = [fcid_Normalizer(z) for z in port_metrics[0].split("::")[2:4]]

        fcns_type = None
        try:
            if i in flogis:
                fcns_type = "Initiator"
            elif ta in flogis:
                fcns_type = "Target"
            else:
                fcns_type = "NA"
        except Exception:
            pass
        vSan = metrics[0].split("::")[1]
        pdata = "\n Interface : {0}  VSAN : {1}  FCNS_type : {2}\
            ".format(
            port, vSan, fcns_type
        )
        print(pdata)
        if args.outfile or args.appendfile:
            try:
                try:
                    fh.write(pdata + "\n")
                except OSError as err:
                    print("Not able to write to a file, No space left on device")
                    sys.exit(0)
            except:
                if args.appendfile:
                    outfile = args.appendfile
                if args.outfile:
                    outfile = args.outfile
                os.chdir("/bootflash")
                fh = open(outfile, "a+")
                try:
                    fh.write(
                        "Data collected at : {}".format(formatdate(localtime=True))
                        + "\n"
                    )
                    fh.write(pdata + "\n")
                except OSError as err:
                    print("Not able to write to a file, No space left on device")
                    sys.exit(0)

    t = PrettyTable(col_names)
    t.add_row([" ", "Read | Write"])
    t.add_row([" ", " "])
    line_count += 5

    qdpth = 0

    if args.nvme:
        t.align[col_names[0]] = "l"

    for data in port_metrics:
        if vmid_enabled:
            p, v, i, vmid, ta, l, r, w = data.split("::")
        else:
            p, v, i, ta, l, r, w = data.split("::")
        o = int(r) + int(w)
        qdpth += o
        line_count += 1
        if vmid_enabled:
            t.add_row(
                [
                    "{0:^{w1}} | {1:>{w2}} | {2:^{w3}} | {3:>{w4}}".format(
                        i,
                        vmid,
                        ta,
                        l,
                        w1=max_fcid_len,
                        w2=max_vmid_len,
                        w3=max_fcid_len,
                        w4=lun_str_len,
                    ),
                    "{0:^3} | {1:^3}".format(r, w),
                ]
            )
        else:
            t.add_row(
                [
                    "{0:^{w1}} | {1:^{w2}} | {2:>{w3}}".format(
                        i, ta, l, w1=max_fcid_len, w2=max_fcid_len, w3=lun_str_len
                    ),
                    "{0:^3} | {1:^3}".format(r, w),
                ]
            )
    # t.add_footer([[["Qdepth",str(qdpth)],[1,1],['l','l']]])
    # t.add_row(['Qdepth',qdpth])
    line_count += 4
    if return_vector[0] is not None:
        time.sleep(return_vector[1])
        clear_previous_lines(return_vector[0])
    if return_vector[0] is not None:
        clear_previous_lines(2)
        print("Data collected at : {}".format(formatdate(localtime=True)))
    if return_vector[2]:
        pdata = return_vector[2]
        print(pdata)
    print()
    print(t)
    if args.outfile or args.appendfile:
        data = t.get_string()
        try:
            try:
                fh.write(data + "\n")
            except OSError as err:
                print("Not able to write to a file, No space left on device")
                sys.exit(0)
        except:
            if args.appendfile:
                outfile = args.appendfile
            if args.outfile:
                outfile = args.outfile
            os.chdir("/bootflash")
            try:
                fh = open(outfile, "a+")
            except OSError as err:
                print("Not able to write to a file, No space left on device")
                sys.exit(0)
            try:
                fh.write(
                    "Data collected at : {}".format(formatdate(localtime=True)) + "\n"
                )
                fh.write(data + "\n")
            except OSError as err:
                print("Not able to write to a file, No space left on device")
                sys.exit(0)

    if args.limit == max_flow_limit:
        print("Instantaneous Qdepth : {}".format(qdpth))
        if args.outfile or args.appendfile:
            try:
                fh.write("Instantaneous Qdepth : {}".format(qdpth) + "\n")
            except OSError as err:
                print("Not able to write to a file, No space left on device")
                sys.exit(0)
            try:
                fh.close()
            except OSError as err:
                print("Not able to write to a file, No space left on device")
                sys.exit(0)

        line_count += 1
    print("")
    return [line_count, return_vector[1], pdata]


def displaySystemLoadActive(ver=None):
    """
    **********************************************************************************
    * Function: displaySystemLoadActive
    *
    * Input:  ver is software version of switch
    * Action: Provides per module system load info for active IT(L/N)
    * Returns: None
    **********************************************************************************
    """

    global error_flag
    ana_query = cli.cli("show analytics query all")
    inst_q = showAnalyticsQuery(ana_query)
    qdetails = inst_q.get_query_details()

    amc_mods = get_amc_modules()
    amc_port_groups = get_amc_port_groups(amc_mods)

    conf_response = str(
        input(
            "This will run differential query on scsi_initiator_itl_flow, scsi_target_itl_flow, \nnvme_initiator_itn_flow, nvme_target_itn_flow, scsi_initiator, scsi_target, \nnvme_initiator and nvme_target  or use the result of installed query if present \n Do you want to continue [Yes|No]? [n]"
        )
    )
    if conf_response not in ["Y", "y", "Yes", "yes", "YES"]:
        return False
    else:
        if args.outfile or args.appendfile:
            try:
                fh.write(
                    "This will run differential query on scsi_initiator_itl_flow, scsi_target_itl_flow, \nnvme_initiator_itn_flow, nvme_target_itn_flow scsi_initiator, scsi_target, \nnvme_initiator and nvme_target or use the result of installed query if present \n Do you want to continue [Yes|No]? [n]"
                    + conf_response
                    + "\n"
                )
            except OSError as err:
                print("Not able to write to a file, No space left on device")
                sys.exit(0)
        json_out_p = {}
        json_out = {}
        flow_keys = [
            "i_itl",
            "t_itl",
            "i_itn",
            "t_itn",
            "s_init",
            "s_target",
            "n_init",
            "n_target",
        ]
        query_dict = {}
        for qkey, qvalue in qdetails.items():
            flow = None
            pattern1 = r"select\s+all"
            pattern2 = "select.*port.*from"
            pattern3 = "select.*target_id.*from"
            pattern4 = "select.*initiator_id.*from"
            pattern5 = r"select.*from\s+(\S+)"
            match1 = re.search(pattern1, qvalue["string"])
            match2 = re.search(pattern2, qvalue["string"])
            match3 = re.search(pattern3, qvalue["string"])
            match4 = re.search(pattern4, qvalue["string"])
            match5 = re.search(pattern5, qvalue["string"])
            if match5:
                flow = match5.group(1).split(".")[1]
            if (
                flow == "scsi_initiator_itl_flow"
                or flow == "scsi_target_itl_flow"
                or flow == "nvme_initiator_itn_flow"
                or flow == "nvme_target_itn_flow"
                or flow == "scsi_initiator"
                or flow == "scsi_target"
                or flow == "nvme_initiator"
                or flow == "nvme_target"
            ):
                if "differential" in qvalue["options"]:
                    if "where" in qvalue["string"] or "limit" in qvalue["string"]:
                        print()
                        print(
                            "Installed query '{}' has where/limit clause hence exiting...".format(
                                qkey
                            )
                        )
                        return False
                    else:
                        if flow == "scsi_initiator" or flow == "nvme_initiator":
                            if not match1 and not (match2 and match4):
                                print()
                                print(
                                    "Installed query '{}' doesn't fetch port,initiator details hence exiting...".format(
                                        qkey
                                    )
                                )
                                return False
                        elif flow == "scsi_target" or flow == "nvme_target":
                            if not match1 and not (match2 and match3):
                                print()
                                print(
                                    "Installed query '{}' doesn't fetch port,target details hence exiting...".format(
                                        qkey
                                    )
                                )
                                return False
                        elif not (match1) and not (match2 and match3 and match4):
                            print()
                            print(
                                "Installed query '{}' doesn't fetch port,initiator,target details hence exiting...".format(
                                    qkey
                                )
                            )
                            return False
                    if flow == "scsi_initiator_itl_flow":
                        query_dict["i_itl"] = qkey
                    elif flow == "scsi_target_itl_flow":
                        query_dict["t_itl"] = qkey
                    elif flow == "nvme_initiator_itn_flow":
                        query_dict["i_itn"] = qkey
                    elif flow == "nvme_target_itn_flow":
                        query_dict["t_itn"] = qkey
                    elif flow == "scsi_initiator":
                        query_dict["s_init"] = qkey
                    elif flow == "scsi_target":
                        query_dict["s_target"] = qkey
                    elif flow == "nvme_initiator":
                        query_dict["n_init"] = qkey
                    elif flow == "nvme_target":
                        query_dict["n_target"] = qkey
        cdate = formatdate(localtime=True)
        print("\nData collected at : {}\n".format(cdate))
        if query_dict:
            print(
                "Using result of installed queries: {}\n".format(
                    ",".join(list(query_dict.values()))
                )
            )
        if args.outfile or args.appendfile:
            try:
                fh.write("\nData collected at : {}".format(cdate) + "\n")
                if query_dict:
                    fh.write(
                        "Using result of installed queries: {}\n".format(
                            ",".join(list(query_dict.values()))
                        )
                    )
            except OSError as err:
                print("Not able to write to a file, No space left on device")
                sys.exit(0)
        for fkey in flow_keys:
            if fkey not in query_dict.keys():
                json_out_p[fkey] = getData(args, ver=sw_ver, misc=fkey)
                if error_flag:
                    str1 = error["getData_str"]
                    if "empty" in str1:
                        continue
                    else:
                        print(str1)
                        return False

        time.sleep(10)
        for fkey in flow_keys:
            if fkey in query_dict.keys():
                json_out[fkey] = getQueryResult(query_dict[fkey])
            else:
                error_flag = False
                json_out[fkey] = getData(args, ver=sw_ver, misc=fkey)
                if error_flag:
                    str1 = error["getData_str"]
                    if "empty" in str1:
                        continue
                    else:
                        print(str1)
                        return False

        initiator_scsi_dict, target_scsi_dict = {}, {}
        initiator_nvme_dict, target_nvme_dict = {}, {}
        active_itls_dict, active_itns_dict = {}, {}
        active_itls, active_itns = {}, {}
        mods = []
        port_groups = {}
        s_initiator, s_target, n_initiator, n_target = {}, {}, {}, {}
        il_modInit, il_modPgInit, tl_modTarget, tl_modPgTarget = [], [], [], []
        in_modInit, in_modPgInit, tn_modTarget, tn_modPgTarget = [], [], [], []
        itl_mod, itn_mod, itl_modpg, itn_modpg = [], [], [], []
        for fkey in flow_keys:
            if not json_out[fkey]:
                continue
            sizeJson = len(json_out[fkey]["values"])
            counter = 1
            while counter <= sizeJson:
                for key, value in json_out[fkey]["values"][str(counter)].items():
                    if str(key) == "port":
                        port = value
                        mod = port.strip().split("/")[0][2:]
                        intf = port.strip().split("/")[1]
                        if args.module:
                            if mod not in args.module:
                                continue
                        if mod in amc_mods:
                            for key, value in amc_port_groups[mod].items():
                                if int(intf) in value:
                                    port_group = key
                                    break
                        else:
                            port_group = 1
                        if mod not in mods:
                            mods.append(mod)
                            port_groups[mod] = []
                            s_initiator[mod], s_target[mod] = 0, 0
                            n_initiator[mod], n_target[mod] = 0, 0
                            active_itls[mod], active_itns[mod] = 0, 0
                            (
                                active_itls_dict[mod],
                                active_itns_dict[mod],
                                target_scsi_dict[mod],
                                target_nvme_dict[mod],
                                initiator_scsi_dict[mod],
                                initiator_nvme_dict[mod],
                            ) = ({}, {}, {}, {}, {}, {})
                        if port_group not in port_groups[mod]:
                            port_groups[mod].append(port_group)
                            (
                                active_itls_dict[mod][port_group],
                                active_itns_dict[mod][port_group],
                                target_scsi_dict[mod][port_group],
                                target_nvme_dict[mod][port_group],
                                initiator_scsi_dict[mod][port_group],
                                initiator_nvme_dict[mod][port_group],
                            ) = (0, 0, 0, 0, 0, 0)

                        if fkey == "s_init":
                            init_id = json_out[fkey]["values"][str(counter)][
                                "initiator_id"
                            ]
                            s_mi = "{}-{}".format(mod, init_id)
                            s_mpi = "{}-{}-{}".format(mod, port_group, init_id)
                            if s_mi not in il_modInit:
                                il_modInit.append(s_mi)
                                s_initiator[mod] = s_initiator[mod] + 1
                            if s_mpi not in il_modPgInit:
                                il_modPgInit.append(s_mpi)
                                initiator_scsi_dict[mod][port_group] = (
                                    initiator_scsi_dict[mod][port_group] + 1
                                )
                        elif fkey == "s_target":
                            target_id = json_out[fkey]["values"][str(counter)][
                                "target_id"
                            ]
                            s_mt = "{}-{}".format(mod, target_id)
                            s_mpt = "{}-{}-{}".format(mod, port_group, target_id)
                            if s_mt not in tl_modTarget:
                                tl_modTarget.append(s_mt)
                                s_target[mod] = s_target[mod] + 1
                            if s_mpt not in tl_modPgTarget:
                                tl_modPgTarget.append(s_mpt)
                                target_scsi_dict[mod][port_group] = (
                                    target_scsi_dict[mod][port_group] + 1
                                )
                        elif fkey == "n_init":
                            init_id = json_out[fkey]["values"][str(counter)][
                                "initiator_id"
                            ]
                            n_mi = "{}-{}".format(mod, init_id)
                            n_mpi = "{}-{}-{}".format(mod, port_group, init_id)
                            if n_mi not in in_modInit:
                                in_modInit.append(n_mi)
                                n_initiator[mod] = n_initiator[mod] + 1
                            if n_mpi not in in_modPgInit:
                                in_modPgInit.append(n_mpi)
                                initiator_nvme_dict[mod][port_group] = (
                                    initiator_nvme_dict[mod][port_group] + 1
                                )
                        elif fkey == "n_target":
                            target_id = json_out[fkey]["values"][str(counter)][
                                "target_id"
                            ]
                            n_mt = "{}-{}".format(mod, target_id)
                            n_mpt = "{}-{}-{}".format(mod, port_group, target_id)
                            if n_mt not in tn_modTarget:
                                tn_modTarget.append(n_mt)
                                n_target[mod] = n_target[mod] + 1
                            if n_mpt not in tn_modPgTarget:
                                tn_modPgTarget.append(n_mpt)
                                target_nvme_dict[mod][port_group] = (
                                    target_nvme_dict[mod][port_group] + 1
                                )
                        if "itl" in fkey:
                            init_id = json_out[fkey]["values"][str(counter)][
                                "initiator_id"
                            ]
                            target_id = json_out[fkey]["values"][str(counter)][
                                "target_id"
                            ]
                            lun = json_out[fkey]["values"][str(counter)]["lun"]
                            itl_m = "{}-{}-{}-{}".format(mod, init_id, target_id, lun)
                            itl_mpg = "{}-{}-{}-{}-{}".format(
                                mod, port_group, init_id, target_id, lun
                            )
                            if itl_m not in itl_mod:
                                itl_mod.append(itl_m)
                                active_itls[mod] = active_itls[mod] + 1
                            if itl_mpg not in itl_modpg:
                                itl_modpg.append(itl_mpg)
                                active_itls_dict[mod][port_group] = (
                                    active_itls_dict[mod][port_group] + 1
                                )
                        if "itn" in fkey:
                            init_id = json_out[fkey]["values"][str(counter)][
                                "initiator_id"
                            ]
                            target_id = json_out[fkey]["values"][str(counter)][
                                "target_id"
                            ]
                            namespace = json_out[fkey]["values"][str(counter)][
                                "namespace_id"
                            ]
                            itn_m = "{}-{}-{}-{}".format(
                                mod, init_id, target_id, namespace
                            )
                            itn_mpg = "{}-{}-{}-{}-{}".format(
                                mod, port_group, init_id, target_id, namespace
                            )
                            if itn_m not in itn_mod:
                                itn_mod.append(itn_m)
                                active_itns[mod] = active_itns[mod] + 1
                            if itn_mpg not in itn_modpg:
                                itn_modpg.append(itn_mpg)
                                active_itns_dict[mod][port_group] = (
                                    active_itns_dict[mod][port_group] + 1
                                )
                counter += 1

        total_scsi_itls, total_nvme_itls, total_init_scsi, total_init_nvme = 0, 0, 0, 0
        total_targ_scsi, total_targ_nvme, total_init, total_targ, total_it = (
            0,
            0,
            0,
            0,
            0,
        )
        if not mods:
            print("\nNo active ITL/Ns\n")
            sys.exit(1)
        if args.module:
            nodataMod = [m for m in args.module if m not in mods]
            if nodataMod:
                print(
                    "\nNo active ITL/Ns found for modules: {}\n".format(
                        ",".join(nodataMod)
                    )
                )
        t = PrettyTable(
            [
                "  ",
                " SCSI ",
                " NVMe ",
                " Total ",
                "SCSI",
                "NVMe",
                "Total",
                " SCSI",
                " NVMe",
                " Total",
            ],
            headers_misc=[
                [
                    "above",
                    ["Module", "ITL/N Count", " Initiators", "Targets"],
                    [1, 3, 3, 3, 1, 1],
                ]
            ],
        )
        mods = list(map(int, mods))
        mods.sort()
        mods = list(map(str, mods))
        for mod in mods:
            tot_scsi_init_mod, tot_scsi_targets_mod, tot_scsi_itl_mod = 0, 0, 0
            tot_nvme_init_mod, tot_nvme_targets_mod, tot_nvme_itl_mod = 0, 0, 0
            total_itls, total_initiators, total_targets = 0, 0, 0
            # Find total
            total_scsi_itls += active_itls[mod]
            total_nvme_itls += active_itns[mod]
            total_init_scsi += s_initiator[mod]
            total_init_nvme += n_initiator[mod]
            total_targ_scsi += s_target[mod]
            total_targ_nvme += n_target[mod]
            total_itls = active_itls[mod] + active_itns[mod]
            total_initiators = s_initiator[mod] + n_initiator[mod]
            total_targets = s_target[mod] + n_target[mod]

            column_str = "{0}, {1}, {2}, {3}, {4}, {5}, {6}, {7}, {8}, {9}".format(
                mod,
                active_itls[mod],
                active_itns[mod],
                total_itls,
                s_initiator[mod],
                n_initiator[mod],
                total_initiators,
                s_target[mod],
                n_target[mod],
                total_targets,
            )
            # print(column_str)
            column_values = column_str.split(",")
            t.add_row(column_values)

        total_it = total_scsi_itls + total_nvme_itls
        total_targ = total_targ_scsi + total_targ_nvme
        total_init = total_init_scsi + total_init_nvme
        column_str = "Total, {0}, {1}, {2}, {3}, {4}, {5}, {6}, {7}, {8}".format(
            total_scsi_itls,
            total_nvme_itls,
            total_it,
            total_init_scsi,
            total_init_nvme,
            total_init,
            total_targ_scsi,
            total_targ_nvme,
            total_targ,
        )
        column_values = column_str.split(",")
        t.add_row(column_values)

        print(t)
        if args.outfile or args.appendfile:
            data = t.get_string()
            try:
                fh.write(data + "\n")
            except OSError as err:
                print("Not able to write to a file, No space left on device")
                sys.exit(0)

        if args.detail:
            flag_amc = False
            detModules = []
            for mod in mods:
                if mod in amc_mods:
                    flag_amc = True
                    detModules.append(get_module_name(mod))
            if flag_amc:
                detModules = set(detModules)
                print("\nDetailed output for {} modules".format(",".join(detModules)))
                if args.outfile or args.appendfile:
                    try:
                        fh.write(
                            "\nDetailed output for {} modules\n".format(
                                ",".join(detModules)
                            )
                        )
                    except OSError as err:
                        print("Not able to write to a file, No space left on device")
                        sys.exit(0)
            else:
                print("\nNo modules having AMC with active IT(L/N)s found")
                if args.outfile or args.appendfile:
                    try:
                        fh.write("\nNo modules having AMC with active IT(L/N)s found\n")
                    except OSError as err:
                        print("Not able to write to a file, No space left on device")
                        sys.exit(0)
                sys.exit(1)
        else:
            sys.exit(1)
        for mod in mods:
            total_scsi_itls, total_nvme_itls, total_init_scsi, total_init_nvme = (
                0,
                0,
                0,
                0,
            )
            total_targ_scsi, total_targ_nvme, total_init, total_targ, total_it = (
                0,
                0,
                0,
                0,
                0,
            )
            if mod in amc_mods:
                print("Module : {}".format(mod))
                t = PrettyTable(
                    [
                        "  ",
                        " SCSI ",
                        " NVMe ",
                        " Total ",
                        "SCSI",
                        "NVMe",
                        "Total",
                        " SCSI",
                        " NVMe",
                        " Total",
                    ],
                    headers_misc=[
                        [
                            "above",
                            ["Ports", "ITL/N Count", " Initiators", "Targets"],
                            [1, 3, 3, 3, 1, 1],
                        ]
                    ],
                )
                port_groups[mod].sort()
                for port_group in port_groups[mod]:
                    total_itls = (
                        active_itls_dict[mod][port_group]
                        + active_itns_dict[mod][port_group]
                    )
                    total_initiators = (
                        initiator_scsi_dict[mod][port_group]
                        + initiator_nvme_dict[mod][port_group]
                    )
                    total_targets = (
                        target_scsi_dict[mod][port_group]
                        + target_nvme_dict[mod][port_group]
                    )

                    # Find total
                    total_scsi_itls += active_itls_dict[mod][port_group]
                    total_nvme_itls += active_itns_dict[mod][port_group]
                    total_init_scsi += initiator_scsi_dict[mod][port_group]
                    total_init_nvme += initiator_nvme_dict[mod][port_group]
                    total_targ_scsi += target_scsi_dict[mod][port_group]
                    total_targ_nvme += target_nvme_dict[mod][port_group]
                    portStr = ",".join(
                        [
                            "fc" + mod + "/" + str(x)
                            for x in amc_port_groups[mod][port_group]
                        ]
                    )
                    column_str = "{0}-{1}-{2}-{3}-{4}-{5}-{6}-{7}-{8}-{9}".format(
                        portStr,
                        active_itls_dict[mod][port_group],
                        active_itns_dict[mod][port_group],
                        total_itls,
                        initiator_scsi_dict[mod][port_group],
                        initiator_nvme_dict[mod][port_group],
                        total_initiators,
                        target_scsi_dict[mod][port_group],
                        target_nvme_dict[mod][port_group],
                        total_targets,
                    )
                    column_values = column_str.split("-")
                    t.add_row(column_values)

                total_it = total_scsi_itls + total_nvme_itls
                total_targ = total_targ_scsi + total_targ_nvme
                total_init = total_init_scsi + total_init_nvme
                column_str = "Total,{0},{1},{2},{3},{4},{5},{6},{7},{8}".format(
                    total_scsi_itls,
                    total_nvme_itls,
                    total_it,
                    total_init_scsi,
                    total_init_nvme,
                    total_init,
                    total_targ_scsi,
                    total_targ_nvme,
                    total_targ,
                )
                column_values = column_str.split(",")
                t.add_row(column_values)

                print(t)
                if args.outfile or args.appendfile:
                    data = t.get_string()
                    try:
                        fh.write("Module : {}\n".format(mod))
                        fh.write(data + "\n")
                    except OSError as err:
                        print("Not able to write to a file, No space left on device")
                        sys.exit(0)


def getHistogramSessions(sessionId=None):
    sessions = 0
    sessionFiles = []
    if sessionId:
        cmd = "show processes  |i nxpython | i " + sessionId
    else:
        cmd = "show processes  |i nxpython"
    status, out = cmd_exc(cmd)
    if not status:
        print("Unable to get histogram session data, please try again")
        sys.exit(0)

    for line in out.splitlines():
        process_id = line.split()[0].strip()
        for files in os.listdir("/nxos/tmp"):
            filename = "histogram_" + process_id
            m = re.search(filename, files)
            if m:
                sessionFiles.append("/nxos/tmp/" + files)
    return sessionFiles


def stopHistogramSessions(processes):
    filenames = getHistogramSessions()
    proc_list = []
    invalidProcs = []
    file_dict = {}
    for filename in filenames:
        fields = filename.split("_")
        if "ALL" in processes:
            proc_list.append(fields[1])
            file_dict[fields[1]] = filename
        else:
            for process_id in processes:
                if process_id == fields[1]:
                    proc_list.append(fields[1])
                    file_dict[process_id] = filename

    if "ALL" not in processes:
        invalidProcs = list(set(processes).difference(set(file_dict.keys())))

    if invalidProcs:
        print("Invalid session IDs: {}".format(",".join(invalidProcs)))
    for process_id in proc_list:
        try:
            print("Stopping session id: {}".format(process_id))
            os.kill(int(process_id), signal.SIGKILL)
            os.remove(file_dict[process_id])
        except Exception as e:
            print("Unable to kill process id: {} Error: {} ".format(process_id, e))


def displayHistogramSessions(filenames=None, sessionId=None):
    if filenames:
        t = PrettyTable(["Session ID", "Arguments"])
        t.align["Arguments"] = "l"
        t.align["Session ID"] = "r"
    elif sessionId:
        filenames = getHistogramSessions(sessionId)
        if not filenames:
            print("Provided session id is not a histogram monitor session ID")
            sys.exit(1)

    for filename in filenames:
        metricList = []
        try:
            with open(filename) as hf:
                f_str = hf.read()
                if "IOPS" in f_str:
                    metricList.append("IOPS")
                if "ECT" in f_str:
                    metricList.append("ECT")
                if "DAL" in f_str:
                    metricList.append("DAL")
                if "FAILURE" in f_str:
                    metricList.append("ERRORS")
        except Exception as e:
            syslog.syslog(
                2,
                "ShowAnalytics: Unable to write to {0} exception {1}".format(
                    filename, e
                ),
            )
            sys.exit(1)

        filename = os.path.basename(filename)
        filename = filename.split(".txt")[0]
        fields = filename.split("_")
        process_id = fields[1]
        metric = ",".join(metricList)

        if "init-itl" in filename:
            dur = fields[6][:-4]
            arguments = "--initiator-itl --initiator {} --target {} --lun {} --interval {} --metric {}".format(
                fields[3], fields[4], fields[5], dur, metric
            )
        elif "target-itl" in filename:
            dur = fields[6][:-4]
            arguments = "--target-itl --initiator {} --target {} --lun {} --interval {} --metric {}".format(
                fields[3], fields[4], fields[5], dur, metric
            )
        elif "init-itn" in filename:
            dur = fields[6][:-4]
            arguments = "--initiator-itn --initiator {} --target {} --namespace {} --interval {} --metric {}".format(
                fields[3], fields[4], fields[5], dur, metric
            )
        elif "target-itn" in filename:
            dur = fields[6][:-4]
            arguments = "--target-itn --initiator {} --target {} --namespace {} --interval {} --metric {}".format(
                fields[3], fields[4], fields[5], dur, metric
            )
        elif "init-it" in filename:
            dur = fields[5][:-4]
            arguments = "--initiator-it --initiator {} --target {} --interval {} --metric {}".format(
                fields[3], fields[4], dur, metric
            )
        elif "target-it" in filename:
            dur = fields[5][:-4]
            arguments = "--target-it --initiator {} --target {}  --interval {} --metric {}".format(
                fields[3], fields[4], dur, metric
            )
        elif "init" in filename:
            dur = fields[4][:-4]
            arguments = "--initiator {} --interval {} --metric {}".format(
                fields[3], dur, metric
            )
        elif "target" in filename:
            dur = fields[4][:-4]
            arguments = "--target {} --interval {} --metric {}".format(
                fields[3], dur, metric
            )
        if "nvme" in filename:
            arguments = arguments + " --nvme"
        if sessionId:
            hfile = "/nxos/tmp/" + filename + ".txt"
            metricList = []
            metricList.append("TIME")
            if "IOPS" in metric:
                metricList.extend(["IOPSR", "IOPSW"])
            if "ECT" in metric:
                metricList.extend(["ECTR", "ECTW"])
            if "DAL" in metric:
                metricList.extend(["DALR", "DALW"])
            if "ERRORS" in metric:
                metricList.extend(["FAILURESR", "FAILURESW", "ABORTSR", "ABORTSW"])

            displayHistogramData(hfile, dur, metricList)
            sys.exit(1)
        else:
            t.add_row([process_id, arguments])
    print(t)
    if args.outfile or args.appendfile:
        data = t.get_string()
        try:
            fh.write(data + "\n")
        except OSError as err:
            print("Not able to write to a file, No space left on device")
            sys.exit(0)
        try:
            fh.close()
        except OSError as err:
            print("Not able to write to a file, No space left on device")
            sys.exit(0)


def displayHistogramData(filename, interval, metricList):
    try:
        with open(filename, "r+") as fhfile:
            prev_data = fhfile.read()
    except Exception as e:
        syslog.syslog(
            2, "ShowAnalytics: Unable to read to {0} exception {1}".format(filename, e)
        )
        sys.exit(1)

    metricDict = {
        "IOPSR": "IOPS Read",
        "IOPSW": "IOPS Write",
        "ECTR": "ECT Read",
        "ECTW": "ECT Write",
        "DALR": "DAL Read",
        "DALW": "DAL Write",
        "FAILURESR": "FAILURES Read",
        "FAILURESW": "FAILURES Write",
        "ABORTSR": "ABORTS Read",
        "ABORTSW": "ABORTS Write",
    }

    prev_data = prev_data.strip()
    prev_data = prev_data.split("\n")
    metricData = {}
    for line in prev_data:
        for metric in metricList:
            if metric in line:
                if metric == "TIME":
                    sample_time = list(filter(None, line.split(":")[1].split(",")[:12]))
                else:
                    metricData[metric] = list(
                        filter(None, line.split(":")[1].split(",")[:12])
                    )

    sample_time = list(map(int, sample_time))
    date_list = list(
        map(
            lambda x: datetime.datetime.fromtimestamp(x).strftime("%d-%m-%Y"),
            sample_time,
        )
    )
    time_list = list(
        map(
            lambda x: datetime.datetime.fromtimestamp(x).strftime("%H:%M:%S"),
            sample_time,
        )
    )

    date_list = [""] + date_list
    time_list = ["Metric"] + time_list

    t = PrettyTable(
        time_list,
        headers_misc=[["above", date_list, [1 for x in range(len(date_list))]]],
    )

    t.align["Metric"] = "l"
    for metric in metricData.keys():
        if "ECT" in metric or "DAL" in metric:
            metricData[metric] = list(map(time_conv, metricData[metric]))

        t.add_row([metricDict[metric]] + metricData[metric])
    print(t)
    if args.outfile or args.appendfile:
        data = t.get_string()
        try:
            fh.write(data + "\n")
        except OSError as err:
            print("Not able to write to a file, No space left on device")
            sys.exit(0)
        try:
            fh.close()
        except OSError as err:
            print("Not able to write to a file, No space left on device")
            sys.exit(0)


def displayHistogram(args, json_out, ver=None):
    counter = 1
    hargs = ""

    if args.interval == None:
        args.interval = "5"
    if args.metric == None:
        args.metric = "ALL"

    metricList = []
    if args.metric is None or "ALL" in args.metric:
        metricList = [
            "IOPSR",
            "IOPSW",
            "ECTR",
            "ECTW",
            "DALR",
            "DALW",
            "FAILURESR",
            "FAILURESW",
            "ABORTSR",
            "ABORTSW",
        ]
    else:
        if "IOPS" in args.metric:
            metricList.extend(["IOPSR", "IOPSW"])
        if "ECT" in args.metric:
            metricList.extend(["ECTR", "ECTW"])
        if "DAL" in args.metric:
            metricList.extend(["DALR", "DALW"])
        if "ERRORS" in args.metric:
            metricList.extend(["FAILURESR", "FAILURESW", "ABORTSR", "ABORTSW"])
    metricList.append("TIME")

    if args.initiator:
        hargs = hargs + "_" + args.initiator
    if args.target:
        hargs = hargs + "_" + args.target
    if args.lun:
        hargs = hargs + "_" + args.lun
    if args.namespace:
        hargs = hargs + "_" + args.namespace
    flowname = ""
    if args.initiator_itl:
        flowname = "_init-itl"
    elif args.target_itl:
        flowname = "_target-itl"
    elif args.initiator_itn:
        flowname = "_init-itn"
    elif args.target_itn:
        flowname = "_target-itn"
    elif args.initiator_it:
        if args.nvme:
            flowname = "_init-it-nvme"
        else:
            flowname = "_init-it"
    elif args.target_it:
        if args.nvme:
            flowname = "_target-it-nvme"
        else:
            flowname = "_target-it"
    elif args.initiator:
        if args.nvme:
            flowname = "_init-nvme"
        else:
            flowname = "_init"
    elif args.target:
        if args.nvme:
            flowname = "_target-nvme"
        else:
            flowname = "_target"

    hfile = r"histogram_(\d+)" + flowname + hargs + r"_(\d+)mins\.txt"
    for files in os.listdir("/nxos/tmp"):
        m = re.search(hfile, files)
        if m:
            process_id = m.group(1)
            dur = m.group(2)
            cmd = r"show processes  |i nxpython | egrep '^\s*{}'".format(process_id)
            status, out = cmd_exc(cmd)
            if not status:
                print("Unable to get histogram session data, please try again")
                sys.exit(0)
            if out:
                filename = "/nxos/tmp/" + m.group(0)
                metricFlag = True
                try:
                    with open(filename) as hf:
                        f_str = hf.read()
                        for metric in metricList:
                            if metric not in f_str:
                                metricFlag = False
                                break
                except Exception as e:
                    syslog.syslog(
                        2,
                        "ShowAnalytics: Unable to write to {0} exception {1}".format(
                            hfile, e
                        ),
                    )
                    sys.exit(1)
                if dur != args.interval or metricFlag != True:
                    print(
                        "Histogram monitor session already running for given args with different interval or different metric"
                    )
                    print("Session ID:{}".format(process_id))
                    conf_response = str(
                        input("Do you want to stop it and start new [Yes|No]? [n]")
                    )
                    if conf_response not in ["Y", "y", "Yes", "yes", "YES"]:
                        cdate = formatdate(localtime=True)
                        print("\nData collected at : {}\n".format(cdate))
                        displayHistogramData(filename, dur, metricList)
                        sys.exit(0)
                    else:
                        hfile = (
                            "/nxos/tmp/histogram_"
                            + str(process_id)
                            + flowname
                            + hargs
                            + "_"
                            + dur
                            + "mins.txt"
                        )
                        print("Stopping process id {}".format(int(process_id)))
                        os.kill(int(process_id), signal.SIGKILL)
                        os.remove(hfile)
                        break
                else:
                    cdate = formatdate(localtime=True)
                    print("\nData collected at : {}\n".format(cdate))
                    displayHistogramData(filename, dur, metricList)
                    sys.exit(0)

            else:
                hfile = (
                    "/nxos/tmp/histogram_"
                    + str(process_id)
                    + flowname
                    + hargs
                    + "_"
                    + dur
                    + "mins.txt"
                )
                os.remove(hfile)
                break

    sessionFiles = getHistogramSessions()
    if len(sessionFiles) >= 3:
        print(
            "Maximum 3 monitor sessions can be active at a time. You can stop one of these and retry"
        )
        displayHistogramSessions(sessionFiles)
        sys.exit(0)

    interval = int(args.interval)
    sleeptime = interval * 60

    print("Starting histogram monitor session")
    pid = os.fork()
    if pid == 0:
        # Child  - Starts histogram session in background
        init_flag = True
        os.setsid()  # This creates a new session
        process_id = os.getpid()
        print("Session ID: {}".format(process_id))
        hargs = ""
        if args.initiator:
            hargs = hargs + "_" + args.initiator
        if args.target:
            hargs = hargs + "_" + args.target
        if args.lun:
            hargs = hargs + "_" + args.lun
        if args.namespace:
            hargs = hargs + "_" + args.namespace
        if args.interval:
            hargs = hargs + "_" + args.interval + "mins"

        flowname = ""
        if args.initiator_itl:
            flowname = "_init-itl"
        elif args.target_itl:
            flowname = "_target-itl"
        elif args.initiator_itn:
            flowname = "_init-itn"
        elif args.target_itn:
            flowname = "_target-itn"
        elif args.initiator_it:
            if args.nvme:
                flowname = "_init-it-nvme"
            else:
                flowname = "_init-it"
        elif args.target_it:
            if args.nvme:
                flowname = "_target-it-nvme"
            else:
                flowname = "_target-it"
        elif args.initiator:
            if args.nvme:
                flowname = "_init-nvme"
            else:
                flowname = "_init"
        elif args.target:
            if args.nvme:
                flowname = "_target-nvme"
            else:
                flowname = "_target"

        hfile = "/nxos/tmp/histogram_" + str(process_id) + flowname + hargs + ".txt"

        if args.interval:
            interval = int(args.interval)
            sleeptime = interval * 60
        else:
            sleeptime = 300
        (
            init_totalread,
            init_totalwrite,
            init_readCount,
            init_writeCount,
            init_readIoIntTime,
            init_writeIoIntTime,
            init_abortsR,
            init_abortsW,
            init_failR,
            init_failW,
        ) = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

        for key, value in json_out["values"]["1"].items():
            if key == "sampling_end_time":
                init_end_time = value
            if str(key) == "read_io_rate" and value != 0:
                init_iopsR = int(value)
                continue
            if str(key) == "write_io_rate" and value != 0:
                init_iopsW = int(value)
                continue
            if str(key) == "total_read_io_time" and value != 0:
                init_totalread = int(value)
                continue
            if str(key) == "total_write_io_time" and value != 0:
                init_totalwrite = int(value)
                continue
            if (
                str(key) == "total_time_metric_based_read_io_count"
                and value != 0
                and ver != "8.3(1)"
            ):
                init_readCount = int(value)
                continue
            if (
                str(key) == "total_time_metric_based_write_io_count"
                and value != 0
                and ver != "8.3(1)"
            ):
                init_writeCount = int(value)
                continue
            if str(key) == "total_read_io_count" and value != 0 and ver == "8.3(1)":
                init_readCount = int(value)
                continue
            if str(key) == "total_write_io_count" and value != 0 and ver == "8.3(1)":
                init_writeCount = int(value)
                continue
            if str(key) == "total_read_io_initiation_time" and value != 0:
                init_readIoIntTime = int(value)
                continue
            if str(key) == "total_write_io_initiation_time" and value != 0:
                init_writeIoIntTime = int(value)
                continue
            if str(key) == "total_read_io_bytes" and value != 0:
                init_readIoB = int(value)
                continue
            if str(key) == "total_write_io_bytes" and value != 0:
                init_writeIoB = int(value)
                continue
            if str(key) == "read_io_aborts" and value != 0:
                init_abortsR = int(value)
                continue
            if str(key) == "write_io_aborts" and value != 0:
                init_abortsW = int(value)
                continue
            if str(key) == "read_io_failures" and value != 0:
                init_failR = int(value)
                continue
            if str(key) == "write_io_failures" and value != 0:
                init_failW = int(value)
                continue
        init_falg = 1
        init_ectR, init_ectW, init_dalR, init_dalW = 0, 0, 0, 0
        if init_readCount != 0:
            init_ectR = init_totalread // init_readCount
            init_dalR = init_readIoIntTime // init_readCount
        if init_writeCount != 0:
            init_ectW = init_totalwrite // init_writeCount
            init_dalW = init_writeIoIntTime // init_writeCount

        metricData = {}
        metricData["TIME"] = str(init_end_time)
        metricData["IOPSR"] = str(init_iopsR)
        metricData["IOPSW"] = str(init_iopsW)
        metricData["ECTR"] = str(init_ectR)
        metricData["ECTW"] = str(init_ectW)
        metricData["DALR"] = str(init_dalR)
        metricData["DALW"] = str(init_dalW)
        metricData["FAILURESR"] = str(init_failR)
        metricData["FAILURESW"] = str(init_failW)
        metricData["ABORTSR"] = str(init_abortsR)
        metricData["ABORTSW"] = str(init_abortsW)
        try:
            with open(hfile, "w") as fhfile:
                for metric in metricList:
                    lstr = metric + ":" + metricData[metric] + "\n"
                    fhfile.write(lstr)
        except Exception as e:
            syslog.syslog(
                2,
                "ShowAnalytics: Unable to write to {0} exception {1}".format(hfile, e),
            )
            sys.exit(1)

        displayHistogramData(hfile, args.interval, metricList)
        print("Histogram data will get updated every {} mins".format(sleeptime // 60))
        (
            totalread,
            totalwrite,
            readCount,
            writeCount,
            readIoIntTime,
            writeIoIntTime,
            abortsR,
            abortsW,
            failR,
            failW,
        ) = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        while 1:
            time.sleep(sleeptime)
            if init_falg:
                (
                    prev_totalread,
                    prev_totalwrite,
                    prev_readcount,
                    prev_writecount,
                    prev_readIoIntTime,
                    prev_writeIoIntTime,
                    prev_abortsR,
                    prev_abortsW,
                    prev_failR,
                    prev_failW,
                ) = (
                    init_totalread,
                    init_totalwrite,
                    init_readCount,
                    init_writeCount,
                    init_readIoIntTime,
                    init_writeIoIntTime,
                    init_abortsR,
                    init_abortsW,
                    init_failR,
                    init_failW,
                )
            else:
                (
                    prev_totalread,
                    prev_totalwrite,
                    prev_readcount,
                    prev_writecount,
                    prev_readIoIntTime,
                    prev_writeIoIntTime,
                    prev_abortsR,
                    prev_abortsW,
                    prev_failR,
                    prev_failW,
                ) = (
                    totalread,
                    totalwrite,
                    readCount,
                    writeCount,
                    readIoIntTime,
                    writeIoIntTime,
                    abortsR,
                    abortsW,
                    failR,
                    failW,
                )

            json_out = getData(args)
            if not json_out:
                syslog.syslog(
                    2,
                    "ShowAnalytics: Unable to get data from analytics query hence exiting histogram session {}".format(
                        hfile
                    ),
                )
                os.remove(hfile)
                os.kill(int(process_id), signal.SIGKILL)
                sys.exit(0)
            init_falg = 0
            vmid = ""
            iopsR, ectR, dalR = 0, 0, 0
            iopsW, ectW, dalW = 0, 0, 0
            for key, value in json_out["values"]["1"].items():
                if key == "sampling_end_time":
                    end_time = value
                if str(key) == "read_io_rate" and value != 0:
                    iopsR = int(value)
                    continue
                if str(key) == "write_io_rate" and value != 0:
                    iopsW = int(value)
                    continue
                if str(key) == "read_io_bandwidth" and value != 0:
                    thputR = value
                    continue
                if str(key) == "write_io_bandwidth" and value != 0:
                    thputW = value
                    continue
                if str(key) == "total_read_io_time" and value != 0:
                    totalread = int(value)
                    continue
                if str(key) == "total_write_io_time" and value != 0:
                    totalwrite = int(value)
                    continue
                if (
                    str(key) == "total_time_metric_based_read_io_count"
                    and value != 0
                    and ver != "8.3(1)"
                ):
                    readCount = int(value)
                    continue
                if (
                    str(key) == "total_time_metric_based_write_io_count"
                    and value != 0
                    and ver != "8.3(1)"
                ):
                    writeCount = int(value)
                    continue
                if str(key) == "total_read_io_count" and value != 0 and ver == "8.3(1)":
                    readCount = int(value)
                    continue
                if (
                    str(key) == "total_write_io_count"
                    and value != 0
                    and ver == "8.3(1)"
                ):
                    writeCount = int(value)
                    continue
                if str(key) == "peak_read_io_rate" and value != 0:
                    peak_read_iops = int(value)
                    continue
                if str(key) == "peak_write_io_rate" and value != 0:
                    peak_write_iops = int(value)
                    continue
                if str(key) == "peak_read_io_bandwidth" and value != 0:
                    peak_read_thput = value
                    continue
                if str(key) == "peak_write_io_bandwidth" and value != 0:
                    peak_write_thput = value
                    continue
                if str(key) == "read_io_completion_time_min" and value != 0:
                    read_ect_min = value
                    continue
                if str(key) == "total_read_io_initiation_time" and value != 0:
                    readIoIntTime = int(value)
                    continue
                if str(key) == "total_write_io_initiation_time" and value != 0:
                    writeIoIntTime = int(value)
                    continue
                if str(key) == "total_read_io_bytes" and value != 0:
                    readIoB = int(value)
                    continue
                if str(key) == "total_write_io_bytes" and value != 0:
                    writeIoB = int(value)
                    continue
                if str(key) == "read_io_aborts" and value != 0:
                    abortsR = int(value)
                    continue
                if str(key) == "write_io_aborts" and value != 0:
                    abortsW = int(value)
                    continue
                if str(key) == "read_io_failures" and value != 0:
                    failR = int(value)
                    continue
                if str(key) == "write_io_failures" and value != 0:
                    failW = int(value)
                    continue

            diff_readCount = int(readCount) - int(prev_readcount)
            diff_writeCount = int(writeCount) - int(prev_writecount)
            diff_readIoIntTime = int(readIoIntTime) - int(prev_readIoIntTime)
            diff_writeIoIntTime = int(writeIoIntTime) - int(prev_writeIoIntTime)
            diff_abortsR = abs(abortsR - prev_abortsR)
            diff_abortsW = abs(abortsW - prev_abortsW)
            diff_failR = abs(failR - prev_failR)
            diff_failW = abs(failW - prev_failW)
            if diff_readCount != 0:
                ectR = abs(int(totalread) - int(prev_totalread)) // diff_readCount
            if diff_writeCount != 0:
                ectW = abs(int(totalwrite) - int(prev_totalwrite)) // diff_writeCount
            if diff_readCount != 0:
                dalR = diff_readIoIntTime // diff_readCount
            if diff_writeCount != 0:
                dalW = diff_writeIoIntTime // diff_writeCount
            try:
                with open(hfile, "r+") as fhfile:
                    prev_data = fhfile.read()
            except Exception as e:
                syslog.syslog(
                    2,
                    "ShowAnalytics: Unable to write to {0} exception {1}".format(
                        hfile, e
                    ),
                )
                sys.exit(1)

            prev_data = prev_data.strip()
            prev_data = prev_data.split("\n")
            metricData = {}
            for line in prev_data:
                if "TIME" in line:
                    metricData["TIME"] = [str(end_time)] + line.split(":")[1].split(
                        ","
                    )[:11]
                if "IOPSR" in line:
                    metricData["IOPSR"] = [str(iopsR)] + line.split(":")[1].split(",")[
                        :11
                    ]
                if "IOPSW" in line:
                    metricData["IOPSW"] = [str(iopsW)] + line.split(":")[1].split(",")[
                        :11
                    ]
                if "ECTR" in line:
                    metricData["ECTR"] = [str(ectR)] + line.split(":")[1].split(",")[
                        :11
                    ]
                if "ECTW" in line:
                    metricData["ECTW"] = [str(ectW)] + line.split(":")[1].split(",")[
                        :11
                    ]
                if "DALR" in line:
                    metricData["DALR"] = [str(dalR)] + line.split(":")[1].split(",")[
                        :11
                    ]
                if "DALW" in line:
                    metricData["DALW"] = [str(dalW)] + line.split(":")[1].split(",")[
                        :11
                    ]
                if "FAILURESR" in line:
                    metricData["FAILURESR"] = [str(diff_failR)] + line.split(":")[
                        1
                    ].split(",")[:11]
                if "FAILURESW" in line:
                    metricData["FAILURESW"] = [str(diff_failW)] + line.split(":")[
                        1
                    ].split(",")[:11]
                if "ABORTSR" in line:
                    metricData["ABORTSR"] = [str(diff_abortsR)] + line.split(":")[
                        1
                    ].split(",")[:11]
                if "ABORTSW" in line:
                    metricData["ABORTSW"] = [str(diff_abortsW)] + line.split(":")[
                        1
                    ].split(",")[:11]
            os.remove(hfile)
            try:
                with open(hfile, "w") as fhfile:
                    for metric in metricList:
                        replaceExp = metric + ":" + ",".join(metricData[metric]) + "\n"
                        fhfile.write(replaceExp)
            except Exception as e:
                syslog.syslog(
                    2,
                    "ShowAnalytics: Unable to write to {0} exception {1}".format(
                        hfile, e
                    ),
                )
                sys.exit(1)

    else:
        # Parent
        exit()


def getSwVersion():
    """
    **********************************************************************************
    * Function: getSwVersion
    *
    * Action: Get current Software version
    * Returns: String as software version of the switch
    **********************************************************************************
    """
    try:
        out = cli.cli("show version  | i version | i syst").strip()
        for valu in out.split(" "):
            vmatch = False
            for str in ["build", "gdb", "system", "version", r"\[", r"\]"]:
                if str in valu.strip():
                    vmatch = True
            if not vmatch and valu.strip() != "":
                return valu.strip()
        return None
    except Exception as e:
        return None


class showAnalyticsQuery(object):
    def __init__(self, output):
        output = output.split("\n")

        pattern = "Total queries:([0-9]+)"

        self.totalQueries = 0
        self.requiredLines = []
        self.queryname_string_and_type = {}
        self.stopIndex = 3
        self.qdetails = {}

        for line in output:
            line = line.strip()
            m = re.match(pattern, line)
            if m:
                self.totalQueries = m.group(1).strip()
            if "Query Name" in line:
                qname = line.split(":")[1]
                self.qdetails[qname] = {}
                self.qdetails[qname]["options"] = ""
            if "Query String" in line:
                self.qdetails[qname]["string"] = line.split(":")[1]
            if "Query Type" in line:
                self.qdetails[qname]["type"] = line.split(":")[1]
            if "Query Options" in line:
                self.qdetails[qname]["options"] = line.split(":")[1]

    def get_total_queries(self):
        return int(self.totalQueries)

    def get_query_details(self):
        return self.qdetails


def getQueryResult(qname):
    try:
        json_str = cli.cli("show analytics query name " + qname + " result")
    except cli.cli_syntax_error:
        pass

    global error
    global error_flag

    try:
        json_out = json.loads(json_str)
    except ValueError as e:
        error["getData_str"] = json_str
        error_flag = True
        error["line_count"] = len(json_str.split("\n")) + 1
        json_out = None
    except MemoryError:
        error["getData_str"] = "Querry Output Too Huge to be processed"
        json_out = None
        error_flag = True
        error["line_count"] = 1
    # print ("Jsone {0}".format(json_out))
    return json_out


def replaceline(fileh, pattern, subst):
    # Read contents from file as a single string
    with open(fileh, "r") as file_handle:
        file_string = file_handle.read()

    file_string = re.sub(pattern, subst, file_string)

    # Write contents to file.
    with open(fileh, "w") as file_handle:
        file_handle.write(file_string)


def getData(args, misc=None, ver=None):
    """
    **********************************************************************************
    *  Function: getData
    *
    *  Input: It takes 3 inputs:
    *           - args is global Object of Argparse Class
    *           - misc which is default to none is to accomodate
    *              some operation as described below
    *           - ver is software version number
    *  misc
    *  0 : default
    *  1 : run target querry this time for outstanding_io,top
    *  i_itl : to run query on fc-scsi.scsi_inititator_itl_flow for systemload_active
    *  t_itl : to run query on fc-scsi.scsi_target_itl_flow for systemload_active
    *  i_itn : to run query on fc-nvme.nvme_inititator_itn_flow for systemload_active
    *  t_itn : to run query on fc-nvme.nvme_target_itn_flow for systemload_active
    *  s_init: to run query on fc-scsi.scsi_inititator for systemload_active
    *  s_target: to run query on fc-scsi.scsi_target for systemload_active
    *  n_init: to run query on fc-nvme.nvme_inititator for systemload_active
    *  n_target: to run query on fc-nvme.nvme_target for systemload_active
    *
    *  Action: Forms a query based on args and misc , run the query on
    *           the switch and get json response and convert it into
    *           dict and return
    *
    *  Returns: json_out which is json format of data
    **********************************************************************************
    """
    vmid_enabled = getVmidFeature()
    vmid_str = "vmid ," if vmid_enabled else ""
    trib, twib, tric, twic = (
        "total_time_metric_based_read_io_bytes",
        "total_time_metric_based_write_io_bytes",
        "total_time_metric_based_read_io_count",
        "total_time_metric_based_write_io_count",
    )
    if ver == "8.3(1)":
        trib, twib, tric, twic = (
            "total_read_io_bytes",
            "total_write_io_bytes",
            "total_read_io_count",
            "total_write_io_count",
        )
    ver1 = int("".join([i for i in sw_ver if i.isdigit()])[:3])
    if ver1 >= 922:
        delayMetric_str = "total_write_io_host_delay_time, total_write_io_array_delay_time, total_write_io_sequences_count,"
        delayMetricMinMax_str = "total_write_io_host_delay_time, total_write_io_array_delay_time, write_io_host_delay_time_max, write_io_host_delay_time_min, write_io_array_delay_time_max, multisequence_exchange_write_io_sequences_max, multisequence_exchange_write_io_sequences_min, total_write_io_sequences_count,"
        ioInterGap_str = ""
    else:
        delayMetric_str = ""
        delayMetricMinMax_str = ""
        ioInterGap_str = "read_io_inter_gap_time_min, read_io_inter_gap_time_max, \
                      write_io_inter_gap_time_min, write_io_inter_gap_time_max,"

    table_name = ""
    global interface_list

    if args.evaluate_npuload:
        if misc is None:
            return None
        else:
            q_type = misc
            if q_type == "nvme":
                query = "select port, nvme_target_count, nvme_initiator_count,\
                    nvme_initiator_itn_flow_count,  \
                    nvme_target_itn_flow_count, read_io_rate, \
                    write_io_rate from fc-nvme.port"
            else:
                query = "select port, scsi_target_count, scsi_initiator_count,\
                    scsi_initiator_itl_flow_count, \
                    scsi_target_itl_flow_count, read_io_rate, \
                    write_io_rate from fc-scsi.port"

    lun_field = "namespace_id," if args.nvme else "lun,"
    protocol_str = "fc-nvme" if args.nvme else "fc-scsi"
    table_protocol_str = "nvme" if args.nvme else "scsi"
    ln_str = "n" if args.nvme else "l"

    if (
        args.initiator_itl
        or args.target_itl
        or args.initiator_it
        or args.target_it
        or args.initiator_itn
        or args.target_itn
    ):
        lun_field = "" if (args.initiator_it or args.target_it) else lun_field
        if args.initiator_itl:
            app_id_str = "app_id ,"
            table_name = "scsi_initiator_itl_flow"
        elif args.target_itl:
            app_id_str = "app_id ,"
            table_name = "scsi_target_itl_flow"
        elif args.initiator_itn:
            app_id_str = "app_id ,"
            table_name = "nvme_initiator_itn_flow"
        elif args.target_itn:
            app_id_str = "app_id ,"
            table_name = "nvme_target_itn_flow"
        elif args.initiator_it:
            app_id_str = ""
            table_name = "{0}_initiator_it_flow".format(table_protocol_str)
        elif args.target_it:
            app_id_str = ""
            table_name = "{0}_target_it_flow".format(table_protocol_str)
        # table_name = 'scsi_initiator_itl_flow'
        # CSCvn26029 also added 4 line below
        if args.target and args.initiator and (args.lun or args.namespace):
            query = "select port, vsan, {app_id} initiator_id, target_id, {vmid} \
                {lun} read_io_rate, write_io_rate, read_io_bandwidth, \
                write_io_bandwidth, read_io_size_min, read_io_size_max, \
                {0}, {2}, write_io_size_min, write_io_size_max, {1}, {3}, \
                read_io_initiation_time_min, read_io_initiation_time_max, \
                total_read_io_initiation_time, write_io_initiation_time_min, \
                write_io_initiation_time_max, total_write_io_initiation_time, \
                read_io_completion_time_min, read_io_completion_time_max, \
                total_read_io_time, write_io_completion_time_min, \
                write_io_completion_time_max, total_write_io_time, \
                total_read_io_inter_gap_time, total_write_io_inter_gap_time, {ioInterGap}\
                read_io_aborts, write_io_aborts, read_io_failures, \
                write_io_failures, peak_read_io_rate, peak_write_io_rate,{delayMetric} \
                peak_read_io_bandwidth, peak_write_io_bandwidth from \
                    {proto}.{fc_table}".format(
                trib,
                twib,
                tric,
                twic,
                lun=lun_field,
                proto=protocol_str,
                fc_table=table_name,
                vmid=vmid_str,
                app_id=app_id_str,
                delayMetric=delayMetricMinMax_str,
                ioInterGap=ioInterGap_str,
            )
        else:
            if args.minmax:
                query = "select port,vsan, {app_id} initiator_id, {vmid}\
                    target_id,{lun}peak_read_io_rate,peak_write_io_rate,\
                    peak_read_io_bandwidth,peak_write_io_bandwidth,\
                    read_io_completion_time_min,read_io_completion_time_max,\
                    write_io_completion_time_min,write_io_completion_time_max,\
                    read_io_rate,write_io_rate,read_io_bandwidth,\
                    write_io_bandwidth,total_read_io_time, {delayMetric}\
                    total_write_io_time,{2},{3},read_io_aborts,write_io_aborts,\
                    read_io_failures,write_io_failures from {proto}.{fc_table}\
                    ".format(
                    trib,
                    twib,
                    tric,
                    twic,
                    lun=lun_field,
                    proto=protocol_str,
                    fc_table=table_name,
                    vmid=vmid_str,
                    app_id=app_id_str,
                    delayMetric=delayMetricMinMax_str,
                )
            else:
                if misc is None:
                    # consider case of args.error also
                    query = "select port,vsan, {app_id} initiator_id,target_id,{lun} \
                        total_read_io_time,total_write_io_time, {vmid} {2},{3},\
                        read_io_aborts,write_io_aborts,read_io_failures,\
                        write_io_failures,total_read_io_initiation_time,\
                        total_write_io_initiation_time,total_read_io_bytes,{delayMetric} \
                        total_write_io_bytes from {proto}.{fc_table}\
                        ".format(
                        trib,
                        twib,
                        tric,
                        twic,
                        lun=lun_field,
                        proto=protocol_str,
                        fc_table=table_name,
                        vmid=vmid_str,
                        app_id=app_id_str,
                        delayMetric=delayMetric_str,
                    )
                else:
                    query = "select port,vsan, {app_id} initiator_id, {vmid}\
                        target_id,{lun}read_io_rate,write_io_rate,\
                        read_io_bandwidth,write_io_bandwidth,\
                        total_read_io_time,total_write_io_time,{2},{3},\
                        read_io_aborts,write_io_aborts,read_io_failures,\
                        write_io_failures,total_read_io_initiation_time,\
                        total_read_io_bytes,total_write_io_bytes,{delayMetric}\
                        total_write_io_initiation_time from {proto}.{fc_table}\
                        ".format(
                        trib,
                        twib,
                        tric,
                        twic,
                        lun=lun_field,
                        proto=protocol_str,
                        fc_table=table_name,
                        vmid=vmid_str,
                        app_id=app_id_str,
                        delayMetric=delayMetric_str,
                    )

    # query = "select all from fc-scsi." + table_name ; #CSCvn26029
    if args.vsan_thput:
        app_id_str = "app_id ,"
        query = "select port, vsan, read_io_bandwidth, write_io_bandwidth, \
            read_io_size_min, write_io_size_min, read_io_rate, \
            write_io_rate from {proto}.logical_port".format(
            proto=protocol_str
        )
    if args.top:
        app_id_str = "app_id ,"
        if args.interface is not None:
            pcre = re.match(r"port-channel(\d+)", args.interface)
            if pcre is not None:
                print("Port channel is not supported by --top option")
                exit()
        if args.key is None or args.key == "IOPS":
            wkey = ["read_io_rate", "write_io_rate"]
        if args.key == "THPUT":
            wkey = ["read_io_bandwidth", "write_io_bandwidth"]
        if args.key == "ECT":
            wkey = [
                "total_time_metric_based_read_io_count",
                "total_time_metric_based_write_io_count",
                "total_read_io_time",
                "total_write_io_time",
            ]
        if args.key == "BUSY":
            wkey = ["total_busy_period"]
        if args.key == "IOSIZE":
            wkey = [
                "total_read_io_count",
                "total_write_io_count",
                "total_read_io_bytes",
                "total_write_io_bytes",
            ]
        if not misc:
            if args.it_flow:
                query = "select port, vsan, initiator_id, {vmid} target_id \
                    ".format(
                    vmid=vmid_str
                )
                for jj in wkey:
                    query = query + "," + str(jj)
                query = (
                    query
                    + " from {0}.{1}_initiator_it_flow\
                    ".format(
                        protocol_str, table_protocol_str
                    )
                )
            elif args.initiator_flow:
                query = "select port, vsan, {vmid} initiator_id \
                    ".format(
                    vmid=vmid_str
                )
                for jj in wkey:
                    query = query + "," + str(jj)
                query = (
                    query
                    + " from {0}.{1}_initiator\
                    ".format(
                        protocol_str, table_protocol_str
                    )
                )
            elif args.target_flow:
                query = "select port, vsan, target_id \
                    ".format(
                    vmid=vmid_str
                )
                for jj in wkey:
                    query = query + "," + str(jj)
                query = (
                    query
                    + " from {0}.{1}_target\
                    ".format(
                        protocol_str, table_protocol_str
                    )
                )
            else:
                query = "select port, vsan, {app_id} initiator_id, {vmid} target_id, {0}\
                    ".format(
                    lun_field[:-1], vmid=vmid_str, app_id=app_id_str
                )
                for jj in wkey:
                    query = query + "," + str(jj)
                query = (
                    query
                    + " from {0}.{1}_initiator_it{2}_flow\
                    ".format(
                        protocol_str, table_protocol_str, ln_str
                    )
                )
        elif misc == 1:
            if args.it_flow:
                query = "select port, vsan, initiator_id, {vmid} target_id \
                    ".format(
                    vmid=vmid_str
                )
                for jj in wkey:
                    query = query + "," + str(jj)
                query = (
                    query
                    + " from {0}.{1}_target_it_flow\
                    ".format(
                        protocol_str, table_protocol_str
                    )
                )
            else:
                query = "select port, vsan, {app_id} {vmid} initiator_id, target_id, {0}\
                    ".format(
                    lun_field[:-1], vmid=vmid_str, app_id=app_id_str
                )
                for jj in wkey:
                    query = query + "," + str(jj)
                query = (
                    query
                    + " from {0}.{1}_target_it{2}_flow\
                    ".format(
                        protocol_str, table_protocol_str, ln_str
                    )
                )
        else:
            return None

    if args.outstanding_io:
        app_id_str = "app_id ,"
        pcre = re.match(r"port-channel(\d+)", args.interface)
        if pcre is not None:
            print("Port channel is not supported by --outstanding-io option")
            exit()
        if not misc:
            query = "select port, vsan, {app_id} initiator_id, {vmid} \
                target_id, {lun} active_io_read_count, \
                active_io_write_count \
                from {proto}.{proto1}_initiator_it{ln}_flow\
                ".format(
                lun=lun_field,
                proto=protocol_str,
                proto1=table_protocol_str,
                ln=ln_str,
                vmid=vmid_str,
                app_id=app_id_str,
            )
        else:
            query = "select port, vsan, {app_id} initiator_id, {vmid} \
                target_id, {lun} active_io_read_count, \
                active_io_write_count \
                from {proto}.{proto1}_target_it{ln}_flow\
                ".format(
                lun=lun_field,
                proto=protocol_str,
                proto1=table_protocol_str,
                ln=ln_str,
                vmid=vmid_str,
                app_id=app_id_str,
            )
    if args.systemload_active:
        if "init" in misc or "target" in misc:
            app_id_str = ""
            protocol_str = "fc-nvme.nvme_" if "n_" in misc else "fc-scsi.scsi_"
            fl = "initiator_id" if "init" in misc else "target_id"
            table_protocol_str = "initiator" if "init" in misc else "target"
            if "target" in misc:
                vmid_str = ""
            query = "select port,vsan, {app_id} {vmid} {0} from {1}{2}".format(
                fl, protocol_str, table_protocol_str, vmid=vmid_str, app_id=app_id_str
            )
        else:
            app_id_str = "app_id ,"
            lun_field = "namespace_id" if "itn" in misc else "lun"
            protocol_str = "fc-nvme" if "itn" in misc else "fc-scsi"
            if "i_" in misc:
                table_protocol_str = (
                    "nvme_initiator_itn_flow"
                    if "itn" in misc
                    else "scsi_initiator_itl_flow"
                )
            elif "t_" in misc:
                table_protocol_str = (
                    "nvme_target_itn_flow" if "itn" in misc else "scsi_target_itl_flow"
                )
            query = "select port,vsan, {app_id} {vmid} initiator_id,target_id,{0} from {1}.{2}".format(
                lun_field,
                protocol_str,
                table_protocol_str,
                vmid=vmid_str,
                app_id=app_id_str,
            )

    if args.histogram:
        if args.initiator_itl:
            app_id_str = "app_id ,"
            table_name = "scsi_initiator_itl_flow"
            fields = ",initiator_id,target_id,lun"
        elif args.target_itl:
            app_id_str = "app_id ,"
            table_name = "scsi_target_itl_flow"
            fields = ",initiator_id,target_id,lun"
        elif args.initiator_itn:
            app_id_str = "app_id ,"
            table_name = "nvme_initiator_itn_flow"
            fields = ",initiator_id,target_id,namespace_id"
        elif args.target_itn:
            app_id_str = "app_id ,"
            table_name = "nvme_target_itn_flow"
            fields = ",initiator_id,target_id,namespace_id"
        elif args.initiator_it:
            app_id_str = ""
            table_name = "{0}_initiator_it_flow".format(table_protocol_str)
            fields = ",initiator_id,target_id"
        elif args.target_it:
            app_id_str = ""
            table_name = "{0}_target_it_flow".format(table_protocol_str)
            fields = ",initiator_id,target_id"
        elif args.initiator:
            app_id_str = ""
            table_name = "{0}_initiator".format(table_protocol_str)
            fields = ",initiator_id"
        elif args.target:
            app_id_str = ""
            vmid_str = ""
            table_name = "{0}_target".format(table_protocol_str)
            fields = ",target_id"
        query = "select vsan, {app_id} {vmid} read_io_rate, write_io_rate, read_io_bandwidth, \
                write_io_bandwidth, read_io_size_min, read_io_size_max, \
                {0}, {2}, write_io_size_min, write_io_size_max, {1}, {3}, \
                read_io_initiation_time_min, read_io_initiation_time_max, \
                total_read_io_initiation_time, write_io_initiation_time_min, \
                write_io_initiation_time_max, total_write_io_initiation_time, \
                read_io_completion_time_min, read_io_completion_time_max, \
                total_read_io_time, write_io_completion_time_min, \
                write_io_completion_time_max, total_write_io_time, \
                total_read_io_inter_gap_time, total_write_io_inter_gap_time,\
                read_io_aborts, write_io_aborts, read_io_failures, \
                write_io_failures, peak_read_io_rate, peak_write_io_rate, \
                peak_read_io_bandwidth, peak_write_io_bandwidth {4} from \
                    {proto}.{fc_table}".format(
            trib,
            twib,
            tric,
            twic,
            fields,
            fc_table=table_name,
            proto=protocol_str,
            vmid=vmid_str,
            app_id=app_id_str,
        )

    filter_count = 0
    filters = {
        "interface": "port",
        "target": "target_id",
        "initiator": "initiator_id",
        "lun": "lun",
        "vsan": "vsan",
        "namespace": "namespace_id",
    }

    for key in filters.keys():
        if hasattr(args, key) and getattr(args, key):
            if filter_count == 0:
                query += " where "
            else:
                query += " and "
            filter_count += 1
            query += filters[key] + "=" + getattr(args, key)

    json_str = ""

    # print ("Executing {0}".format(query))
    try:
        if args.systemload_active:
            json_str = cli.cli("show analytics query '" + query + "'" + "differential")
        else:
            query += " limit " + str(args.limit)
            json_str = cli.cli("show analytics query '" + query + "'")
    except cli.cli_syntax_error:
        pass

    global error
    global error_flag

    try:
        json_out = json.loads(json_str)
    except ValueError as e:
        error["getData_str"] = json_str
        error_flag = True
        error["line_count"] = len(json_str.split("\n")) + 1
        json_out = None
    except MemoryError:
        error["getData_str"] = "Querry Output Too Huge to be processed"
        json_out = None
        error_flag = True
        error["line_count"] = 1
        if args.histogram:
            if misc_opt == 0:
                return getData(args, 1)
    # print ("Jsone {0}".format(json_out))
    return json_out


def print_util_help(self):
    print(
        """
ShowAnalytics   --errors <options> | --errorsonly <options> | \
--evaluate-npuload <options> | --help | --info <options> | \
--minmax <options> | --outstanding-io <options> | \
--top <options> | --version |  --vsan-thput <options> | \
--systemload-active <options> |  --histogram <options>


OPTIONS :
---------

 --errors                 Provides error metrics for all IT(L/N)s
                          ShowAnalytics --errors [--initiator-itl <args> | \
--target-itl <args> | --initiator-itn <args> | --target-itn <args> | \
--initiator-it <args> | --target-it <args>]

      --initiator-itl         Provides errors metrics for SCSI initiator ITLs
                              Args :  [--interface <interface>] \
[--initiator <initiator_fcid>] [--target <target_fcid>] \
[--lun <lun_id>] [--alias] [--limit <itl_limit>] [--outfile <out_file>]\
[--appendfile <out_file>]
      --target-itl            Provides errors metrics for SCSI target ITLs
                              Args :  [--interface <interface>] \
[--initiator <initiator_fcid>] [--target <target_fcid>] \
[--lun <lun_id>] [--alias] [--limit <itl_limit>] [--outfile <out_file>]\
[--appendfile <out_file>]
      --initiator-itn         Provides errors metrics for NVMe initiator ITNs
                              Args :  [--interface <interface>] \
[--initiator <initiator_fcid>] [--target <target_fcid>] \
[--alias] [--limit <itn_limit>] [--namespace <namespace_id>]\
[--outfile <out_file>] [--appendfile <out_file>]
      --target-itn            Provides errors metrics for NVMe target ITNs
                              Args :  [--interface <interface>] \
[--initiator <initiator_fcid>] [--target <target_fcid>] \
[--alias] [--limit <itn_limit>] [--namespace <namespace_id>]\
[--outfile <out_file>] [--appendfile <out_file>]
      --initiator-it          Provides errors metrics for initiator ITs
                              Args :  [--interface <interface>] \
[--initiator <initiator_fcid>] [--target <target_fcid>] \
[--alias] [--limit <itl_limit>] [--nvme] [--outfile <out_file>]\
[--appendfile <out_file>]
      --target-it             Provides errors metrics for target ITs
                              Args :  [--interface <interface>] \
[--initiator <initiator_fcid>] [--target <target_fcid>]\
[--alias] [--limit <itl_limit>] [--nvme] [--outfile <out_file>]\
[--appendfile <out_file>]

 --errorsonly             Provides error metrics for IT(L/N)s. Only display \
IT(L/N)s with non-zero errors.
                          ShowAnalytics --errorsonly [--\
initiator-itl <args> | --target-itl <args> | --initiator-itn <args> | --\
target-itn <args> | --initiator-it <args> | --target-it <args>]

      --initiator-itl         Provides errors metrics for SCSI initiator ITLs
                              Args :  [--interface <interface>] [--\
initiator <initiator_fcid>] [--target <target_fcid>] \
[--lun <lun_id>] [--alias] [--limit <itl_limit>]
[--outfile <out_file>] [--appendfile <out_file>]
      --target-itl            Provides errors metrics for SCSI target ITLs
                              Args :  [--interface <interface>] [--\
initiator <initiator_fcid>] [--target <target_fcid>] \
[--outfile <out_file>] [--appendfile <out_file>]\
[--lun <lun_id>] [--alias] [--limit <itl_limit>]
      --initiator-itn         Provides errors metrics for NVMe initiator ITNs
                              Args :  [--interface <interface>] [--\
initiator <initiator_fcid>] [--target <target_fcid>] \
[--alias] [--limit <itn_limit>] [--namespace <namespace_id>]\
[--outfile <out_file>] [--appendfile <out_file>]
      --target-itn            Provides errors metrics for NVMe target ITNs
                              Args :  [--interface <interface>] [--\
initiator <initiator_fcid>] [--target <target_fcid>] \
[--alias] [--limit <itn_limit>] [--namespace <namespace_id>]\
[--outfile <out_file>] [--appendfile <out_file>]
      --initiator-it          Provides errors metrics for initiator ITs
                              Args :  [--interface <interface>] [--\
initiator <initiator_fcid>] [--target <target_fcid>] \
[--alias] [--limit <itl_limit>] [--nvme] [--outfile <out_file>]\
[--appendfile <out_file>]
      --target-it             Provides errors metrics for target ITs
                              Args :  [--interface <interface>] [--\
initiator <initiator_fcid>] [--target <target_fcid>] \
[--alias] [--limit <itl_limit>] [--nvme] [--outfile <out_file>]\
[--appendfile <out_file>]

 --evaluate-npuload       Provides per port NPU load
                          This option must be run without analytics \
interface configurations
                          Args :  [--module <mod1,mod2> | --\
interface <int1,int2>] [--outfile <out_file>]\
[--appendfile <out_file>]
                          Provides system wide data if --module \
and --interface arguments are not present

 --help                   Provides help about this utility
 --histogram              Provide historical info about I,T,IT or IT(L/N) flows \
 gathered at every given interval. Stores 12 instance of history collected at input interval. 
                          ShowAnalytics --histogram [--\
initiator-itl <args> | --target-itl <args> | --\
initiator-itn <args> | --target-itn <args> | --\
initiator-it <args> | --target-it <args>] | --initiator <args> | \
--target <args> | --sessionId <session_id> | --show-sessions | \
--stop-session

      --initiator-itl         Provides ITL view for SCSI initiators ITLs
                              Args :  [-- initiator <initiator_fcid>] \
[--target <target_fcid>] [--lun <lun_id>] [--interval <interval>] [--metric <metric_list] \
[--outfile <out_file>] [--appendfile <out_file>] 
      --target-itl            Provides ITL view for SCSI target ITLs
                              Args :  [--initiator <initiator_fcid>] \
[--target <target_fcid>] [--lun <lun_id>] [--interval <interval>] [--metric <metric_list] \
[--outfile <out_file>]  [--appendfile <out_file>] 
      --initiator-itn         Provides ITN view for NVMe initiator ITNs
                              Args :  [--initiator <initiator_fcid>] \
[--target <target_fcid>]  [--namespace <namespace_id>] [--interval <interval>] [--metric <metric_list] \
[--outfile <out_file>] [--appendfile <out_file>]
      --target-itn            Provides ITN views for NVMe target ITNs
                              Args :  [--initiator <initiator_fcid>] \
[--target <target_fcid>]  [--namespace <namespace_id>] [--interval <interval>] [--metric <metric_list] \
[--outfile <out_file>] [--appendfile <out_file>]
      --initiator-it          Provides IT view for initiators ITs
                              Args :  [--initiator <initiator_fcid>] \
[--target <target_fcid>] [--interval <interval>] [--metric <metric_list] \
[--outfile <out_file>] [--appendfile <out_file>] 
      --target-it             Provides IT view for target ITs
                              Args :  [--initiator <initiator_fcid>] \
[--target <target_fcid>]d>] [--outfile <out_file>] [--appendfile <out_file>] \
[--interval <interval>] [--metric <metric_list]
      --initiator             Provides initiator view
                              Args :  [--initiator <initiator_fcid>] \
[--interval <interval>] [--metric <metric_list] [--outfile <out_file>] [--appendfile <out_file>] 
      --target                Provides target view
                              Args :  [--target <target_fcid>] \
[--interval <interval>] [--metric <metric_list] [--outfile <out_file>] [--appendfile <out_file>] 
      --sessionId             Shows histogram data collected by given session ID
      --show-sessions         Shows active histogram monitor sessions
      --stop-session          Stops given histogram monitor session 
                              Args :  [--sessionId <session_id>]


 --info                   Provide information about IT(L/N) flows \
 gathered over 1 second
                          ShowAnalytics --info [--\
initiator-itl <args> | --target-itl <args> | --\
initiator-itn <args> | --target-itn <args> | --\
initiator-it <args> | --target-it <args>]

      --initiator-itl         Provides ITL view for SCSI initiators ITLs
                              Args :  [--interface <interface>] [--\
initiator <initiator_fcid>] [--target <target_fcid>] \
[--lun <lun_id>] [--alias] [--limit <itl_limit>]\
[--outfile <out_file>] [--appendfile <out_file>]
      --target-itl            Provides ITL view for SCSI target ITLs
                              Args :  [--interface <interface>] [--\
initiator <initiator_fcid>] [--target <target_fcid>] \
[--lun <lun_id>] [--alias] [--limit <itl_limit>]\
[--outfile <out_file>] [--appendfile <out_file>]
      --initiator-itn         Provides ITN view for NVMe initiator ITNs
                              Args :  [--interface <interface>] [--\
initiator <initiator_fcid>] [--target <target_fcid>] \
[--alias] [--limit <itn_limit>] [--namespace <namespace_id>]\
[--outfile <out_file>] [--appendfile <out_file>]
      --target-itn            Provides ITN views for NVMe target ITNs
                              Args :  [--interface <interface>] [--\
initiator <initiator_fcid>] [--target <target_fcid>] \
[--alias] [--limit <itn_limit>] [--namespace <namespace_id>]\
[--outfile <out_file>] [--appendfile <out_file>]
      --initiator-it          Provides IT view for initiators ITs
                              Args :  [--interface <interface>] [--\
initiator <initiator_fcid>] [--target <target_fcid>] \
[--lun <lun_id>] [--alias] [--limit <itl_limit>] [--nvme]\
[--outfile <out_file>] [--appendfile <out_file>]
      --target-it             Provides IT view for target ITs
                              Args :  [--interface <interface>] [--\
initiator <initiator_fcid>] [--target <target_fcid>]d>] \
[--alias] [--limit <itl_limit>] [--nvme]\
[--outfile <out_file>] [--appendfile <out_file>]

 --minmax                 Provide Min/Max/Peak values of IT(L/N)s
                          ShowAnalytics --minmax [--\
initiator-itl <args> | --target-itl <args> | --\
initiator-itn <args> | --target-itn <args> | --\
initiator-it <args> | --target-it <args>]

      --initiator-itl         Provides ITL view for SCSI initiators ITLs
                              Args :  [--interface <interface>] [--\
initiator <initiator_fcid>] [--target <target_fcid>] \
[--lun <lun_id>] [--alias] [--limit <itl_limit>] [--outfile <out_file>]\
[--appendfile <out_file>]
      --target-itl            Provides ITL view for SCSI target ITLs
                              Args :  [--interface <interface>] [--\
initiator <initiator_fcid>] [--target <target_fcid>] \
[--lun <lun_id>] [--alias] [--limit <itl_limit>] [--outfile <out_file>]\
[--appendfile <out_file>]
      --initiator-itn         Provides ITN view for NVMe initiator ITNs
                              Args :  [--interface <interface>] [--\
initiator <initiator_fcid>] [--target <target_fcid>] \
[--alias] [--limit <itn_limit>] [--namespace <namespace_id>]\
[--outfile <out_file>] [--appendfile <out_file>]
      --target-itn            Provides ITN views for NVMe target ITNs
                              Args :  [--interface <interface>] [--\
initiator <initiator_fcid>] [--target <target_fcid>] \
[--alias] [--limit <itn_limit>] [--namespace <namespace_id>]\
[--outfile <out_file>] [--appendfile <out_file>]
      --initiator-it          Provides IT view for initiators ITs
                              Args :  [--interface <interface>] [--\
initiator <initiator_fcid>] [--target <target_fcid>] \
[--lun <lun_id>] [--alias] [--limit <itl_limit>] [--nvme]\
[--outfile <out_file>] [--appendfile <out_file>]
      --target-it             Provides IT view for target  ITs
                              Args :  [--interface <interface>] [--\
initiator <initiator_fcid>] [--target <target_fcid>]d>] \
[--alias] [--limit <itl_limit>] [--nvme] [--outfile <out_file>]\
[--appendfile <out_file>]

 --outstanding-io         Provides Outstanding io per IT(L/N) for an interface
                          Args : [--interface <interface>] [--\
initiator <initiator_fcid>] [--target <target_fcid>] [--lun <lun_id>] [--\
limit] [--refresh] [--alias] [--nvme] [--namespace <namespace_id>]\
[--outfile <out_file>] [--appendfile <out_file>]

 --systemload-active      Provides per module system load info for active IT(L/N)
                          Args :  [--module <mod1,mod2>] [--detail] [--outfile <out_file>]\
[--appendfile <out_file>]
                          Provides system wide data if --module argument is not present
 --top                    By default provides top IT(L/N)s based on key. 
                          if --it-flows provides top ITs 
                          if --initiator-flows provides top initiators
                          if --target-flows provides top targets
                          Default key is IOPS
                          Args : [--interface <interface>] [--\
initiator <initiator_fcid>] [--target <target_fcid>] [--lun <lun_id>] \
[--limit] [--key <IOPS|THPUT|ECT|BUSY|IOSIZE>] [--progress] [--alias] [--nvme] [--\
namespace <namespace_id>] [--outfile <out_file>] [--appendfile <out_file>]

 --version                Provides version details of this utility

 --vsan-thput             Provides per vsan scsi/nvme traffic rate for interface.
                          Args : [--interface <interface>] [--nvme] \
[--outfile <out_file>] [--appendfile <out_file>]



ARGUMENTS:
---------

      --alias                                      Prints device-alias for \
initiator and target in place of FCID.
      --appendfile        <output_file>            Append output of the command \
to a file on bootflash
      --detail                                     Provides per AMC load for F64 card \
--systemload-active
      --interval          <interval>               Interval at which data is fetched for histogram
      --initiator         <initiator_fcid>         Specifies initiator FCID in \
the format 0xDDAAPP
      --interface         <interface>              Specifies Interface in \
the format module/port
      --key               <iops|thput|ect|         Defines the key value for the
                           busy|iosize>            --top option
      --limit             <itl_limit>              Maximum number of ITL records \
to display. Valid range 1-{flow_limit}. Default={flow_limit}. With --top valid \
range 1-50. Default=10
      --lun               <lun_id>                 Specifies LUN ID in \
the format XXXX-XXXX-XXXX-XXXX
      --module            <mod1,mod2>              Specifies module list \
for --evaluate-npuload  or --systemload-active option example 1,2
      --metric            <iops|ect|dal|errors>    Defines metrics for histogram
      --namespace         <namespace_id>           Specifies namespace in \
the range 1-255
      --nvme                                       Provides NVMe related stats.
      --outfile           <output_file>            Write output of the command \
to a file on bootflash
      --progress                                   Provides progress for --top \
option. Should not be used on console
      --refresh                                    Refreshes output of --\
outstanding-io
      --sessionId         <session_id>             Histogram monitor session ID 
      --target            <target_fcid>            Specifies target FCID in \
the format 0xDDAAPP
      --vsan              <vsan_number>            Specifies vsan number



Note:
  --interface can take range of interfaces in case of --evaluate-npuload \
and port-channel only in case of --vsan-thput
  --initiator-itn and --target-itn options are supported from NXOS \
version 8.4(1) onwards
  --nvme and --namespace arguments are supported from NXOS \
version 8.4(1) onwards
  --key BUSY with --top is supported from NXOS version 9.2(2) onwards
""".format(
            flow_limit=max_flow_limit
        )
    )
    return True


if sys.version_info[0] < 3:
    print("Please use python3")
    sys.exit(1)

argparse.ArgumentParser.print_help = print_util_help

# argument parsing
parser = argparse.ArgumentParser(prog="ShowAnalytics", description="ShowAnalytics")
parser.add_argument(
    "--version", action="version", help="version", version="%(prog)s 5.3.0"
)
parser.add_argument("--info", action="store_true", help="--info | --errors mandatory")
parser.add_argument("--nvme", action="store_true", help="Displays NVMe related stats")
parser.add_argument(
    "--minmax", action="store_true", help="Displays Min/Max/Peak ITL view"
)
parser.add_argument("--errors", action="store_true", help="--info | --errors mandatory")
parser.add_argument(
    "--errorsonly",
    action="store_true",
    help="--info | --errors | --errorsonly  mandatory",
)
parser.add_argument(
    "--vsan-thput",
    action="store_true",
    help=" To display per vsan traffic rate for interface",
)
parser.add_argument(
    "--initiator-it", action="store_true", help="--initiator-it | --target-it mandatory"
)
parser.add_argument(
    "--target-it", action="store_true", help="--initiator-it | --target-it mandatory"
)
parser.add_argument(
    "--initiator-itl",
    action="store_true",
    help="--initiator-itl | --target-itl mandatory",
)
parser.add_argument(
    "--initiator-itn",
    action="store_true",
    help="--initiator-itn | --target-itn mandatory",
)
parser.add_argument(
    "--target-itl", action="store_true", help="--initiator-itl | --target-itl mandatory"
)
parser.add_argument(
    "--target-itn", action="store_true", help="--initiator-itn | --target-itn mandatory"
)
parser.add_argument("--interface", dest="interface", help="fc interface")
parser.add_argument("--vsan", dest="vsan", help="vsan")
parser.add_argument("--target", dest="target", help="target FCID")
parser.add_argument("--initiator", dest="initiator", help="initiator FCID")
parser.add_argument("--lun", dest="lun", help="lun")
parser.add_argument("--namespace", dest="namespace", help="nvme nsamespace")
parser.add_argument(
    "--limit",
    dest="limit",
    help="Maximum number of ITL records to display. \
                        Valid range 1-{flow_limit}. Default = {flow_limit}\
                        ".format(
        flow_limit=max_flow_limit
    ),
    default=max_flow_limit,
)
parser.add_argument(
    "--alias", action="store_true", help="--alias print device-alias info"
)
parser.add_argument("--outfile", dest="outfile", help="output file to write")
parser.add_argument("--appendfile", dest="appendfile", help="output file to append")
parser.add_argument(
    "--evaluate-npuload", action="store_true", help="To Display per port NPU load"
)
parser.add_argument("--module", dest="module", help="module list")
parser.add_argument(
    "--top", action="store_true", help="Display Top ITL based on the key specified"
)
parser.add_argument("--key", dest="key", help="iops or thput or ect | --top mandatory")
parser.add_argument("--progress", action="store_true", help="Show progress")
parser.add_argument(
    "--outstanding-io",
    action="store_true",
    help=" To display outstanding io per interface",
)
parser.add_argument("--refresh", action="store_true", help="Auto refresh")
parser.add_argument(
    "--systemload-active",
    action="store_true",
    help="To Display per module system load for active IT(L/N)",
)
parser.add_argument("--detail", action="store_true", help="Detailed information")
parser.add_argument(
    "--histogram", action="store_true", help="Shows historgram for particular ITL"
)
parser.add_argument(
    "--interval",
    dest="interval",
    help="<5-120>  Fetch interval in minutes. Default = 5| --histogram mandatory",
)
parser.add_argument(
    "--metric",
    dest="metric",
    help="iops or ect or dal or errors| --histogram mandatory",
)
parser.add_argument(
    "--show-sessions",
    action="store_true",
    help="Display histogram session details| --histogram mandatory",
)
parser.add_argument(
    "--stop-session",
    action="store_true",
    help="Stops histogram session | --histogram mandatory",
)
parser.add_argument(
    "--sessionId",
    dest="sessionId",
    help="Histogram monitor session id| --histogram mandatory",
)
parser.add_argument(
    "--it-flow",
    action="store_true",
    help=" To display top IT based on the key specified | --top mandatory",
)
parser.add_argument(
    "--initiator-flow",
    action="store_true",
    help=" To display top initiators based on the key specified | --top mandatory",
)
parser.add_argument(
    "--target-flow",
    action="store_true",
    help=" To display top targets based on the key specified | --top mandatory",
)
parser.add_argument(
    "--noclear",
    action="store_true",
    help=" Previous output will not be cleared | --top mandatory",
)
# parser.add_argument('--intlist',dest="intlist", help='int_list')


if "__cli_script_help" in sys.argv:
    print("Provide overlay cli for Analytics related stats\n")
    exit(0)
if "__cli_script_args_help" in sys.argv:
    if len(sys.argv) == 2:
        print("--errors|To display errors stats in all IT(L/N) pairs")
        print("--errorsonly|To display IT(L/N) flows with errors")
        print("--evaluate-npuload|To evaluate npuload on system")
        print("--help|To display help and exit")
        print("--histogram|To provide histogram view of particular IT(L/N)")
        print("--info|To display information about IT(L/N) flows")
        print("--minmax|To display min max and peak info about IT(L/N) flows")
        print("--outstanding-io|To display outstanding io for an interface")
        print("--systemload-active|To display system load info for active IT(L/N)s")
        print("--top|To display top 10 IT(L/N) Flow")
        print("--version|To display version of utility and exit")
        print("--vsan-thput|To display per vsan throughput for interface")
        exit(0)
    elif "--interface" == sys.argv[-1]:
        if "--evaluate-npuload" in sys.argv:
            print(
                "fc<module>/<start_port>-<end_port>,fc<module>/<port>|Interface range"
            )
        else:
            print("fc<module>/<port>|fc Interface")
        exit(0)
    elif ("--initiator" == sys.argv[-1]) or ("--target" == sys.argv[-1]):
        print("0xDDAAPP|Fcid Notation")
        exit(0)
    elif "--vsan" == sys.argv[-1]:
        print("1-4094|Vsan id")
        exit(0)
    elif "--namespace" == sys.argv[-1]:
        print(" |Namespace id as whole number")
        exit(0)
    elif "--limit" == sys.argv[-1]:
        if "--top" not in sys.argv:
            print("1-{flow_limit}|Result flow count".format(flow_limit=max_flow_limit))
        else:
            print("1-50|Result flow count")
        exit(0)
    elif "--lun" == sys.argv[-1]:
        print("XXXX-XXXX-XXXX-XXXX|Lun Notation")
        exit(0)
    elif "--key" == sys.argv[-1]:
        print("IOPS|To Provide result based on iops")
        print("ECT|To Provide result based on ect")
        print("THPUT|To Provide reslut based on throughput")
        print(
            "BUSY|To Provide reslut based on total busy period, supported from NXOS version 9.2(2) onwards"
        )
        print("IOSIZE|To Provide reslut based on iosize")
        exit(0)
    elif "--module" == sys.argv[-1]:
        print("1-3,5|module range to be considered")
        exit(0)
    elif "--interval" == sys.argv[-1]:
        print(
            "<5-120>  Fetch interval in minutes. Default = 5,| Histogram data will be collected at every <interval> minutes"
        )
        exit(0)
    elif "--metric" == sys.argv[-1]:
        print("IOPS|To Provide histogram view for iops")
        print("ECT|To Provide histogram view for ect")
        print("DAL|To Provide histogram view for dal")
        print("ERRORS|To Provide histogram view for erros")
        print("ALL|To Provide histogram view for iops,ect,dal and errors")
        exit(0)
    elif "--sessionId" == sys.argv[-1]:
        if "--stop-session" in sys.argv:
            print("all or session id(s) |use histogram --show-sessions to get the IDs")
        else:
            print(" |use histogram --show-sessions to get the IDs")
        exit(0)

    elif (
        ("--errors" in sys.argv)
        or ("--errorsonly" in sys.argv)
        or ("--info" in sys.argv)
        or ("--minmax" in sys.argv)
    ):
        if ("--initiator-itl" in sys.argv) or ("--target-itl" in sys.argv):
            if "--alias" not in sys.argv:
                print(
                    "--alias|Prints device-alias for initiator and target in place of FCID"
                )
            if "--outfile" not in sys.argv:
                print(
                    "--outfile|Provide output file name to write on bootflash on switch"
                )
            if "--appendfile" not in sys.argv:
                print(
                    "--appendfile|Provide output file name to append on bootflash on switch"
                )
            if "--initiator" not in sys.argv:
                print("--initiator|Provide initiator FCID in the format 0xDDAAPP")
            if "--interface" not in sys.argv:
                print("--interface|Provide Interface in format module/port")
            if "--limit" not in sys.argv:
                print(
                    "--limit| Maximum number of ITL records to display. Valid range 1-{flow_limit}. Default = {flow_limit}".format(
                        flow_limit=max_flow_limit
                    )
                )
            if "--lun" not in sys.argv:
                print("--lun|Provide LUN ID in the format XXXX-XXXX-XXXX-XXXX")
            if "--target" not in sys.argv:
                print("--target|Provide target FCID in the format 0xDDAAPP")
            if "--vsan" not in sys.argv:
                print("--vsan|Provide vsan number")
        elif ("--initiator-it" in sys.argv) or ("--target-it" in sys.argv):
            if "--alias" not in sys.argv:
                print(
                    "--alias|Prints device-alias for initiator and target in place of FCID"
                )
            if "--outfile" not in sys.argv:
                print(
                    "--outfile|Provide output file name to write on bootflash on switch"
                )
            if "--appendfile" not in sys.argv:
                print(
                    "--appendfile|Provide output file name to append on bootflash on switch"
                )
            if "--initiator" not in sys.argv:
                print("--initiator|Provide initiator FCID in the format 0xDDAAPP")
            if "--interface" not in sys.argv:
                print("--interface|Provide Interface in format module/port")
            if "--limit" not in sys.argv:
                print(
                    "--limit| Maximum number of ITL records to display. Valid range 1-{flow_limit}. Default = {flow_limit}".format(
                        flow_limit=max_flow_limit
                    )
                )
            if "--target" not in sys.argv:
                print("--target|Provide target FCID in the format 0xDDAAPP")
            if "--vsan" not in sys.argv:
                print("--vsan|Provide vsan number")
        elif ("--initiator-itn" in sys.argv) or ("--target-itn" in sys.argv):
            if "--alias" not in sys.argv:
                print(
                    "--alias|Prints device-alias for initiator and target in place of FCID"
                )
            if "--outfile" not in sys.argv:
                print(
                    "--outfile|Provide output file name to write on bootflash on switch"
                )
            if "--appendfile" not in sys.argv:
                print(
                    "--appendfile|Provide output file name to append on bootflash on switch"
                )
            if "--initiator" not in sys.argv:
                print("--initiator|Provide initiator FCID in the format 0xDDAAPP")
            if "--interface" not in sys.argv:
                print("--interface|Provide Interface in format module/port")
            if "--limit" not in sys.argv:
                print(
                    "--limit| Maximum number of ITL records to display. Valid range 1-{flow_limit}. Default = {flow_limit}".format(
                        flow_limit=max_flow_limit
                    )
                )
            if "--namespace" not in sys.argv:
                print("--namespace|Provide NVMe Namespace id")
            if "--target" not in sys.argv:
                print("--target|Provide target FCID in the format 0xDDAAPP")
            if "--vsan" not in sys.argv:
                print("--vsan|Provide vsan number")
        else:
            print("--initiator-itl|Prints SCSI initiator side stats")
            print("--target-itl|Prints SCSI target side stats")
            print("--initiator-itn|Prints NVMe initiator side stats")
            print("--target-itn|Prints NVMe target side stats")
            print("--initiator-it|Prints initiator side stats")
            print("--target-it|Prints target side stats")

        exit(0)
    elif "--evaluate-npuload" in sys.argv:
        if "--outfile" not in sys.argv:
            print("--outfile|Provide output file name to write on bootflash on switch")
        if "--appendfile" not in sys.argv:
            print(
                "--appendfile|Provide output file name to append on bootflash on switch"
            )
        if "--interface" not in sys.argv:
            print("--interface|Provide Interface single or multiple")
        if "--module" not in sys.argv:
            print("--module|Provide Interface in format module/port")
        exit(0)
    elif "--top" in sys.argv:
        if "--alias" not in sys.argv:
            print(
                "--alias|Prints device-alias for initiator and target in place of FCID"
            )
        if "--outfile" not in sys.argv:
            print("--outfile|Provide output file name to write on bootflash on switch")
        if "--appendfile" not in sys.argv:
            print(
                "--appendfile|Provide output file name to append on bootflash on switch"
            )
        if not "--target-flow" in sys.argv:
            if "--initiator" not in sys.argv:
                print("--initiator|Provide initiator FCID in the format 0xDDAAPP")
        if "--interface" not in sys.argv:
            print("--interface|Provide Interface in format module/port")
        if "--limit" not in sys.argv:
            print(
                "--limit| Maximum number of ITL records to display. Valid range 1-{flow_limit}. Default = {flow_limit}".format(
                    flow_limit=max_flow_limit
                )
            )
        if (
            not "--it-flow" in sys.argv
            and not "--initiator-flow" in sys.argv
            and not "--target-flow" in sys.argv
        ):
            if "--lun" not in sys.argv:
                print("--lun|Provide LUN ID in the format XXXX-XXXX-XXXX-XXXX")
            if "--namespace" not in sys.argv:
                print("--namespace|Provide NVMe Namespace id")
        if not "--initiator-flow" in sys.argv:
            if "--target" not in sys.argv:
                print("--target|Provide target FCID in the format 0xDDAAPP")
        if "--vsan" not in sys.argv:
            print("--vsan|Provide vsan number")
        if "--progress" not in sys.argv:
            print("--progress|Prints progress bar")
        if "--key" not in sys.argv:
            print("--key|Provide key like iops or thput or ect or busy or iosize")
        if "--nvme" not in sys.argv:
            print("--nvme|Provide NVMe related output")
        if "--noclear" not in sys.argv:
            print("--noclear|Previous output will not be cleared")
        if "--it-flow" not in sys.argv:
            print("--it-flow|Provides top ITs")
        if "--initiator-flow" not in sys.argv:
            print("--initiator-flow|Provides top initiators")
        if "--target-flow" not in sys.argv:
            print("--target-flow|Provides top targets")
        exit(0)
    elif "--vsan-thput" in sys.argv:
        if "--outfile" not in sys.argv:
            print("--outfile|Provide output file name to write on bootflash on switch")
        if "--appendfile" not in sys.argv:
            print(
                "--appendfile|Provide output file name to append on bootflash on switch"
            )
        if "--interface" not in sys.argv:
            print("--interface|Provide Interface in format module/port")
        if "--nvme" not in sys.argv:
            print("--nvme|Provide NVMe related output")
        print("<CR>|Run it")
        exit(0)
    elif "--outstanding-io" in sys.argv:
        if "--alias" not in sys.argv:
            print(
                "--alias|Prints device-alias for initiator and target in place of FCID"
            )
        if "--outfile" not in sys.argv:
            print("--outfile|Provide output file name to write on bootflash on switch")
        if "--appendfile" not in sys.argv:
            print(
                "--appendfile|Provide output file name to append on bootflash on switch"
            )
        if "--interface" not in sys.argv:
            print("--interface|Provide Interface in format module/port")
        if "--refresh" not in sys.argv:
            print("--refresh|auto-refresh the output")
        if "--nvme" not in sys.argv:
            print("--nvme|Provide NVMe related output")
    elif "--systemload-active" in sys.argv:
        if "--outfile" not in sys.argv:
            print("--outfile|Provide output file name to write on bootflash on switch")
        if "--appendfile" not in sys.argv:
            print(
                "--appendfile|Provide output file name to append on bootflash on switch"
            )
        if "--module" not in sys.argv:
            print("--module|Provide module number")
        if "--detail" not in sys.argv:
            print("--detail|Provides per AMC load for F64 card")
        print("<CR>|Run it")
    elif "--histogram" in sys.argv:
        if ("--initiator-itl" in sys.argv) or ("--target-itl" in sys.argv):
            if "--initiator" not in sys.argv:
                print("--initiator|Provide initiator FCID in the format 0xDDAAPP")
            if "--target" not in sys.argv:
                print("--target|Provide target FCID in the format 0xDDAAPP")
            if "--lun" not in sys.argv:
                print("--lun|Provide LUN ID in the format XXXX-XXXX-XXXX-XXXX")
            if "--interval" not in sys.argv:
                print(
                    "--interval|Provide interval at which histogram data is collected"
                )
            if "--metric" not in sys.argv:
                print(
                    "--metric|Provide metric for which histogram data needs to be collected"
                )
            if "--sessionId" not in sys.argv:
                print("--sessionId|Provide process id of histogram session")
        elif ("--initiator-it" in sys.argv) or ("--target-it" in sys.argv):
            if "--initiator" not in sys.argv:
                print("--initiator|Provide initiator FCID in the format 0xDDAAPP")
            if "--target" not in sys.argv:
                print("--target|Provide target FCID in the format 0xDDAAPP")
            if "--interval" not in sys.argv:
                print(
                    "--interval|Provide interval at which histogram data is collected"
                )
            if "--metric" not in sys.argv:
                print(
                    "--metric|Provide metric for which histogram data needs to be collected"
                )
            if "--nvme" not in sys.argv:
                print("--nvme|Provide NVMe related output")
        elif ("--initiator-itn" in sys.argv) or ("--target-itn" in sys.argv):
            if "--initiator" not in sys.argv:
                print("--initiator|Provide initiator FCID in the format 0xDDAAPP")
            if "--target" not in sys.argv:
                print("--target|Provide target FCID in the format 0xDDAAPP")
            if "--namespace" not in sys.argv:
                print("--namespace|Provide NVMe Namespace id")
            if "--interval" not in sys.argv:
                print(
                    "--interval|Provide interval at which histogram data is collected"
                )
            if "--metric" not in sys.argv:
                print(
                    "--metric|Provide metric for which histogram data needs to be collected"
                )
        elif "--show-sessions" in sys.argv:
            print("<CR>|Run it")
        elif "--stop-session" in sys.argv:
            if "--sessionId" not in sys.argv:
                print("--sessionId|Provide process id(s) of histogram session")
        else:
            print("--initiator-itl|Prints SCSI initiator side stats")
            print("--target-itl|Prints SCSI target side stats")
            print("--initiator-itn|Prints NVMe initiator side stats")
            print("--target-itn|Prints NVMe target side stats")
            print("--initiator-it|Prints initiator side stats")
            print("--target-it|Prints target side stats")
            print("--initiator|Provide initiator FCID in the format 0xDDAAPP")
            print("--target|Provide target FCID in the format 0xDDAAPP")
            print("--interval|Provide intervals at which histogram data is collected")
            print(
                "--metric|Provide metric for which histogram data needs to be collected"
            )
            print("--show-sessions|Display histogram session details")
            print("--stop-session|Stops histogram session")
        if "--outfile" not in sys.argv:
            print("--outfile|Provide output file name to write on bootflash on switch")
        if "--appendfile" not in sys.argv:
            print(
                "--appendfile|Provide output file name to append on bootflash on switch"
            )

    exit(0)


"""
if '__cli_script_args_help_partial' in sys.argv:
    print('__man_page')
    print('--error:     Display error info')
    exit(0)
"""


args = parser.parse_args()

if args.initiator_itn or args.target_itn:
    args.nvme = True

sw_ver = getSwVersion()
if sw_ver is None:
    print("Unable to get Switch software version")
    os._exit(1)

feature = verifyAnalyticsFeature()
if not feature:
    print("\nFeature analytics not enabled")
    sys.exit(1)

if not validateArgs(args, sw_ver):
    os._exit(1)

date = formatdate(localtime=True)

if args.outfile:
    outfile = args.outfile
    os.chdir("/bootflash")
    try:
        fh = open(outfile, "w+", 1)
    except:
        print("Unable to write file on bootflash")
        sys.exit(0)
    try:
        if not (args.top or args.systemload_active) or args.outstanding_io:
            fh.write("Data collected at : {}".format(date) + "\n")
        if args.top:
            fh.write("--------Output of --top--------" + "\n")
        if args.outstanding_io:
            fh.write("--------Output of --outstanding-io--------" + "\n")
    except OSError as err:
        print("Not able to write to a file, No space left on device")
        sys.exit(0)

if args.appendfile:
    outfile = args.appendfile
    os.chdir("/bootflash")
    try:
        fh = open(outfile, "a+", 1)
    except:
        print("Unable to append file on bootflash")
    try:
        if not (args.top or args.systemload_active) or args.outstanding_io:
            fh.write("Data collected at : {}".format(date) + "\n")
        if args.top:
            fh.write("--------Output of --top--------" + "\n")
        if args.outstanding_io:
            fh.write("--------Output of --outstanding-io--------" + "\n")
    except OSError as err:
        print("Not able to write to a file, No space left on device")
        sys.exit(0)

if not (args.errorsonly or args.systemload_active or args.histogram):
    print("Data collected at : {}".format(date))

if (
    not args.systemload_active
    and not args.show_sessions
    and not args.stop_session
    and not args.sessionId
):
    json_out = getData(args, ver=sw_ver)
else:
    json_out = ""

if not json_out and (args.top or args.outstanding_io):
    json_out = " "

if not json_out and not (
    args.evaluate_npuload
    or args.systemload_active
    or args.show_sessions
    or args.stop_session
    or args.sessionId
):
    if error_flag and "empty" not in error["getData_str"]:
        if error["getData_str"] == "":
            print("\n\t Table is empty\n")
        else:
            print(error["getData_str"])
    else:
        print("\n\t Table is empty\n")
else:
    if args.info:
        if args.target and args.initiator and (args.lun or args.namespace):
            if args.outfile or args.appendfile:
                if args.lun:
                    lun_namespace = args.lun
                elif args.namespace:
                    lun_namespace = args.namespace
                try:
                    fh.write(
                        "---Detailed statistics of initiator:{} target:{} lun/namespace:{}---".format(
                            args.initiator, args.target, lun_namespace
                        )
                        + "\n"
                    )
                except OSError as err:
                    print("Not able to write to a file, No space left on device")
                    sys.exit(0)
            displayDetailOverlay(json_out, ver=sw_ver)
        else:
            if args.outfile or args.appendfile:
                try:
                    fh.write("--------Output of --info--------" + "\n")
                except OSError as err:
                    print("Not able to write to a file, No space left on device")
                    sys.exit(0)
            displayFlowInfoOverlay(json_out, ver=sw_ver)

    if args.errors or args.errorsonly:
        if args.outfile or args.appendfile:
            try:
                fh.write("--------Output of --errors/--errorsonly--------" + "\n")
            except OSError as err:
                print("Not able to write to a file, No space left on device")
                sys.exit(0)
        displayErrorsOverlay(json_out, date, ver=sw_ver)

    elif args.minmax:
        if args.outfile or args.appendfile:
            try:
                fh.write("--------Output of --minmax--------" + "\n")
            except OSError as err:
                print("Not able to write to a file, No space left on device")
                sys.exit(0)
        displayFlowInfoOverlay(json_out, ver=sw_ver)

    elif args.evaluate_npuload:
        if args.outfile or args.appendfile:
            try:
                fh.write("--------Output of --evaluate-npuload--------" + "\n")
            except OSError as err:
                print("Not able to write to a file, No space left on device")
                sys.exit(0)
        displayNpuloadEvaluation(json_out, ver=sw_ver)

    elif args.vsan_thput:
        if args.outfile or args.appendfile:
            try:
                fh.write("--------Output of --vsan-thput--------" + "\n")
            except OSError as err:
                print("Not able to write to a file, No space left on device")
                sys.exit(0)
        displayVsanOverlay(json_out, ver=sw_ver)

    elif args.top:
        return_vector = displayTop(args, json_out, [None, 2, None], ver=sw_ver)
        while not (return_vector[0] is None and return_vector[2] is None):
            json_out = getData(args, ver=sw_ver)
            if not json_out:
                json_out = " "
            return_vector = displayTop(args, json_out, return_vector, ver=sw_ver)

    elif args.outstanding_io:
        return_vector = displayOutstandingIo(json_out, [None, 1, None], ver=sw_ver)
        if args.refresh:
            while not (return_vector[0] is None and return_vector[2] is None):
                json_out = getData(args, ver=sw_ver)
                if not json_out:
                    json_out = " "
                return_vector = displayOutstandingIo(
                    json_out, return_vector, ver=sw_ver
                )

    elif args.systemload_active:
        displaySystemLoadActive(ver=sw_ver)

    elif args.histogram:
        if args.show_sessions or args.stop_session:
            sessionFiles = getHistogramSessions()
            if sessionFiles:
                if args.show_sessions:
                    displayHistogramSessions(filenames=sessionFiles)
                elif args.stop_session:
                    stopHistogramSessions(args.sessionId)
            else:
                print("No histogram monitor sessions running")
        else:
            if args.sessionId:
                displayHistogramSessions(sessionId=args.sessionId)
            else:
                return_vector = displayHistogram(args, json_out, ver=sw_ver)
