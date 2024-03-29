#!/usr/bin/env python

##############################################################
# Copyright (c) 2019 by Cisco Systems, Inc.
# Applicable for NX-OS 8.3(1) and above
##############################################################

import sys
import argparse
import json
import datetime
from prettytable import *
import cli
import time
import re
import signal
import os


global sig_hup_flag
global pline
global error_log
global working_interface
global interface_list
global top_count
global error
global error_flag
global prev_wid

sig_hup_flag = None
max_flow_limit = 20000
working_interface = None
pline = 0
error_log = []
analytics_supported_module =  ['DS-X9648-1536K9', 'DS-C9148T-K9-SUP', 'DS-C9396T-K9-SUP', 'DS-C9132T-K9-SUP']
interface_list = None
top_count = 10
error_flag = False
error = dict()
prev_wid = None


def sig_hup_handler(signum,stack):
    '''
    **********************************************************************************
    * Function: sig_hup_handler
    *
    * Action: This is built for evaluate option to handle SIG_HUP i.e, ternination of ssh or telnet session.
    *            - Generates name for output file
    *            - Provides syslog to user with generated filename for output file
    * Returns: None
    **********************************************************************************
    '''
    global sig_hup_flag
    if sig_hup_flag == 'Armed':
        sig_hup_flag = 'ShowAnalytics_' + "_".join(sys.argv[1:]).replace('/','_') + '_' + str(time.time()).replace('.','_') + '.txt'
        cli.cli('logit ShowAnalytics: Remote session is closed. This process will keep running in the background. Output will be saved in the file {} in bootflash'.format(sig_hup_flag))
    else:
        cli.cli('logit ShowAnalytics: Received SIG_HUP. Hence, exiting the utility')
        os._exit(1)

def sig_int_handler(signum,stack):
    '''
    **********************************************************************************
    * Function: sig_int_handler
    *
    * Action: to handle ctrl +c operation gracefully instead of printing traceback and handling some restore operation like:
    *            - disabling analytics on interface if its enabled by this utility
    *            - Setting back the orignal terminal width if its altered by this utility
    * Returns: None
    **********************************************************************************
    '''
    global working_interface
    global prev_wid
    print '\nReceived ctrl + c'
    if working_interface:
        print 'Disabling analytics on port {} which is enabled by this utility'.format(working_interface)
        cli.cli('conf t ; interface {} ; no analytics type fc-all'.format(working_interface))
    if prev_wid != None:
        print 'Setting orignal terminal width'
        cli.cli('conf t ; terminal width {}'.format(prev_wid))
    os._exit(1)

signal.signal(signal.SIGINT,sig_int_handler)

def print_status(msgs):
    '''
    **********************************************************************************
    * Function: print_status
    *
    * Input: message to be send as status
    * Action: It is built for evaluate funcion to send status as syslog if script is running in background and just print the message on terminal if script is running in foreground
    * Returns: None
    **********************************************************************************
    '''
    global sig_hup_flag
    global pline
    global error_log
    if sig_hup_flag in ['Armed',None]:
        for msg in msgs:
            print msg
            pline +=1
    error_log.extend(msgs) 

def cmd_exc(cmd):
    '''
    **********************************************************************************
    * Function: cmd_exc
    *
    * Input: command to be executed
    * Returns: Tuple of 2 Element
    *           -  Status: Bool indicating whether command executed without error or not i.e True if executed without error
    *           -  Out: if Status is True, then output else error object
    **********************************************************************************
    '''
    try:
        cli_out = cli.cli(cmd)
    except Exception as e:
        return (False,e)
    return (True,cli_out)

def is_traffic_running(port):
    '''
    **********************************************************************************
    * Function: is_traffic_running
    *
    * Input: interface
    * Returns: Tuple of 2 Element
    *           -  Bool indicating whether traffic is running or not i.e, true if traffic is running on the port provided
    *           -  List of errors encountered , If no errors encoutered during check traffic on port then blank list 
    **********************************************************************************
    '''
    status,out = cmd_exc("show interface {} | i frame | ex min".format(port))
    out_list = []
    if not status:
        out_list.append(out)
        out_list.append('Unable to find traffic status for interface {}'.format(port))
        return (False, out_list)
    status,out1 = cmd_exc("show interface {} | i frame | ex min".format(port))
    if not status:
        out_list.append(out1)
        out_list.append('Unable to fing traffic status for interface {}'.format(port))
        return (False, out_list)
    if out1 != out:
        return (True, [])
    else:
        return (False, [])

    
def clear_previous_lines (number_of_lines):
    '''
    **********************************************************************************
    * Function: clear_previous_lines
    *
    * Cleares Previous lines from terminal to support refreshing output on terminal
    * Returns: None
    **********************************************************************************
    '''
    for _ in xrange(number_of_lines):
        sys.stdout.write("\x1b[1A")
        sys.stdout.write("\x1b[2K")


def check_port_is_analytics_enabled(inte):
    '''
    **********************************************************************************
    * Function: check_port_is_analytics_enabled
    *
    * Input: Interface in format fc<module>/<port>
    * Returns: Bool which is True if interface id port of port-sampling database i.e analytics is enabled on port else False
    **********************************************************************************
    '''
    mod = inte.strip().split('/')[0][2:]
    status,sdb_out = cmd_exc("sh analytics port-sampling module {} | i '{}'".format(mod, inte))
    if not status:
        return False
    if inte not in sdb_out:
        return False
    return True


def get_analytics_module():
    '''
    **********************************************************************************
    * Function: get_analytics_module
    *
    * Returns: set of module numbers which support analytics
    **********************************************************************************
    '''
    global analytics_supported_module
    cmd = "sh mod | i {} | cut -d ' ' -f 1".format('|'.join(analytics_supported_module))
    status, out = cmd_exc(cmd)
    if not status:
        print out
        #print 'Unable to find analytics supported module'
        return []
    else:
        return set([i for i in out.split('\n') if i.isdigit()])
            

def get_up_ints_permodule(module):
    '''
    **********************************************************************************
    * Function: get_up_ints_permodule
    *
    * Input: module number
    * Returns: list of interfaces which are up in that module
    **********************************************************************************
    '''
    status, out  = cmd_exc("sh int br | i fc{}/ | i 'up|trunking' | cut -d ' ' -f 1".format(module))
    if not status:
        print out
        print 'Unable to find any up interface in module {}'.format(module)
        return []
    else:
        return [ i for i in out.split('\n') if i.startswith('fc') and '/' in i ]

def getTermWid():
    '''
    **********************************************************************************
    * Function: getTermWid
    *
    * Returns: Width of terminal
    **********************************************************************************
    '''
    try:
        cli_out = cli.cli('sh ru all | section terminal | i width')
        term_wid = int([i for i in cli_out.split('\n') if 'alias' not in i][0].split(' ')[-1])
    except:
        term_wid = 511
    return term_wid

class flogi():
    '''
    **********************************************************************************
    * Class for parsing show flogi database output
    **********************************************************************************
    ''' 
    def __init__(self, str_out):
        ints = {}
        vsans = {}
        fcids = []
        pwwns = {}
        wwns = {}
        for line in str_out.split('\n') :
             try:
                 inte, vsan, fcid, pwwn, wwn = line.split()
             except:
                 continue
             if inte not in ints.keys() :
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
    '''
    **********************************************************************************
    * Function: fcid_Normalizer
    *
    * Input: fcid
    * Returns: fcid in 0xDDAAPP format
    **********************************************************************************
    '''
    if len(fcid) == 8:
        return fcid
    elif len(fcid) == 7:
        return fcid[0:2]+'0'+fcid[2:9]
    else :
        return fcid


def getDalias():
    '''
    **********************************************************************************
    * Function: getDalias
    *
    * Returns: Dictonary with key as pwwn and value as device-alias
    **********************************************************************************
    '''
    pwwn2alias = {}
    try:
        cli_out = cli.cli("show device-alias database")
    except:
        return {}

    for line in cli_out.split('\n'):
        line_split = line.split(' ')
        try:
            pwwn2alias[line_split[4]] = line_split[2]
        except:
            continue
    return pwwn2alias


def getfcid2pwwn():
    '''
    **********************************************************************************
    * Function: getfcid2pwwn
    *
    * Returns: Dictonary with key as fcid and value as pwwn
    **********************************************************************************
    '''
    fcid2pwwn = {}
    vsan = 1
    try:
        cli_out = cli.cli("show fcns database")        
        cli_out = cli_out.strip()
        if ':'  not in cli_out:
            return {}
    except:
        return {}
    for line in cli_out.split('\n'):
        if ':' not in line:
            continue
        if 'VSAN' in line:
            vsan = int(line.split(' ')[-1][:-1])
            continue
        line_split = line.split(' ')
        try:
            fcid2pwwn[(line_split[0],vsan)] = line_split[9]
        except:
            continue
    return fcid2pwwn


def alias_maker(init_fcid, targ_fcid, f2p, p2a, vsan):
    '''
    **********************************************************************************
    * Function: alias_maker
    *
    * Returns: List of the following:
    *       string: initiator device alias name (or null) + '::' + target device alias name (or null) 
    *       bool: True if either or both device alias were found, False if niether device alias was found 
    **********************************************************************************
    '''

    iav = False
    alias_str = ''
    for fcid in [init_fcid, targ_fcid]:
        val = '  '
        if (str(fcid),int(vsan)) in f2p:
            pwn = f2p[(str(fcid), int(vsan))]
            if pwn in p2a:
                iav = True
                val=p2a[pwn]
        alias_str = alias_str+'::'+val
    return [alias_str, iav]


def parse_module(module_str):
    '''
    **********************************************************************************
    * Function: parse_module
    *
    * Input: module string like 1-9,11
    * Returns: list of module numbers like [1,2,3,4,5,6,7,8,9,11]
    **********************************************************************************
    '''
    module = []
    for mod in  module_str.split(','):
        if '-' in mod:
            try:
                st,en = [i for i in mod.split('-') if i.isdigit()]
            except:
                print "Invalid module {}".format(mod)
                return []
            module.extend(range(int(st), int(en)+1))
        else:
             if mod.isdigit():
                 module.append(mod)
             else:
                 print "Invalid module {}".format(mod)
    return module

def parse_intlist(intlist_str):
    '''
    **********************************************************************************
    * Function: parse_intlist
    *
    * Input: interface string like fc1/9-12,fc2/13,fc3/14
    * Returns: List of interfaces like [ 'fc1/9', 'fc1/10', 'fc1/11', 'fc1/12', 'fc2/13', 'fc3/14']
    **********************************************************************************
    '''
    intlist = []
    if 'port-channel' in intlist_str:
        print 'port-channel is not supported for --evaluate-npuload option'
        return []
    for inte in intlist_str.split(','):
       if '-' in inte:
           start_int, end_int = [i.strip() for i in inte.split('-')]
           if not start_int.startswith('fc'):
                print "Invalid interface {}".format(start_int)
                return []
           try:
               start_mod, start_port = [ i for i in start_int[2:].split('/') if i.isdigit()]
           except:
               print "Invalid interface {}".format(start_int)
               return []
           if end_int.startswith('fc'):
               try:
                   end_mod,end_port = [ i for i in end_int[2:].split('/') if i.isdigit()]
               except:
                   print "Invalid interface {}".format(end_int)
                   return []
               if start_mod != end_mod:
                   print "Invalid interface range {} as start and end module number are different".format(inte)
                   return []
               intlist.extend(['fc'+str(start_mod)+'/'+str(i) for i in range(int(start_port), int(end_port)+1)])
               
           else:
               if not end_int.isdigit():
                   print "Invalid Interface range {}".format(inte)
                   return []
               else:
                   intlist.extend(['fc'+str(start_mod)+'/'+str(i) for i in range(int(start_port),int(end_int)+1)])
                   
       else:
           if re.match('fc\d+\/\d+', inte):
               intlist.append(inte)
           else:
               print 'Invalid interface {}'.format(inte)
               return []
              
    return intlist


def time_formator(sec_count):
    '''
    **********************************************************************************
    * Function: time_formator
    *
    * Input: Int number of seconds
    * Returns: String in format of seconds , minutes and hours like - 2 hours 10 minutes 30 seconds
    **********************************************************************************
    '''
    out = ''
    if sec_count > 3600:
        out += '{} hours '.format(sec_count/3600)
        sec_count = sec_count % 3600
    if sec_count > 60:
        out += '{} minutes '.format(sec_count/60)
        sec_count = sec_count % 60
    out += '{} seconds'.format(sec_count)
    return out


def calculate_max_sample_window(iops_list,flow_list):
    '''
    **********************************************************************************
    * Function: calculate_max_sample_window
    *
    * Input: It takes 2 lists as input which are as follows:
    *          - iops_list : List of active iops for each port
               - flow_list : List of ITL+ITN flows for ports
    * Returns: Maximum number of flows that can supported in 1 sampling window
    **********************************************************************************
    '''
    iops_list.sort(reverse=True)
    flow_list.sort(reverse=True)
    for i in xrange(1,len(iops_list)+1):
        if sum(iops_list[:i]) == 100:
            return i
        if sum(flow_list[:i]) == 20000:
            return i
        if sum(iops_list[:i]) > 100:
            return i-1
        if sum(flow_list[:i]) > 20000:
            return i-1
    return 48

def check_analytics_conf_per_module(mod):
    '''
    **********************************************************************************
    * Function: check_analytics_conf_per_module
    *
    * Input: Int module number
    * Returns: Bool which is True if not even single interface on that module has analytics configured and else False
    **********************************************************************************
    '''
    status,out = cmd_exc("show analytics port-sampling module {} | i fc".format(mod))
    if not status:
        print out
        print 'Unable to get analytics configuration for module {}'.format(mod)
        return True
    if out != '':
        return True
    return False

def extract_module_from_port(inte):
    '''
    **********************************************************************************
    * Function: extract_module_from_port
    *
    * Input: String Describing the interface like fc1/2
    * Returns: Int describing the module number of that interface like 1
    **********************************************************************************
    '''
    if '/' in inte:
        return int(inte.split('/')[0].split('c')[1])
    else:
        return 0


def validateArgs (args):
    '''
    **********************************************************************************
    * Function: validateArgs
    *
    * Input: Object of argparse constructed by command line arguments 
    * Returns: Bool which is True if validation of argument passes and False ootherwise
    **********************************************************************************
    '''
    if not args.info and not args.errors and not args.errorsonly and not args.minmax and not args.evaluate_npuload and not args.vsan_thput and not args.top and not args.outstanding_io :
        print "\n Please choose an action via --info or --minmax or --errors or --errorsonly or --evaluate-npuload or --vsan-thput or --top or --outstanding-io option\n"
        return False

    if int(args.info) + int(args.minmax) + int(args.errors) + int(args.errorsonly) + int(args.evaluate_npuload) + int(args.vsan_thput) + int(args.top) + int(args.outstanding_io) > 1:
        print "\nPlease choose a single option out of --info, --errors, --errorsonly, --minmax, --evaluate-npuload, --vsan-thput, --top and --outstanding-io \n"
        return False

    if not args.initiator_itl and not args.target_itl and not args.initiator_it and not args.target_it and not args.evaluate_npuload and not args.vsan_thput and not args.top and not args.outstanding_io:
        print "\n Please choose a table type via --initiator-itl or --target-itl or --initiator-it or --target-it option\n"
        return False

    if int(args.initiator_itl) + int(args.target_itl) + int(args.initiator_it) + int(args.target_it) > 1:
        print "\n Please choose a single table type via --initiator-itl or --target-itl or --initiator-it or --target-it\n"
        return False

    if args.initiator:
        try :
            initiator_id = int(args.initiator, 16)
            if initiator_id >> 32:
                print "Please enter a valid initiator id in hexadecimal format"
                return False
        except ValueError:
            print "Please enter a valid initiator id in hexadecimal format"
            return False

    if args.target:
        try :
            target_id = int(args.target, 16)
            if target_id >> 32:
                print "Please enter a valid target id in hexadecimal format"
                return False
        except ValueError:
            print "Please enter a valid target id in hexadecimal format"
            return False

    if args.alias:
        if not (args.errors or args.errorsonly or args.info or args.minmax or args.top):
            print "\n Alias option is only supported with --errors or --errorsonly or --info or --minmax or --top\n"
            return False
    if args.lun:
        lun = "0x" + ((args.lun).replace("-", ""))[::-1]
        try :
            lun_id = int(lun, 16)
            if lun_id >> 64:
                print "Please enter a valid lun id in xxxx-xxxx-xxxx-xxxx format"
                return False
        except ValueError :
            print "Please enter a valid lun id in xxxx-xxxx-xxxx-xxxx format"
            return False

    if (args.initiator_itl or args.target_itl or args.initiator_it or args.target_it) and (not (args.info or args.errors or args.minmax or args.errorsonly)):
        print "--initiator-itl or --target-itl or --initiator-it or --target-it is only supported with --info or --errors or --errorsonly or --minmax"
        return False

    if args.limit:
        try:
            args.limit = int(args.limit)
        except:
            print "--limit supports integer value from 1 to {}".format(max_flow_limit)
            return False
        if args.top:
            if args.limit <= 10:
                global top_count
                top_count = args.limit
                args.limit = 20000
            elif args.limit != 20000:
                print '--top supports maximum limit of 10'
                return False
        if (args.limit > int(max_flow_limit)) or (args.limit < 1):
            print "--limit supports integer value from 1 to {}".format(max_flow_limit)
            return False

    if args.key:
        if not args.top:
            print "--key only works with --top option"
            return False
        try:
            args.key = args.key.upper()
        except:
            print '--key can only take thput or iops or ect'
            return False
        if args.key not in ['IOPS', 'THPUT', 'ECT']:
            print " {0}  is not a valid key".format(args.key)
            return False
    if args.progress:
        if not args.top:
            print "--progress only works with --top option"
            return False

    if args.module:
        if not args.evaluate_npuload:
            print "--module only works with --evaluate-npuload"
            return False
        if args.interface:
            print "--module is not supported with --interface"
            return False
        module = parse_module(args.module)
        analytics_mods = get_analytics_module()
        invalid_module = [i for i in module if i not in analytics_mods]
        if invalid_module != []:
            print 'Module {} does not support analytics or is not present'.format(",".join(invalid_module))
            module = [i for i in module if i not in invalid_module]
        if module == []:
             print "Please provide valid module list"
             return False
        args.module = module

    if args.interface:

        global interface_list

        if not args.evaluate_npuload:
            if ',' in args.interface:
                print 'Please provide Single interface only'
                return False
            if not re.match('fc\d+\/\d+', args.interface):
                if (not args.vsan_thput ) or (not re.match('port-channel\d+',args.interface)):
                    print 'Please provide Valid Interface'
                    return False

        if args.module:
            print "--interface is not supported with --module"
            return False
        if args.evaluate_npuload:
            intlist = parse_intlist(args.interface)
        else:
            intlist = [args.interface]
        if args.vsan_thput:
            pcre = re.match('port-channel(\d+)', args.interface)
            if pcre is not None:
                pc_num = int(pcre.group(1))
                po_mem_out = cli.cli("show port-channel database interface port-channel {0} | i up".format(pc_num))
                intlist = re.findall('fc\d+\/\d+', po_mem_out)
                if intlist == []:
                    print "Port-channel {0} has no operational member".format(pc_num)
                    return False
                intlist1 = filter(check_port_is_analytics_enabled,intlist)
                if intlist1 != intlist:
                    print "Some members of {} does not support analytics or analytics is not enabled on them".format(args.interface)
                    return False
        if args.evaluate_npuload:
            analytics_mods = get_analytics_module()
            invalid_intlist = [i for i in intlist if i.strip().split('/')[0][2:] not in analytics_mods]
            if invalid_intlist != []:
                print 'Interface {} does not support analytics'.format(",".join(invalid_intlist))
            intlist = [i for i in intlist if i not in invalid_intlist]
            if intlist == []:
                print "Please provide valid interface"
                return False

            interface_list = intlist
            args.interface = None

        elif args.vsan_thput:
            if pcre:
                interface_list = [args.interface,intlist]
                args.interface = None

    if args.vsan_thput:
        if args.alias or args.initiator or args.target or args.module:
           print '--vsan-thput only supports --interface argument'
           return False

    if args.outstanding_io:
        if args.interface is None:
            print "--outstanding-io is interface specific option .. Please specify interface and try again"
            return False

    if args.refresh:
        if not args.outstanding_io:
            print '--refresh is only supported with --outstanding-io'
            return False


    return True

def thput_conv(thput_val):
    '''
    **********************************************************************************
    * Function: thput_conv
    *
    * Input: Int read from analytics metrics
    * Returns: String showing throughput in format of GB/s or MB/s or KB/s or B/s
    **********************************************************************************
    '''

    try:
        out1 = float(thput_val)
    except:
        return 'NA'

    if out1 == 0.000:
        return "0 B/s"
    elif out1 >= 1073741824:
        return "{0:3.1f} GB/s".format(float(out1/1073741824))
    elif out1 >= 1048576:
        return "{0:3.1f} MB/s".format(float(out1/1048576))
    elif out1 >= 1024:
        return "{0:3.1f} KB/s".format(float(out1/1024))
    else:
        return "{0:3.1f} B/s".format(float(thput_val))


def time_conv(time_val):
    '''
    **********************************************************************************
    * Function: time_conv
    *
    * Input: Int number of seconds
    * Returns: String showing time in format '120.0 ns' or '120.1 us' or '120.1 ms' or '120.1 s'
    **********************************************************************************
    '''

    try:
        out1 = float(time_val)
    except:
        return 'NA'
 
    if out1 == 0.000:
        if args.top:
            return "0 ns "
        return "0 ns "
    elif out1 < 1:
        return "{0:3.1f} ns".format(float(out1*1000))
    elif out1 >= 1000000:
        return "{0:3.1f} s".format(float(out1/1000000))
    elif out1 >= 1000:
        return "{0:3.1f} ms".format(float(out1/1000))
    else :
        return "{0:3.1f} us".format(float(out1))


def tick_to_time(tick):
    '''
    **********************************************************************************
    * Function: tick_to_time
    *
    * Input: Int number of ticks
    * Returns: Int number of microseconds
    **********************************************************************************
    '''
    out1 = float(tick) / 256
    return time_conv(out1)


def getMinMaxAvg(min_col, max_col, total_col, count_col) :
    '''
    **********************************************************************************
    * Function: getMinMaxAvg
    *
    * Input: This function takes 4 arguments
    *            - min_col : minimum io time
    *            - max_col : maximum io time
    *            - total_col : total io time
    *            - count_col : number of io
    * Returns: String which is '/' seperated minimum_time,maximum_time,average_time
    **********************************************************************************
    '''
    min_val = 0
    max_val = 0
    avg_val = 0
    if min_col in json_out['values']['1']:
        min_val = json_out['values']['1'][min_col]

    if max_col in json_out['values']['1']:
        max_val = json_out['values']['1'][max_col]

    if (total_col in json_out['values']['1'] and count_col in json_out['values']['1'] and long(json_out['values']['1'][count_col]) > 0):
        #avg_val = long(json_out['values']['1'][count_col]) / long(json_out['values']['1'][count_col])
        try:
            avg_val = long(json_out['values']['1'][total_col]) / long(json_out['values']['1'][count_col])
        except ZeroDivisionError:
            avg_val = 0

    return str(min_val) + '/' + str(max_val) + '/' + str(avg_val)


def getAnalyticsEnabledPorts():
    '''
    **********************************************************************************
    * Function: getAnalyticsEnabledPorts
    *
    * Returns: List of interfaces on which analytics is enabled
    **********************************************************************************
    '''
    out = []
    j_s = ""  
    qry = 'select port from fc-scsi.logical_port'
    try:
        j_s = cli.cli("show analytics query '" + qry + "'")
        j_s = json.loads(j_s)
    except:
        j_s = None
        pass
    sizeJson = len(j_s['values'])
    counter = 1
    while counter <= sizeJson:
        for key,value in j_s['values'][str(counter)].iteritems():
            if str(key) == 'port':
                if value not in out:
                    out.append(str(value))
        counter += 1
    return out


def getEPorts():
    '''
    **********************************************************************************
    * Function: getEPorts
    *
    * Returns: List of all the interface which are in mode E as per show interface brief output
    **********************************************************************************
    '''
    eports_out = cli.cli('show int brief | i fc | i E | i trunk')
    eports = re.findall('fc\d+\/\d+|vfc\d+\/\d+|vfc\d+', eports_out)
    return eports

def getPureFPorts():
    '''
    **********************************************************************************
    * Function: getPureFPorts
    *
    * Returns: List of all the interface which are in mode F as per show interface brief output
    **********************************************************************************
    '''
    fports_out = cli.cli('show interface brief | ex not | ex TF | i F | i up')
    fports = re.findall('fc\d+\/\d+|vfc\d+\/\d+|vfc\d+', fports_out)
    return fports


def vsanNormalizer(vsan_str):
    '''
       Parse Vsan Range and convert it into list
       1-10   => [1,2,3,4,5,6,7,8,9,10]
       20,30  => [10, 30]
       
    '''
    out = []
    split1 = vsan_str.split(',')
    for vsan_ins in split1:
        if '-' in vsan_ins:
            vsan_range = vsan_ins.split('-')
            try:
                start_vsan, end_vsan = map(int, vsan_range)
                out.extend(range(start_vsan, end_vsan+1))
            except:
                print "Unable to Parse Vsan range {}".format(vsan_ins)
                continue
        else:
            try:
                out.append(int(vsan_ins))
            except:
                print "Unable to Parse Vsan range {}".format(vsan_ins)
                continue
    return out              


def getVsansPerEPort(prt):
    '''
    **********************************************************************************
    * Function: getVsansPerEPort
    *
    * Input: String describing the interface like fc1/1
    * Returns: List of all the vsans that are allowed on that interface
    **********************************************************************************
    '''
    out = []
    try:
        upvsan_out = cli.cli('show interface '+str(prt)+' | i up')
        out1 = re.search('\(up\)\s+\(([0-9-,]+)\)',upvsan_out)
    except:
        print 'Unknown Interface '+str(prt)
        exit()
    if out1 is not None:
        out.extend(vsanNormalizer(out1.group(1)))
    return out


def read_write_stats(read_thput, write_thput, rios, wios, rir, wir):

    '''
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

      affected_read = (number_of_frames_per_cmd * fc_header_footer_size + (scsi_cmd_payload + 2*fc_header_footer_size + scsi_status_payload))*read_iops + read_data_thput 
                    = (number_of_frames_per_cmd*36 + (32+72+12))*read_iops + read_data_thput
                   
                    = (number_of_frames_per_cmd*36 + 116)*read_iops + read_data_thput



      affected_write = (number_of_frames_per_cmd * fc_header_footer_size + (scsi_cmd_payload + 3*fc_header_footer_size + scsi_status_payload + xrdy_payload))*read_iops + write_data_thput

                     = (number_of_frames_per_cmd*36 + (32+108+12+12))*write_iops + write_data_thput

                     = (number_of_frames_per_cmd*36 + 164)*write_iops + write_data_thput
      

    '''

    if int(read_thput) != 0:
        rd_pkt_cnt_pr_cmd = rios / 2048
        if rios%2048 != 0:
            rd_pkt_cnt_pr_cmd += 1
        affected_read = (((rd_pkt_cnt_pr_cmd*36) + 116) * rir)  +  read_thput
        #affected_read = (((rd_pkt_cnt_pr_cmd*36) + (52)) * rir)  +  read_thput
    else:
        affected_read = 0
    if int(write_thput) != 0:
        wr_pkt_cnt_pr_cmd = wios / 2048
        if wios%2048 != 0:
            wr_pkt_cnt_pr_cmd += 1
        affected_write = (((wr_pkt_cnt_pr_cmd*36) + 164) * wir)  +  write_thput
    else:
        affected_write = 0

    return [affected_read, affected_write]


def displayDetailOverlay(json_out, ver=None):
    '''
    **********************************************************************************
    * Function: displayDetailOverlay
    *
    * Input: json_out is the json data returned by switch as response for querry
    *        ver is software version of switch
    * Action: Displays detailed statistics of a particular ITL
    * Returns: None
    **********************************************************************************
    '''

    col_names = ['Metric','Min  ','Max  ','Avg  ']

    t = PrettyTable(col_names)
    t.align['Metric'] = 'l'
    t.align['Min  '] = 'r'
    t.align['Max  '] = 'r'
    t.align['Avg  '] = 'r'

    print
    print 'B: Bytes, s: Seconds, Avg: Average, Acc: Accumulative,'
    print 'ns: Nano Seconds, ms: Milli Seconds, us: Micro Seconds,'
    print 'GB: Giga Bytes, MB: Mega Bytes, KB: Killo Bytes,'
    print 'ECT: Exchange Completion Time, DAL: Data Access Latency'
    print
    if 'port' in json_out['values']['1'] : 
        print '\nInterface : ' + json_out['values']['1']['port']

    if args.alias:
        vsan = json_out['values']['1']['vsan']
        fcid2pwwn = getfcid2pwwn()
        pwwn2alias = getDalias()
        if (str(args.initiator),int(vsan)) in fcid2pwwn:
            init_pwwn = fcid2pwwn[(str(args.initiator),int(vsan))]
            if init_pwwn in pwwn2alias:
                print "Initiator Device-alias : {}".format(pwwn2alias[init_pwwn])
        if (str(args.target),int(vsan)) in fcid2pwwn:
            tar_pwwn = fcid2pwwn[(str(args.target),int(vsan))]
            if tar_pwwn in pwwn2alias:
                print "Target Device-alias : {}".format(pwwn2alias[tar_pwwn])

    conv ={'read_io_rate':'Read  IOPS', 'write_io_rate':'Write IOPS', 'read_io_bandwidth':'Read  Throughput', 'write_io_bandwidth':'Write Throughput'}
    for key in ['read_io_rate', 'write_io_rate', 'read_io_bandwidth', 'write_io_bandwidth'] :
        if key in json_out['values']['1']:
            col_values = []
            salt = '       '
            if 'rate' not in key:
                salt = ' '
            col_values.append("{} {} {}".format(conv[key],salt,'(4sec Avg)'))
            col_values.append('NA')
            col_values.append('NA')
            out_val = json_out['values']['1'][key]
            if 'rate' not in key:
                if int(out_val) != 0:
                    out_val = thput_conv(out_val)
            col_values.append(out_val)
            t.add_row(col_values)
            
    trib, twib, tric, twic = 'total_time_metric_based_read_io_bytes', 'total_time_metric_based_write_io_bytes', 'total_time_metric_based_read_io_count', 'total_time_metric_based_write_io_count'
    if ver == '8.3(1)':
        trib, twib, tric, twic = 'total_read_io_bytes', 'total_write_io_bytes', 'total_read_io_count', 'total_write_io_count'

    # io size
    col_values = []
    col_values.append('Read  Size         (Acc Avg)')
    #col_values.append(getMinMaxAvg('read_io_size_min', 'read_io_size_max', 'total_read_io_blocks', 'total_time_metric_based_read_io_count'))
    #col_values.append(getMinMaxAvg('read_io_size_min', 'read_io_size_max', 'total_time_metric_based_read_io_bytes', 'total_time_metric_based_read_io_count'))
    miin, maax, avg = getMinMaxAvg('read_io_size_min', 'read_io_size_max', trib, tric).split('/')
    col_values.extend(map(lambda x:"{} B".format(x) if int(x) != 0 else 0, [miin,maax,avg]))
    #miin,maax,avg = [" {} B".format(val) for val in [miin,maax,avg]]
    #col_values.append("/".join([miin,maax,avg]))
    t.add_row(col_values)

    col_values = []
    col_values.append('Write Size         (Acc Avg)')
    #col_values.append(getMinMaxAvg('write_io_size_min', 'write_io_size_max', 'total_write_io_blocks', 'total_time_metric_based_write_io_count'))
    #col_values.append(getMinMaxAvg('write_io_size_min', 'write_io_size_max', 'total_time_metric_based_write_io_bytes', 'total_time_metric_based_write_io_count'))
    miin, maax, avg = getMinMaxAvg('write_io_size_min', 'write_io_size_max', twib, twic).split('/')
    col_values.extend(map(lambda x:"{} B".format(x) if int(x) != 0 else 0, [miin, maax, avg]))
    #miin,maax,avg = [" {} B".format(val) for val in [miin,maax,avg]]
    #col_values.append(" | ".join([miin,maax,avg]))
    t.add_row(col_values)

    # io initiation time
    col_values = []
    col_values.append('Read  DAL          (Acc Avg)')
    #col_values.append(getMinMaxAvg('read_io_initiation_time_min', 'read_io_initiation_time_max', 'total_read_io_initiation_time', 'total_time_metric_based_read_io_count'))
    miin, maax, avg =getMinMaxAvg('read_io_initiation_time_min', 'read_io_initiation_time_max', 'total_read_io_initiation_time', 'total_time_metric_based_read_io_count').split('/')
    col_values.extend(map(time_conv,[miin, maax, avg]))
    #miin,maax,avg = ["{} \xce\xbcs".format(val) for val in [miin,maax,avg]] 
    #col_values.append(" | ".join([miin,maax,avg]))
    t.add_row(col_values)

    col_values = []
    col_values.append('Write DAL          (Acc Avg)')
    miin, maax, avg = getMinMaxAvg('write_io_initiation_time_min', 'write_io_initiation_time_max', 'total_write_io_initiation_time', twic).split('/')
    #miin,maax,avg = ["{} \xce\xbcs".format(val) for val in [miin,maax,avg]] 
    col_values.extend(map(time_conv, [miin, maax, avg]))
    #col_values.append(" | ".join([miin,maax,avg]))
    #col_values.append(getMinMaxAvg('write_io_initiation_time_min', 'write_io_initiation_time_max', 'total_write_io_initiation_time', 'total_time_metric_based_write_io_count'))
    t.add_row(col_values)

    # io completion time
    col_values = []
    col_values.append('Read  ECT          (Acc Avg)')
    miin, maax, avg = getMinMaxAvg('read_io_completion_time_min', 'read_io_completion_time_max', 'total_read_io_time', tric).split('/')
    col_values.extend(map(time_conv,[miin, maax, avg]))
    #miin,maax,avg = ["{} \xce\xbcs".format(val) for val in [miin,maax,avg]] 
    #col_values.append("/".join([miin,maax,avg]))
    #col_values.append(getMinMaxAvg('read_io_completion_time_min', 'read_io_completion_time_max', 'total_read_io_time', 'total_time_metric_based_read_io_count'))
    t.add_row(col_values)

    col_values = []
    col_values.append('Write ECT          (Acc Avg)')
    miin, maax, avg = getMinMaxAvg('write_io_completion_time_min', 'write_io_completion_time_max', 'total_write_io_time', twic).split('/')
    col_values.extend(map(time_conv, [miin,maax,avg]))
    #miin,maax,avg = ["{} \xce\xbcs".format(val) for val in [miin,maax,avg]] 
    #col_values.append(" | ".join([miin,maax,avg]))
    #col_values.append(getMinMaxAvg('write_io_completion_time_min', 'write_io_completion_time_max', 'total_write_io_time', 'total_time_metric_based_write_io_count'))
    t.add_row(col_values)

    # io inter gap time
    col_values = []
    col_values.append('Read  Inter-IO-Gap (Acc Avg)')
    min_read_io_gap, max_read_io_gap, avg_read_io_gap = [tick_to_time(int(i)) for i in getMinMaxAvg('read_io_inter_gap_time_min', 'read_io_inter_gap_time_max', 'total_read_io_inter_gap_time', tric).split('/')]
    #min_read_io_gap,max_read_io_gap,avg_read_io_gap = (min_read_io_gap*1000)/256,max_read_io_gap/(256*1000),avg_read_io_gap/256
    col_values.extend(["{}".format(min_read_io_gap), "{}".format(max_read_io_gap), "{}".format(avg_read_io_gap)])
    #col_values.append(getMinMaxAvg('read_io_inter_gap_time_min', 'read_io_inter_gap_time_max', 'total_read_io_inter_gap_time', 'total_time_metric_based_read_io_count'))
    t.add_row(col_values)

    col_values = []
    col_values.append('Write Inter-IO-Gap (Acc Avg)')
    min_write_io_gap, max_write_io_gap, avg_write_io_gap = [tick_to_time(int(i)) for i in getMinMaxAvg('write_io_inter_gap_time_min', 'write_io_inter_gap_time_max', 'total_write_io_inter_gap_time', twic).split('/')]
    #min_write_io_gap,max_write_io_gap,avg_write_io_gap = (min_write_io_gap*1000)/256,max_write_io_gap/(256*1000),avg_write_io_gap/256
    col_values.extend(["{}".format(min_write_io_gap), "{}".format(max_write_io_gap), "{}".format(avg_write_io_gap)])
    #col_values.append(getMinMaxAvg('write_io_inter_gap_time_min', 'write_io_inter_gap_time_max', 'total_write_io_inter_gap_time', 'total_time_metric_based_write_io_count'))
    t.add_row(col_values)

    print t

def displayFlowInfoOverlay(json_out, ver=None):
    '''
    **********************************************************************************
    * Function: displayFlowInfoOverlay
    *
    * Input: json_out is the json data returned by switch as response for querry
    * Action: Displays statistics of a ITLs from json_out
    * Returns: None
    **********************************************************************************
    '''
    
    global prev_wid

    if args.alias:
        prev_wid = getTermWid()
        #setting termial width as 511 to display alias
        cli.cli('terminal width 511')
        fcid2pwwn = getfcid2pwwn()
        pwwn2alias = getDalias()
        max_init_alias_len, max_targ_alias_len = 22, 19
    
    lun_str = '' if (args.initiator_it or args.target_it) else '|LUN'   

    col_names = ['VSAN|Initiator|Target{0}'.format(lun_str), 'Avg IOPS', 'Avg Throughput', 'Avg ECT']
    col_names_desc = ['', 'Read | Write', 'Read | Write', 'Read | Write']
    metrics = []
    cols = ''
    vals = ''
    port,vsan,initiator,lun,target = '0/0', '', '', '', ''
    totalread, totalwrite, readCount, writeCount = 0, 0, 0, 0
    sizeJson = len(json_out['values'])
    counter = 1
    max_iops = 0

    if args.minmax:
        col_names = ['VSAN|Initiator|Target{0}'.format(lun_str), 'Peak IOPS*', 'Peak Throughput*', 'Read ECT*', 'Write ECT*']
    else:
        pre_a = {}
        while counter <= sizeJson:
            for key,value in json_out['values'][str(counter)].iteritems():
                if str(key) == 'port':
                    port = value
                    continue
                if str(key) == 'vsan':
                    vsan = value
                    continue
                if str(key) == 'initiator_id':
                    initiator = value
                    continue
                if str(key) == 'target_id':
                    target = value
                    continue
                if str(key) == 'lun':
                    lun = value
                    continue
                if str(key) == 'total_read_io_time' and value != 0:
                    totalread = int(value)
                    continue
                if str(key) == 'total_write_io_time' and value != 0:
                    totalwrite = int(value)
                    continue
                if (str(key) == 'total_time_metric_based_read_io_count' and
                        value != 0 and ver != '8.3(1)'):
                    readCount = int(value)
                    continue
                if (str(key) == 'total_time_metric_based_write_io_count' and
                        value != 0 and ver != '8.3(1)'):
                    writeCount = int(value)
                    continue
                if str(key) == 'total_read_io_count' and value != 0 and ver == '8.3(1)':
                    readCount = int(value)
                    continue
                if str(key) == 'total_write_io_count' and value != 0 and ver == '8.3(1)':
                    writeCount = int(value)
                    continue
            counter = counter + 1
            pre_a[str(port) + '::' + str(vsan) + '::' + str(initiator) + '::' + str(target) + '::' + str(lun)]= str(totalread) + '::' + str(totalwrite)+ '::' + str(readCount)+ '::' + str(writeCount)

        if len(pre_a) < 200:
            #adding sleep for more accurate results CSCvp66699
            time.sleep(1)

        json_out = getData(args, misc=1)
        counter = 1

    while counter <= sizeJson:
        a = '' 
        iopsR, thputR, ectR = 0, 0, 0
        iopsW, thputW, ectW = 0, 0, 0
        if args.minmax:
            peak_read_iops, peak_write_iops, peak_read_thput, peak_write_thput, read_ect_min, read_ect_max, write_ect_min, write_ect_max = 0, 0, 0, 0, 0, 0, 0, 0
        for key,value in json_out['values'][str(counter)].iteritems():
            if str(key) == 'port':
                port = value
                continue
            if str(key) == 'vsan':
                vsan = value
                continue
            if str(key) == 'initiator_id':
                initiator = value
                continue
            if str(key) == 'target_id':
                target = value
                continue
            if str(key) == 'lun':
                lun = value
                continue
            if str(key) == 'read_io_rate' and value != 0:
                iopsR = int(value)
                continue
            if str(key) == 'write_io_rate' and value != 0:
                iopsW = int(value)
                continue
            if str(key) == 'read_io_bandwidth' and value != 0:
                thputR = value
                continue
            if str(key) == 'write_io_bandwidth' and value != 0:
                thputW = value
                continue
            if str(key) == 'total_read_io_time' and value != 0:
                totalread = int(value)
                continue
            if str(key) == 'total_write_io_time' and value != 0:
                totalwrite = int(value)
                continue
            if (str(key) == 'total_time_metric_based_read_io_count' and 
                    value != 0 and ver != '8.3(1)'):
                readCount = int(value)
                continue
            if (str(key) == 'total_time_metric_based_write_io_count' 
                    and value != 0 and ver != '8.3(1)'):
                writeCount = int(value)
                continue
            if str(key) == 'total_read_io_count' and value != 0 and ver == '8.3(1)':
                readCount = int(value)
                continue
            if str(key) == 'total_write_io_count' and value != 0 and ver == '8.3(1)':
                writeCount = int(value)
                continue
            if str(key) ==  'peak_read_io_rate' and value != 0:
                peak_read_iops = int(value)
                continue
            if str(key) ==  'peak_write_io_rate' and value != 0:
                peak_write_iops = int(value)
                continue
            if str(key) ==  'peak_read_io_bandwidth' and value != 0:
                peak_read_thput = value
                continue
            if str(key) ==  'peak_write_io_bandwidth' and value != 0:
                peak_write_thput = value
                continue
            if str(key) ==  'read_io_completion_time_min' and value != 0:
                read_ect_min = value
                continue
            if str(key) ==  'read_io_completion_time_max' and value != 0:
                read_ect_max = value
                continue
            if str(key) ==  'write_io_completion_time_min' and value != 0:
                write_ect_min = value
                continue
            if str(key) ==  'write_io_completion_time_max' and value != 0:
                write_ect_max = value
                continue
        if args.minmax:
            a = str(port) + '::' + str(vsan) + '::' + str(initiator) + '::' + str(target) + '::' + str(lun) \
                + '::' + str(peak_read_iops) + '::' + str(peak_write_iops) + '::' + str(peak_read_thput) \
                + '::' + str(peak_write_thput) + '::' + str(read_ect_min) + '::' + str(read_ect_max) \
                + '::' + str(write_ect_min) + '::' + str(write_ect_max)
            max_iops = max(peak_write_iops, peak_read_thput, max_iops)
        else:
            itl_id = str(port) + '::' + str(vsan) + '::' + str(initiator) + '::' + str(target) + '::' + str(lun)
            try:
                prev_totalread, prev_totalwrite, prev_readcount, prev_writecount = pre_a[itl_id].split('::')
            except:
                prev_totalread,prev_totalwrite, prev_readcount,prev_writecount = 0, 0, 0, 0
            a = itl_id  + '::' + str(iopsR) + '::' + str(iopsW) + '::' + str(thputR) + '::' + str(thputW)
            diff_readCount = int(readCount)-int(prev_readcount)          
            diff_writeCount = int(writeCount)-int(prev_writecount)          
            if diff_readCount != 0:
                ectR = abs(int(totalread)-int(prev_totalread)) / diff_readCount
            if diff_writeCount != 0:
                ectW = abs(int(totalwrite) - int(prev_totalwrite)) / diff_writeCount
            a = a + '::' + str(ectR) + '::' + str(ectW)
            max_iops = max(max_iops, iopsR, iopsW)
        counter = counter + 1
        if args.alias:
            ali_str,tisAliasValid = alias_maker(initiator, target, fcid2pwwn, pwwn2alias, vsan)
            max_init_alias_len, max_targ_alias_len = [max(aa, bb) for aa, bb in zip([len(i) for i in ali_str.split('::')[1:]],(max_init_alias_len, max_targ_alias_len))]
            a = a + ali_str
        metrics.append(a)
        cols = str(vsan) + '|' + str(initiator) + '|' + str(target) + '|' + str(lun)
    
    port_metrics = {}
    for l in metrics:
        parts  = []
        parts  = l.split('::')

        port = str(parts[0])
        if port in port_metrics:
            port_metrics[port].append(l)
        else :
            port_metrics[port] = []
            port_metrics[port].append(l)
    if args.alias:
        if args.minmax:
            part_alias_h = 13
            part_alias_t = 14
        else:
            part_alias_h = 11
            part_alias_t = 12
        col_names.append("{0:^{width}}".format('Initiator Device alias', width=max_init_alias_len))
        col_names.append("{0:^{width}}".format('Target Device alias', width=max_targ_alias_len))
        # col_names_desc.extend(['',''])

    for port in sorted(port_metrics,key= lambda x: tuple([int(i) for i in x[2:].split('/')])):
        t = PrettyTable(col_names)
        col_names_empty = ['', '', '', ''] if not args.minmax else ['', '', '', '', '']
        if args.alias:
            col_names_empty.extend(['', ''])
        # t.align = "l"
        # aligning iops
        max_iops_len = len(str(max_iops))

        col_names_desc = ['', ' {0:^{width}} | {1:^{width}} '.format('Read', 'Write', width=max_iops_len), '   Read   |   Write   ', '  Read   |   Write  ']
        if args.minmax:
            col_names_desc = ['', '{0:^{width}} | {1:^{width}} '.format('Read', 'Write', width=max_iops_len), '   Read   |   Write   ', '   Min   |    Max   ', '  Min    |    Max   ']
        if args.alias:
            col_names_desc.extend(['', ''])
        t.add_row(col_names_desc)
        t.add_row(col_names_empty)


        print "\n Interface " + port
        for l in port_metrics[port]:
            col_values = []
            parts  = []
            parts  = l.split('::')
            cols = str(parts[1]) + '|' + str(parts[2]) + '|' + str(parts[3])
            if not (args.initiator_it or args.target_it):
                cols = cols + '|' + str(parts[4])
            col_values.append(cols)
            col_values.append(" {0:^{width}} | {1:^{width}} ".format(parts[5],parts[6], width=max_iops_len))
            col_values.append(" {0:>10} | {1:^11} ".format(thput_conv(float(parts[7])), thput_conv(float(parts[8]))))
            col_values.append(" {0:>7} | {1:>8} ".format(time_conv(float(parts[9])), time_conv(float(parts[10]))))
            if args.minmax:
                col_values.append("{0:>9} |{1:>10}".format(time_conv(float(parts[11])), time_conv(float(parts[12]))))
            if args.alias:
                t.align["{0:^{width}}".format('Initiator Device alias', width=max_init_alias_len)] = 'l'
                t.align["{0:^{width}}".format('Target Device alias', width=max_targ_alias_len)] = 'l'
                col_values.extend([str(parts[part_alias_h]), str(parts[part_alias_t])])
            t.add_row(col_values)

        print t
    if args.minmax:
        print '*These values are calculated since the metrics were last cleared.'

    #setting back orignal terminal width 
    if args.alias:
        cli.cli("terminal width {}".format(prev_wid))


def displayErrorsOverlay(json_out, date, ver=None):
    '''
    **********************************************************************************
    * Function: displayErrorsOverlay
    *
    * Input: It takes 3 arguments:
    *          - json_out is the json data returned by switch as response for querry
    *          - date is String format system date
    *          - ver is software version of switch
    * Action: Displays error statistics of a ITLs from json_out
    * Returns: None
    **********************************************************************************
    '''

    if args.alias:
        prev_wid = getTermWid()
        # setting termial width as 511 to display alias
        cli.cli('terminal width 511')
        fcid2pwwn = getfcid2pwwn()
        pwwn2alias = getDalias()
        max_init_alias_len = 22
        max_targ_alias_len = 19
        
        def alias_maker(init_fcid, targ_fcid, f2p, p2a, vsan):
           iav = False
           alias_str = ''
           for fcid in [init_fcid,targ_fcid]:
               val = ' '
               if (str(fcid),int(vsan)) in f2p:
                   pwn = f2p[(str(fcid),int(vsan))]
                   if pwn in p2a:
                       iav = True
                       val=p2a[pwn]
               alias_str = alias_str+'::'+val
           return [alias_str, iav]

    displaydateFlag = False
    col_names = ['VSAN|Initiator|Target|LUN', 'Total SCSI Failures', 'Total FC Aborts']
    if args.initiator_it or args.target_it:
        col_names = ['VSAN|Initiator|Target', 'Total SCSI Failures', 'Total FC Aborts']
    col_names_desc = ['', 'Read | Write', 'Read | Write']
    col_values = []
    metrics = []
    cols = ''
    vals = ''
    vsan,initiator,lun,target = '', '', '', ''
    max_failures,max_aborts=0,0
    sizeJson = len(json_out['values'])
    counter = 1
    while counter <= sizeJson:
        a = ''
        failR, abortsR = 0, 0
        failW, abortsW = 0, 0
        for key,value in json_out['values'][str(counter)].iteritems():
            #print key,value
            if str(key) == 'port':
                port = value
            if str(key) == 'vsan':
                vsan = value
            if str(key) == 'initiator_id':
                initiator = value
            if str(key) == 'target_id':
                target = value
            if str(key) == 'lun':
                lun = value
            if str(key) == 'read_io_aborts' and value != 0:
                abortsR = int(value)
            if str(key) == 'write_io_aborts' and value != 0:
                abortsW = int(value)
            if str(key) == 'read_io_failures' and value != 0:
                failR = int(value)
            if str(key) == 'write_io_failures' and value != 0:
                failW = int(value)
        counter = counter + 1
        #for errorsonly
        if args.errors or (failR != 0 or failW != 0 or abortsR != 0 or abortsW != 0 ):
            a = str(port) + '::' + str(vsan) + '::' + str(initiator) + '::' + str(target) + '::' + str(lun) \
                    + '::' + str(failR) + '::' + str(failW) + '::' + str(abortsR) + '::' + str(abortsW)
            max_failures=max(max_failures,failR,failW)
            max_aborts=max(max_aborts,abortsR,abortsW)
            if args.alias:
                ali_str,tisAliasValid = alias_maker(initiator,target,fcid2pwwn,pwwn2alias,vsan)
                max_init_alias_len,max_targ_alias_len = [max(aa,bb) for aa,bb in zip([len(i) for i in ali_str.split('::')[1:]],(max_init_alias_len,max_targ_alias_len))]
                a = a + ali_str
            metrics.append(a)
            cols = str(vsan) + '|' + str(initiator) + '|' + str(target) + '|' + str(lun)
            displaydateFlag = True

    if args.errorsonly:
        if displaydateFlag:
            print date
        else:
            print "\n No ITLs with errors found\n"

    port_metrics = {}
    for l in metrics:
        parts  = []
        parts  = l.split('::')

        port = str(parts[0])
        if port in port_metrics:
            port_metrics[port].append(l)
        else:
            port_metrics[port] = []
            port_metrics[port].append(l)

    if args.alias:
        col_names.append("{0:^{width}}".format('Initiator Device alias',width=max_init_alias_len))
        col_names.append("{0:^{width}}".format('Target Device alias',width=max_targ_alias_len))
        col_names_desc.extend(['', ''])

    # aligning o/p
    failure_width = len(str(max_failures))+2
    abort_width = len(str(max_aborts))+2

    for port in sorted(port_metrics,key= lambda x: tuple([int(i) for i in x[2:].split('/')])):
        t = PrettyTable(col_names)
        t.add_row(col_names_desc)
        col_names_empty = ['', '', '', '', ''] if args.alias else ['', '', '']
        t.add_row(col_names_empty)
        # t.align = "l"

        print "\n Interface " + port
        for l in port_metrics[port]:
            col_values = []
            parts  = []
            parts  = l.split('::')
            cols = str(parts[1]) + '|' + str(parts[2]) + '|' + str(parts[3]) 
            if not(args.initiator_it or args.target_it):
                cols = cols + '|' + str(parts[4])
            col_values.append(cols)
            col_values.append("{0:^{width}}|{1:^{width}}".format(parts[5],parts[6],width=failure_width))
            col_values.append("{0:^{width}}|{1:^{width}}".format(parts[7],parts[8],width=abort_width))
            if args.alias:
                col_values.extend([str(parts[9]),str(parts[10])])
            t.add_row(col_values)
        print t


def displayNpuloadEvaluation(json_out, ver=None):
    '''
    **********************************************************************************
    * Function: displayNpuloadEvaluation
    *
    * Input: json_out is the json data returned by switch as response for querry
    *        ver is software version of switch
    * Action: Enable Analytics on  Analytics Capable ports selected via args global object , collect NpuLoad added by each port and disable analytics on that port
    * Returns: None
    **********************************************************************************
    '''

    global interface_list
    global error_log
    global pline
    error_log = []
    global sig_hup_flag
    global working_interface
    interface_list_flag = False

    signal.signal(signal.SIGHUP, sig_hup_handler)
    
    if interface_list:
        interface_list_flag = True
    else:
       interface_list = []

    if ( not (args.module) ) and ( interface_list == [] ) :  
        #complete chassis option
        module = get_analytics_module()
    if args.module:
        module = args.module
    if 'module' in dir():
        if module == []:
            print '\nNo analytics enabled module found.\n'
            sys.exit(1)
        else:
            analytics_interface_configured_modules = filter(check_analytics_conf_per_module,module)
            if analytics_interface_configured_modules != []:
                print 'Execution terminated as analytics is configured on interface of following module:'
                for mod in analytics_interface_configured_modules:
                    print ' Module {}'.format(mod)
                print 'Note: --evaluate-npuload option should only be run prior to configuring analytics'
                sys.exit(1)
            interface_list = []
            for mod in module:
                interface_list.extend(get_up_ints_permodule(mod))
    else:
        if interface_list != []:
            passed_modules = []
            for inte in interface_list:
                mod = extract_module_from_port(inte)
                if mod not in passed_modules:
                    if not check_analytics_conf_per_module(mod):
                        passed_modules.append(mod)
                    else:
                        print 'Execution terminated as analytics is configured on interface of module {}'.format(mod)
                        print 'Note: --evaluate-npuload option should only be run prior to configuring analytics'
                        sys.exit(1)

    if interface_list == []:
        print 'No Up port found on device capable for analytics'
        sys.exit(1)
 
    int_count = len(interface_list)
    expected_time = int_count*60
    print 'There are {} interfaces to be evaluated. Expected time is {}'.format(int_count,time_formator(expected_time))
    conf_response = str(raw_input('Do you want to continue [Yes|No]? [n]'))
    if conf_response not in ['Y', 'y', 'Yes', 'yes', 'YES'] :
       return False

    # arming the sighup handler
    sig_hup_flag = 'Armed'

    if sig_hup_flag == 'Armed':
        status,out = cmd_exc('configure terminal ;  terminal session-timeout 0')
        if not status:
            print out
            print 'Unable to set session timeout'
    mod_matrix = {}
    int_iterator = 0
    pline = 0
    for inte in interface_list:
        int_iterator+=1
        if int_iterator != 1:
            if sig_hup_flag == 'Armed':
                clear_previous_lines(pline)
                pline = 0
        if sig_hup_flag in [None, 'Armed']:
            print 'Evaluating interface {} ({} out of {} interfaces)'.format(inte, int_iterator, int_count)
            pline = 1
        else:
            cli.cli('logit ShowAnalytics: Evaluating interface {} ({} out of {} interfaces)'.format(inte, int_iterator, int_count))
        if not interface_list_flag:
            traffic_flag,err_out= is_traffic_running(inte)
            if not traffic_flag:
                if err_out == []:
                    err_out.append('Traffic is not running on port {}'.format(inte))
                print_status(err_out)
                continue
        cmd = 'configure terminal ; interface {} ; analytics type fc-all ; sh clock'.format(inte)
        status,out = cmd_exc(cmd)
        if not status:
            print_status([out, 'Unable to enable analytics on interface {}'.format(inte)])
            continue
        start_time = out.split('\n')[-2].split(' ')[0][:-4]
        working_interface = inte
        time.sleep(10)
        mod = inte.strip().split('/')[0][2:]
        status,sdb_out = cmd_exc("sh analytics port-sampling module {} | i '{}'".format(mod, inte))
        fail_flag = False

        if inte in sdb_out:
            try:
                sdb_out = " ".join([ i for i in sdb_out.split(' ') if i != '' and i != '-' and i != '\n'][1:])
                sampling_start_time = datetime.datetime.strptime(sdb_out,'%m/%d/%y %H:%M:%S')
            except Exception as e:
                sdb_out = ''
        if inte not in sdb_out:
            for x in xrange(30):
                time.sleep(1)
                status,sdb_out = cmd_exc("sh analytics port-sampling module {} | i '{}'".format(mod,inte))
                if not status:
                    print_status([out, 'Unable to get sdb data'])
                    continue
                if inte in sdb_out:
                    try:
                        sdb_out = " ".join([ i for i in sdb_out.split(' ') if i != '' and i != '-' and i != '\n'][1:])
                        sampling_start_time = datetime.datetime.strptime(sdb_out.split('*')[-1].strip(),'%m/%d/%y %H:%M:%S')
                    except Exception as e:
                        continue
                    break
                elif x == 29:
                  error_data = 'Analytics is still not enabled for interface {}'.format(inte)
                  print_status([error_data])
                  fail_flag = True

        if fail_flag:
            cmd = 'configure terminal ; interface {} ; no analytics type fc-all ; sh clock'.format(inte)
            status,out = cmd_exc(cmd)
            if not status:
                print_status([out, 'Unable to disable analytics on interface {}'.format(inte)])
            working_interface = None
            continue
        # print 'port in SDB time {}'.format(time.ctime())
        # sampling_start_time = datetime.datetime.strptime(sdb_out.split('*')[-1].strip(),'%m/%d/%y %H:%M:%S')
        current_time = datetime.datetime.now()
        time_drift = current_time - sampling_start_time
        time_drift = time_drift.seconds
        if time_drift < 30:
            sleep_time = 31 - time_drift
            time.sleep(sleep_time)
        data_scsi, data_nvme = None, None
        # print 'SCSI Analysis start time {}'.format(datetime.datetime.now())
        data_scsi = getData(args, (inte, 'scsi'), ver)
        # print 'SCSI Analysis end time {}'.format(datetime.datetime.now())
        data_nvme = getData(args, (inte, 'nvme'), ver)
        #print 'Nvme Analysis end time {}'.format(datetime.datetime.now())
        cmd = 'configure terminal ; interface {} ; no analytics type fc-all ; sh clock'.format(inte)
        status,out = cmd_exc(cmd)
        if not status:
            print_status([out, 'Unable to disable analytics on interface {}'.format(inte)])
        working_interface = None
        end_time = out.split('\n')[-2].split(' ')[0][:-4]
        itl_count, itn_count, scsi_iops,nvme_iops = 0, 0, 0, 0
        data = ''
        if data_scsi is not None:
            for key,value in data_scsi['values']['1'].iteritems():
                if key == 'sampling_start_time':
                    scsi_sampling_start_time = int(value)
                    start_time = datetime.datetime.fromtimestamp(int(value)).strftime("%H:%M:%S")
                    continue
                if key == 'sampling_end_time':
                    end_time = datetime.datetime.fromtimestamp(int(value)).strftime("%H:%M:%S")
                    continue
                if key == 'scsi_initiator_itl_flow_count':
                    itl_count += int(value)
                    continue
                if key == 'scsi_target_itl_flow_count':
                    itl_count += int(value)
                    continue
                if key == 'read_io_rate':
                    scsi_iops += int(value)
                    continue
                if key == 'write_io_rate':
                    scsi_iops += int(value)
                    continue
            scsi_iops = scsi_iops/5000.0
            #print 'SCSI Window {}   {}'.format(start_time,end_time)

        if data_nvme is not None:
            for key,value in data_nvme['values']['1'].iteritems():
                if key == 'sampling_start_time':
                    start_time = datetime.datetime.fromtimestamp(int(value)).strftime("%H:%M:%S")
                    continue
                if key == 'sampling_end_time':
                    end_time = datetime.datetime.fromtimestamp(int(value)).strftime("%H:%M:%S")
                    continue
                if key == 'nvme_initiator_itn_flow_count':
                    itn_count += int(value)
                    continue
                if key == 'nvme_target_itn_flow_count':
                    itn_count += int(value)
                    continue
                if key == 'read_io_rate':
                    nvme_iops += int(value)
                    continue
                if key == 'write_io_rate':
                    nvme_iops += int(value)
                    continue

            nvme_iops = nvme_iops/5000.0
            # print 'Nvme Window {}   {}'.format(start_time,end_time)
 
        data = inte + '-' + str(itl_count) + '-' + str(scsi_iops)\
        + '-' + str(itn_count) + '-' + str(nvme_iops)\
        + '-' + str(start_time) + '-' + str(end_time)
        if 'module' in dir():
            mod = inte.split('/')[0][2:]
        else:
            mod = 51
        if mod not in mod_matrix:
            mod_matrix[mod] = [data]
        else:
            mod_matrix[mod].append(data)

    col_empty = ['']*9
    if sig_hup_flag not in [None,'Armed']:
        file_name = '/bootflash/'+sig_hup_flag
        try:
            file_handler = open(file_name, 'w+')
        except Exception as e:
            cli.cli('logit ShowAnalytics: Unable to save output in bootflash with name {} as {}'.format(sig_hup_flag,e))
            sys.exit(1)
    else:
        clear_previous_lines(pline)
    for mod in mod_matrix:
        mod_iops_list = []
        mod_flow_list = []
        if mod  < 50:
            if  sig_hup_flag not in [None,'Armed']:
                file_handler.write("Module {}".format(mod))
            else:
                print "Module {}".format(mod)
        m_itl_count, m_scsi_iops, m_itn_count, m_nvme_iops = 0, 0, 0, 0

        t= PrettyTable(['',' SCSI ', ' NVMe ', ' Total ','SCSI','NVMe','Total','Start Time','End Time'],headers_misc=[['above',['Interface', 'ITL/N Count',' NPU Load %','Analyis','Analysis'],[1,3,3,1,1]]])

        for port_metrix in mod_matrix[mod]:
            tport,t_itl_count,t_scsi_iops,t_itn_count,t_nvme_iops,t_start_time,t_end_time = port_metrix.split('-')
            t_itl_count, t_itn_count = [int(i) for i in [t_itl_count,t_itn_count]]
            t_scsi_iops, t_nvme_iops = [float(i) for i in [t_scsi_iops,t_nvme_iops]]
            m_itl_count += t_itl_count
            m_scsi_iops += round(t_scsi_iops, 1)
            m_itn_count += t_itn_count
            m_nvme_iops += round(t_nvme_iops, 1)
            port_flow_count = t_itl_count + t_itn_count
            port_iops_count = round(t_scsi_iops, 1) + round(t_nvme_iops, 1)
            mod_iops_list.append(port_iops_count)
            mod_flow_list.append(port_flow_count)
            
            t.add_row([tport,t_itl_count,t_itn_count,port_flow_count,'{:.1f}'.format(t_scsi_iops),'{:.1f}'.format(t_nvme_iops),'{:.1f}'.format(port_iops_count),t_start_time,t_end_time])
        t.add_row(col_empty)
        t.add_row(['*Total',m_itl_count,m_itn_count,(m_itl_count+m_itn_count),'{:.1f}'.format(m_scsi_iops),'{:.1f}'.format(m_nvme_iops),'{:.1f}'.format(m_scsi_iops+m_nvme_iops),'',''])
        if sig_hup_flag not in [None, 'Armed']:
            file_handler.write(str(t.get_string()))
            if not interface_list_flag:
                file_handler.write("\nRecommended port sampling size: {}".format(calculate_max_sample_window(mod_iops_list, mod_flow_list)))
        else:
            print t
            if not interface_list_flag:
                print "Recommended port sampling size: {}\n".format(calculate_max_sample_window(mod_iops_list,mod_flow_list))

    if sig_hup_flag not in [None,'Armed']:
        file_handler.write('\n')
        file_handler.write('* This total is an indicative reference based on evaluated ports')
        if error_log != []:
            file_handler.write('\nErrors:\n------\n')
            for msg in error_log:
                file_handler.write(msg)
        file_handler.close()
    else:
        print '* This total is an indicative reference based on evaluated ports'
        if error_log != []:
            print '\nErrors:\n------\n'
            for msg in error_log:
                print msg
    cli.cli('logit ShowAnalytics: Task Completed')    


def displayVsanOverlay(json_out, ver=None) :
    '''
    **********************************************************************************
    * Function: displayVsanOverlay
    *
    * Input: json_out is the json data returned by switch as response for querry
    *         ver is software version of the switch
    * Action: Displays per vsan throughput for the interface pointed by global args object
    * Returns: None
    **********************************************************************************
    '''
  
    # have to write that
    metrics = {}
    sizeJson = len(json_out['values'])
    counter = 1
    while counter <= sizeJson:
        port, vsan, read, write, rios, wios, rir, wir = '', '', '', '', '', '', '', ''
        for key,value in json_out['values'][str(counter)].iteritems():
            if str(key) == 'port':
                port = str(value)
            elif str(key) == 'vsan':
                vsan = int(value)
            elif str(key) == 'read_io_bandwidth':
                read = int(value)
            elif str(key) == 'write_io_bandwidth':
                write = int(value)
            elif str(key) == 'read_io_size_min':
                rios = int(value)
            elif str(key) == 'write_io_size_min':
                wios = int(value)
            elif str(key) == 'read_io_rate':
                rir = int(value)
            elif str(key) == 'write_io_rate':
                wir = int(value)
            else:
                pass
         
        counter += 1
        if port not in metrics.keys():
            metrics[port]={}
        metrics[port][vsan] = read_write_stats(read, write, rios, wios, rir, wir)

    port_metrics = {}
    f_ports = None
    global interface_list
    if interface_list is None:
        eports_to_consider = getAnalyticsEnabledPorts()
        if args.interface is None:
            f_ports = getPureFPorts()
    else :
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
                    a,b = metrics[port][vsan]
                    if vsan in port_metrics[interface_list[0]].keys():
                        c, d = port_metrics[interface_list[0]][vsan]
                        port_metrics[interface_list[0]][vsan] = [(a+c), (b+d)]
                    else:
                        port_metrics[interface_list[0]][vsan] = [a, b]
                if considered_port_count < ( len(interface_list[1]) -1 ):
                    considered_port_count += 1
                    continue
                else:
                    port1 = interface_list[0]
                
            evsan = [int(i) for i in enabled_vsans if int(i) not in [int(j) for j in  port_metrics[port1].keys()]]
            if evsan != []:
                for vsan in evsan:
                    port_metrics[port1][vsan] = [0,0]

    col_names = ['', 'Read', 'Write', 'Total']
    col_names_desc = ['', '(MBps)', '(MBps)', '(MBps)']

 
    for port in sorted(port_metrics, key= lambda x: tuple([int(i) for i in x[2:].split('/')]) if not x.startswith('port-channel') else int(x[12:])):
        if port_metrics[port] == {}:
            if interface_list:
                print "\n\t Table is empty\n"
                sys.exit(1)
            else:
                continue
                
        t = PrettyTable(col_names,headers_misc=[['above', ['VSAN', 'Throughput (4s avg)'], [1, 3]], ['below', ['', '(MBps)', '(MBps)', '(MBps)'], [1, 1, 1, 1]]])
        # t.add_row(col_names_desc)
        t.align = "l"
        for vsan in sorted(port_metrics[port].keys()):
            col = []
            col.append("%d"%int(vsan))
            port_metrics[port][vsan] = [float(i)/1000000 for i in port_metrics[port][vsan]]
            col.append("{0:.1f}".format(port_metrics[port][vsan][0]))
            col.append("{0:.1f}".format(port_metrics[port][vsan][1]))
            tmp_tb = float(port_metrics[port][vsan][0]) + float(port_metrics[port][vsan][1])
            col.append("{0:.1f}".format(tmp_tb))
            t.add_row(col)
        print "\n Interface " + port
        print t
    print 'Note: This data is only for SCSI\n'


def displayTop(args,json_out, return_vector, ver=None):
    '''
    **********************************************************************************
    * Function: displayTop
    *
    * Input: It takes 3 input 
    *           - json_out is the json data returned by switch as response for querry
    *           - return_vector is the list of 3 elements described as [<lines to be deleted before printing new iteration result> <time to sleep between 2 iteration> <data from previous iteration>]
    *           - ver is software version of switch
    * Action: Displays top 10 ITLs based on the key provided via args global object, by default key is ECT
    * Returns: return_vector is the same one as described in Input
    **********************************************************************************
    '''

    global top_count
    global error
    global error_flag

    if args.progress:
        sys.stdout.write('#')
        sys.stdout.flush()

    if args.alias:
        prev_wid = getTermWid()
        # setting termial width as 511 to display alias
        cli.cli('terminal width 511')
        fcid2pwwn = getfcid2pwwn()
        pwwn2alias = getDalias()
        max_init_alias_len, max_targ_alias_len = 22, 19

    line_count = 0
    str1 = None
    str2 = None
    if error_flag:
        str1 = error['getData_str']
        if 'empty'  in str1 or str1 == '':
            str1 = None
        else:
            line_count += error['line_count']
            line_count += 1

    json_out1 = getData(args,1)
    if error_flag:
        str2 = error['getData_str']
        if 'empty' in str2 or str2 == '':
            str2 = None
        else:
            line_count += error['line_count']
            line_count += 1
    # print json_out
    # print return_vector[0]

    if json_out == ' ':
        if json_out1 is None:
            tmp_clr_line_count = 2
            if return_vector[0] is not None:
                time.sleep(return_vector[1])
                clear_previous_lines(return_vector[0])
            else:
                clear_previous_lines(1)
            print
            print datetime.datetime.now()
            if str1 is not None:
                print
                print str1
            if (str2 is not None) and (str1 != str2):
                print 
                print str2
            if str1 == str2 and (str1 is not None):
                line_count -= (error['line_count']+1)
            tmp_clr_line_count += line_count
            if str1 == str2 == None:
                print "\n\t Table is empty\n"
                tmp_clr_line_count = 5
            return [tmp_clr_line_count, return_vector[1], '']
        else :
            json_out = json_out1
            json_out1 = None

    #clear_previous_lines(1)
    if args.progress:
        sys.stdout.write('##')
        sys.stdout.flush()
        
    tric,twic = 'total_time_metric_based_read_io_count','total_time_metric_based_write_io_count'
    if ver == '8.3(1)':
        tric,twic = 'total_read_io_count','total_write_io_count'
   
    metrics = []
    pdata = {}
    while json_out:
        sizeJson = len(json_out['values'])
        counter = 1
        while counter <= sizeJson:
    
            iter_itl = json_out['values'][str(counter)]
            port, initiator, target, lun = [str(iter_itl.get(unicode(i), '')) for i in ['port', 'initiator_id', 'target_id', 'lun']]
            vsan = str(iter_itl.get(u'vsan',0))
            read,write,rb,wb,totalread,totalwrite,readCount,writeCount = [int(iter_itl.get(unicode(i),0)) for i in ['read_io_rate', 'write_io_rate', 'read_io_bandwidth', 'write_io_bandwidth', 'total_read_io_time', 'total_write_io_time', tric, twic]]
    
            counter += 1
            itl_id = port + '::' + vsan + '::' + initiator + '::' + target + '::' + lun
            if args.key == None or args.key == 'IOPS':
                a = itl_id + '::' + str(read) + '::' + str(write) + '::' + str(read+write)
            elif args.key == 'THPUT':
                a = itl_id + '::' + str(rb) + '::' +str(wb) + '::' +str(rb+wb)
            elif args.key == 'ECT':
                pdata[itl_id] = str(readCount) + '::' +str(totalread) + '::' + str(writeCount) + '::' + str(totalwrite)
                ectR, ectW = 0, 0
                if return_vector[2] != None and itl_id in return_vector[2].keys():
                    rc, tr, wc, tw = [int(i) for i in return_vector[2][itl_id].split('::')]
                    ectR = abs((tr-totalread)/(rc-readCount)) if rc != readCount else 0
                    ectW = abs((tw-totalwrite)/(wc-writeCount)) if wc != writeCount else 0
                else:
                    ectR = (totalread / readCount) if readCount != 0 else 0
                    ectW = (totalwrite / writeCount) if writeCount != 0 else 0
    
                a = itl_id + '::' + str(ectR) + '::' + str(ectW) + '::' +str(ectW+ectR)
            if args.alias:
                ali_str,tisAliasValid = alias_maker(initiator,target,fcid2pwwn,pwwn2alias,vsan)
                max_init_alias_len, max_targ_alias_len = [max(aa, bb) for aa, bb in zip([len(i) for i in ali_str.split('::')[1:]], (max_init_alias_len, max_targ_alias_len))]
                a = a + ali_str
            metrics.append(a)

        json_out = None

        if json_out1 is not None:
            json_out = json_out1
            json_out1 = None

    # clear_previous_lines(1)
    if args.progress:
        sys.stdout.write('###')
        sys.stdout.flush()
    out_metrics = []
    sTep = 1000
    lm = len(metrics)
    if lm > sTep:
        d_l, r_l = lm/sTep, lm % sTep
        for c_li in xrange(1, d_l+1):
            out_metrics.extend(sorted(metrics[(c_li-1)*sTep:(c_li*sTep)], key=lambda st: int(st.split('::')[7]), reverse=True)[:top_count])
        if args.progress:
            # sys.stdout.write("###%d"%c_li)
            # sys.stdout.flush()
            pass
        out_metrics.extend(sorted(metrics[d_l*sTep:lm+1], key=lambda st: int(st.split('::')[7]), reverse=True)[:top_count])
        port_metrics = sorted(out_metrics, key=lambda st: int(st.split('::')[7]), reverse=True)[:top_count]
    else:
        port_metrics = sorted(metrics, key=lambda st : int(st.split('::')[7]), reverse=True)[:top_count]
    #clear_previous_lines(1)
    if args.progress:
        sys.stdout.write('####')
        sys.stdout.flush()
    if args.key == None or args.key == 'IOPS':
        col_names = ["PORT", "VSAN|Initiator|Target|LUN", "Avg IOPS"]
    elif args.key == 'THPUT': 
        col_names = ["PORT", "VSAN|Initiator|Target|LUN", "Avg Throughput"]
    elif args.key == 'ECT':
        col_names = ["PORT", "VSAN|Initiator|Target|LUN", "ECT"]
    if args.alias:
        col_names.append("{0:^{width}}".format('Initiator Device alias', width=max_init_alias_len))
        col_names.append("{0:^{width}}".format('Target Device alias', width=max_targ_alias_len))
    t = PrettyTable(col_names)
    line_count = 4
    if args.key == 'THPUT':
        t = PrettyTable(col_names)
        row_val = [" ", " ", " Read   |   Write"]
    else:
        row_val = [" ", " ", "Read  |  Write"]

    if args.alias:
        row_val.extend(["", ""])

    t.add_row(row_val)

    for data in port_metrics:
        if args.alias:
            p, v, i, ta, l, r, w, to, ini_ali, tar_ali = data.split('::')
        else:
            p, v, i, ta, l, r, w, to = data.split('::')
        if args.key == 'THPUT':
            col_values = [p, "{}|{}|{}|{}".format(v, i, ta, l), "{0:^11}| {1:^10}".format(thput_conv(r), thput_conv(w))]
        elif args.key == 'ECT':
            col_values = [p, "{}|{}|{}|{}".format(v, i, ta, l), "{0:>8} |{1:^10}".format(time_conv(r), time_conv(w))]
        else:
            col_values = [p, "{}|{}|{}|{}".format(v, i, ta, l), "{0:^8}|{1:^8}".format(r, w)]

        if args.alias:
            t.align["{0:^{width}}".format('Initiator Device alias', width=max_init_alias_len)] = 'l'
            t.align["{0:^{width}}".format('Target Device alias', width=max_targ_alias_len)] = 'l'
            col_values.extend([str(ini_ali), str(tar_ali)])

        t.add_row(col_values)
        line_count += 1
    
    if args.progress:
        sys.stdout.write('')
        sys.stdout.flush()
    if return_vector[0] is not None:
        time.sleep(return_vector[1])
        clear_previous_lines(return_vector[0])
    line_count += 5
    if return_vector == [None, 2, None]:
        clear_previous_lines(1)
    if str1:
        print
        print str1
    if str2:
        print
        print str2
    print
    print datetime.datetime.now()
    print
    print t
    print
    if args.key == 'ECT':
        return [line_count, return_vector[1], pdata]
    else :
        return [line_count, return_vector[1], '']

def displayOutstandingIo(json_out, return_vector, ver=None):
    '''
    **********************************************************************************
    * Function: displayOutstandingIo
    *
    * Input: It takes 3 input 
    *           - json_out is the json data returned by switch as response for querry
    *           - return_vector is the list of 3 elements described as [ <lines to be deleted before printing new iteration result> <time to sleep between 2 iteration> <data from previous iteration>]
    *           - ver is software version of switch
    * Action: Displays Outstanding io per interface 
    * Returns: return_vector is the same one as described in Input
    **********************************************************************************
    '''
    global error
    global error_flag

    f_ports = getPureFPorts()
    port = args.interface
    if port not in f_ports:
        print "--outstanding-io is only supported on F Ports"
        return [None, return_vector[1], None]
        exit()
 
    line_count = 0
    str1 = None
    str2 = None
    if error_flag:
        str1 = error['getData_str']
        if 'empty'  in str1 or str1 == '':
            str1 = None
        else:
            line_count += error['line_count']
            line_count += 1

    col_names = ["Initiator|Target|LUN", "Outstanding IO"]
    json_out1 = getData(args, 1, ver)
    #print json_out

    if error_flag:
        str2 = error['getData_str']
        if 'empty' in str2 or str2 == '':
            str2 = None
        else:
            line_count += error['line_count']
            line_count += 1

    if json_out == ' ':
        if json_out1 is None:
            tmp_clr_line_count = 2
            if return_vector[0] != None:
                time.sleep(return_vector[1])
                clear_previous_lines(return_vector[0])
            else:
                clear_previous_lines(1)
            print
            print datetime.datetime.now()
            if str1 is not None:
                print
                print str1
            if (str2 is not None) and (str1 != str2):
                print 
                print str2
            if str1 == str2 and str1 != None:
                line_count -= (error['line_count']+1)
            tmp_clr_line_count += line_count
            if str1 == str2 == None:
                print "\n\t Table is empty\n"
                tmp_clr_line_count = 5
            return [tmp_clr_line_count, return_vector[1], '']
        else :
            json_out = json_out1
            json_out1 = None

    metrics = []
    while json_out:
        sizeJson = len(json_out['values'])
        counter = 1
        while counter <= sizeJson:
            iter_itl = json_out['values'][str(counter)]
            port, initiator, target, lun = [str(iter_itl.get(unicode(i), '')) for i in ['port', 'initiator_id', 'target_id', 'lun']]
            vsan = str(iter_itl.get(u'vsan',0))
            read, write = [int((iter_itl.get(unicode(i), 0))) for i in ['active_io_read_count', 'active_io_write_count']]
            counter += 1
            a = str(port) + '::' + str(vsan) + '::' + str(initiator) + '::' + str(target) + '::' + str(lun) \
                + '::' + str(read) + '::' + str(write)

            metrics.append(a)
        json_out = None

        if json_out1 is not None:
            json_out = json_out1
            json_out1 = None

    port_metrics = metrics

    if not return_vector[0]:
        flogis=[str(i) for i in flogi(cli.cli("sh flogi database interface {0} | ex '\-\-' | ex '^\s*$' | ex Tot | ex PORT".format(port))).get_fcids(port)]
        i, ta = [fcid_Normalizer(z) for z in port_metrics[0].split('::')[2:4]]
    
        fcns_type = None
        try :
            if i in flogis:
                fcns_type = 'Initiator'
            elif ta in flogis: 
                fcns_type = 'Target'
            else:
                fcns_type = 'NA'
        except:
            pass
        vSan =  metrics[0].split('::')[1]
        pdata = "\n Interface : {0}  VSAN : {1}  FCNS_type : {0}".format(port, vSan, fcns_type)
        print pdata

    t = PrettyTable(col_names)
    t.add_row([" ", "Read | Write"])
    t.add_row([" ", " "])
    line_count += 5

    qdpth = 0

    for data in port_metrics :
        p, v, i, ta, l, r, w = data.split('::')
        o = int(r)+int(w)
        qdpth += o
        line_count += 1
        t.add_row(["{0}|{1}|{2}".format(i, ta, l), "{0:^3} | {1:^3}".format(r, w)])
    # t.add_footer([[["Qdepth",str(qdpth)],[1,1],['l','l']]])
    # t.add_row(['Qdepth',qdpth])
    line_count += 4
    if return_vector[0] is not None:
        time.sleep(return_vector[1])
        clear_previous_lines(return_vector[0])
    if return_vector[0] is not None:
        clear_previous_lines(2)
        print datetime.datetime.now()
    if return_vector[2]:
        pdata = return_vector[2]
        print pdata
    print
    print t
    if args.limit == max_flow_limit:
        print "", 'Instantaneous Qdepth :', qdpth
        line_count += 1
    print 
    return [line_count, return_vector[1], pdata]

def getSwVersion():
    '''
    **********************************************************************************
    * Function: getSwVersion
    *
    * Action: Get current Software version
    * Returns: String as software version of the switch
    **********************************************************************************
    '''
    try:
        out = cli.cli('sh ver  | i version | i syst').strip()
        ver = out.split(' ')[-1]
        return ver
    except Exception as e:
        return None


def getData(args, misc=None, ver=None):
    '''
    **********************************************************************************
    *  Function: getData
    *
    *  Input: It takes 3 inputs:
    *           - args is global Object of Argparse Class
    *           - misc which is default to none is to accomodate some operation as described below
    *           - ver is software version number
    *  misc
    *  0 : default
    *  1 : run target querry this time for outstanding_io,top and histogram
    *
    *  Action: Forms a query based on args and misc , run the query on the switch and get json response and convert it into dict and return 
    *
    *  Returns: json_out which is json format of data 
    **********************************************************************************
    '''

    trib,twib,tric,twic = 'total_time_metric_based_read_io_bytes','total_time_metric_based_write_io_bytes','total_time_metric_based_read_io_count','total_time_metric_based_write_io_count'
    if ver == '8.3(1)':
        trib,twib,tric,twic = 'total_read_io_bytes','total_write_io_bytes','total_read_io_count','total_write_io_count'
        
        
    table_name = ''
    global interface_list

    if args.evaluate_npuload:
        if misc == None:
            return None
        else:
            port, q_type = misc
            if q_type == 'nvme':
                query = "select nvme_initiator_itn_flow_count, nvme_target_itn_flow_count, read_io_rate, write_io_rate from fc-nvme.port where port={}".format(port)
            else:
                query = "select scsi_initiator_itl_flow_count, scsi_target_itl_flow_count, read_io_rate, write_io_rate from fc-scsi.port where port={}".format(port)

    if args.initiator_itl or args.target_itl or args.initiator_it or args.target_it:
        lun_field = '' if (args.initiator_it or args.target_it) else 'lun,'
        if args.initiator_itl:
            table_name = 'scsi_initiator_itl_flow'
        elif args.target_itl:
            table_name = 'scsi_target_itl_flow'
        elif args.initiator_it:
            table_name = 'scsi_initiator_it_flow'
        elif args.target_it:
            table_name = 'scsi_target_it_flow'
        # table_name = 'scsi_initiator_itl_flow' ; #CSCvn26029 also added 4 line below
        if args.target and args.initiator and args.lun:
            query = "select port, vsan, initiator_id, target_id, {lun} read_io_rate, write_io_rate, read_io_bandwidth, write_io_bandwidth, read_io_size_min, read_io_size_max, {0}, {2}, write_io_size_min, write_io_size_max, {1}, {3}, read_io_initiation_time_min, read_io_initiation_time_max, total_read_io_initiation_time, write_io_initiation_time_min, write_io_initiation_time_max, total_write_io_initiation_time, read_io_completion_time_min, read_io_completion_time_max, total_read_io_time, write_io_completion_time_min, write_io_completion_time_max, total_write_io_time, read_io_inter_gap_time_min, read_io_inter_gap_time_max, total_read_io_inter_gap_time, write_io_inter_gap_time_min, write_io_inter_gap_time_max, total_write_io_inter_gap_time, read_io_aborts, write_io_aborts, read_io_failures, write_io_failures, peak_read_io_rate, peak_write_io_rate, peak_read_io_bandwidth, peak_write_io_bandwidth from fc-scsi.{fc_table}".format(trib,twib,tric,twic,lun=lun_field, fc_table=table_name)
        else :
            if args.minmax:
                query = "select port,vsan,initiator_id,target_id,{lun}peak_read_io_rate,peak_write_io_rate,peak_read_io_bandwidth,peak_write_io_bandwidth,read_io_completion_time_min,read_io_completion_time_max,write_io_completion_time_min,write_io_completion_time_max,read_io_rate,write_io_rate,read_io_bandwidth,write_io_bandwidth,total_read_io_time,total_write_io_time,{2},{3},read_io_aborts,write_io_aborts,read_io_failures,write_io_failures from fc-scsi.{fc_table}".format(trib,twib,tric,twic, lun=lun_field, fc_table=table_name)
            else:
                if misc is None:
                    # consider case of args.error also
                    query = "select port,vsan,initiator_id,target_id,{lun} total_read_io_time,total_write_io_time,{2},{3},read_io_aborts,write_io_aborts,read_io_failures,write_io_failures from fc-scsi.{fc_table}".format(trib,twib,tric,twic, lun=lun_field, fc_table=table_name)
                else:
                    query = "select port,vsan,initiator_id,target_id,{lun}read_io_rate,write_io_rate,read_io_bandwidth,write_io_bandwidth,total_read_io_time,total_write_io_time,{2},{3},read_io_aborts,write_io_aborts,read_io_failures,write_io_failures from fc-scsi.{fc_table}".format(trib,twib,tric,twic, lun=lun_field, fc_table=table_name)


    # query = "select all from fc-scsi." + table_name ; #CSCvn26029
    if args.vsan_thput:
        query = "select port, vsan, read_io_bandwidth, write_io_bandwidth, read_io_size_min, write_io_size_min, read_io_rate, write_io_rate from fc-scsi.logical_port"
    if args.top:
        if args.interface is not None:
            pcre = re.match('port-channel(\d+)',args.interface)
            if pcre is not None:
                print "Port channel is not supported by --top option"
                exit()
        if args.key is None or args.key == 'IOPS':
           wkey = ['read_io_rate', 'write_io_rate']
        if args.key == 'THPUT':
           wkey = ['read_io_bandwidth', 'write_io_bandwidth']
        if args.key == 'ECT':
           wkey = ['total_time_metric_based_read_io_count', 'total_time_metric_based_write_io_count', 'total_read_io_time','total_write_io_time']
        if not misc:
            query = "select port, vsan, initiator_id, target_id, lun"
            for jj in wkey:
                query = query + ',' + str(jj)
            query = query + " from fc-scsi.scsi_initiator_itl_flow"
        elif misc == 1:
            query = "select port, vsan, initiator_id, target_id, lun"
            for jj in wkey:
                query = query + ',' + str(jj)
            query = query + " from fc-scsi.scsi_target_itl_flow"
        else:
            return None

    if args.outstanding_io:
        pcre = re.match('port-channel(\d+)', args.interface)
        if pcre != None:
            print "Port channel is not supported by --outstanding-io option"
            exit()
        if not misc:
            query = "select port, vsan, initiator_id, target_id, lun,active_io_read_count, active_io_write_count from fc-scsi.scsi_initiator_itl_flow"
        else:
            query = "select port, vsan, initiator_id, target_id, lun, active_io_read_count, active_io_write_count from fc-scsi.scsi_target_itl_flow"

    filter_count = 0
    filters = {'interface': 'port', 'target': 'target_id', 'initiator': 'initiator_id', 'lun': 'lun', 'vsan': 'vsan'}

    for key in filters.keys():
        if hasattr(args, key) and getattr(args, key):
            if filter_count == 0: 
                query += " where "
            else :
                query += " and "
            filter_count += 1
            query += filters[key] + "=" + getattr(args, key)

    json_str = ""

    query += " limit "+str(args.limit)
    try:
        json_str = cli.cli("show analytics query '" + query + "'")
    except cli.cli_syntax_error:
        pass
    
    json_out = None

    global error
    global error_flag

    try:
        json_out = json.loads(json_str)
    except ValueError, e:
        error['getData_str'] =  json_str
        json_out = None
        error_flag = True
        error['line_count'] = len(json_str.split('\n')) + 1
        json_out = None
    except MemoryError:
        error['getData_str']="Querry Output Too Huge to be processed"
        json_out = None
        error_flag = True
        error['line_count'] = 1
        if args.histogram:
           if misc_opt == 0:
               return getData(args, 1) 

    return json_out


def print_util_help(self):
    print '''
ShowAnalytics   --errors <options> | --errorsonly <options> | --evaluate-npuload <options> | --help | --info <options> | --minmax <options> | --outstanding-io <options> | --top <options> | --version |  --vsan-thput <options> 
 
 
OPTIONS :
---------
 
 --errors                 Provides error metrics for all ITLs
                          ShowAnalytics --errors [--initiator-itl <args> | --target-itl <args>]
 
      --initiator-itl         Provides errors metrics for initiator ITLs
                              Args :  [--interface <interface>] [--initiator <initiator_fcid>] [--target <target_fcid>] [--lun <lun_id>] [--alias] [--limit <itl_limit>]
      --target-itl            Provides errors metrics for target ITLs
                              Args :  [--interface <interface>] [--initiator <initiator_fcid>] [--target <target_fcid>] [--lun <lun_id>] [--alias] [--limit <itl_limit>]
      --initiator-it          Provides errors metrics for initiator ITs
                              Args :  [--interface <interface>] [--initiator <initiator_fcid>] [--target <target_fcid>] [--alias] [--limit <itl_limit>]
      --target-it             Provides errors metrics for target ITs
                              Args :  [--interface <interface>] [--initiator <initiator_fcid>] [--target <target_fcid>] [--alias] [--limit <itl_limit>]
     
 --errorsonly             Provides error metrics for ITLs. Only display ITLs with non-zero errors.
                          ShowAnalytics --errorsonly [--initiator-itl <args> | --target-itl <args>]
 
      --initiator-itl         Provides errors metrics for initiator ITLs
                              Args :  [--interface <interface>] [--initiator <initiator_fcid>] [--target <target_fcid>] [--lun <lun_id>] [--alias]
      --target-itl            Provides errors metrics for target ITLs
                              Args :  [--interface <interface>] [--initiator <initiator_fcid>] [--target <target_fcid>] [--lun <lun_id>] [--alias]
      --initiator-it          Provides errors metrics for initiator ITs
                              Args :  [--interface <interface>] [--initiator <initiator_fcid>] [--target <target_fcid>] [--alias] [--limit <itl_limit>]
      --target-it             Provides errors metrics for target ITs
                              Args :  [--interface <interface>] [--initiator <initiator_fcid>] [--target <target_fcid>] [--alias] [--limit <itl_limit>]

 --evaluate-npuload       Provides per port NPU load
                          This option must be run without analytics interface configurations
                          Args :  [--module <mod1,mod2> | --interface <int1,int2>]
                          Provides system wide data if --module and --interface arguments are not present

 --help                   Provides help about this utility

 --info                   Provide information about ITLs
                          ShowAnalytics --info [--initiator-itl <args> | --target-itl <args>] 
 
      --initiator-itl         Provides ITL view for initiators ITLs
                              Args :  [--interface <interface>] [--initiator <initiator_fcid>] [--target <target_fcid>] [--lun <lun_id>] [--alias] [--limit <itl_limit>]
      --target-itl            Provides IT view for target  ITs
                              Args :  [--interface <interface>] [--initiator <initiator_fcid>] [--target <target_fcid>] [--lun <lun_id>] [--alias] [--limit <itl_limit>]
      --initiator-it          Provides IT view for initiators ITs
                              Args :  [--interface <interface>] [--initiator <initiator_fcid>] [--target <target_fcid>] [--lun <lun_id>] [--alias] [--limit <itl_limit>]
      --target-it             Provides IT view for target  ITs
                              Args :  [--interface <interface>] [--initiator <initiator_fcid>] [--target <target_fcid>]d>] [--alias] [--limit <itl_limit>]

 --minmax                 Provide Min/Max/Peak values of ITLs
                          ShowAnalytics --minmax [--initiator-itl <args> | --target-itl <args>] 
 
      --initiator-itl         Provides ITL view for initiators ITLs
                              Args :  [--interface <interface>] [--initiator <initiator_fcid>] [--target <target_fcid>] [--lun <lun_id>] [--alias] [--limit <itl_limit>]
      --target-itl            Provides ITL view for target  ITLs
                              Args :  [--interface <interface>] [--initiator <initiator_fcid>] [--target <target_fcid>] [--lun <lun_id>] [--alias] [--limit <itl_limit>]
      --initiator-it          Provides IT view for initiators ITs
                              Args :  [--interface <interface>] [--initiator <initiator_fcid>] [--target <target_fcid>] [--lun <lun_id>] [--alias] [--limit <itl_limit>]
      --target-it             Provides IT view for target  ITs
                              Args :  [--interface <interface>] [--initiator <initiator_fcid>] [--target <target_fcid>]d>] [--alias] [--limit <itl_limit>]
 
 --outstanding-io         Provides Outstanding io per ITL for an interface
                          Args : [--interface <interface>] [--initiator <initiator_fcid>] [--target <target_fcid>] [--lun <lun_id>] [--limit] [--refresh]
 
 --top                    Provides top ITLs based on key. Default key is IOPS
                          Args : [--interface <interface>] [--initiator <initiator_fcid>] [--target <target_fcid>] [--lun <lun_id>] [--limit] [--key <IOPS|THPUT|ECT>] [--progress] [--alias]

 --version                Provides version details of this utility

 --vsan-thput             Provides per vsan scsi traffic rate for interface.
                          Args : [--interface <interface>]

ARGUMENTS:
---------
 
      --alias                                 Prints device-alias for initiator and target. Terminal Emulator should support 511 width size.
      --initiator         <initiator_fcid>    Specifies initiator FCID in the format 0xDDAAPP
      --interface         <interface>         Specifies Interface in format module/port
      --key               <iops|thput|ect>    Defines the key value for the --top option
      --limit             <itl_limit>         Maximum number of ITL records to display. Valid range 1-{flow_limit}. Default = {flow_limit}
      --lun               <lun_id>            Specifies LUN ID in the format XXXX-XXXX-XXXX-XXXX
      --module            <mod1,mod2>         Specifies module list for --evaluate-npuload option example 1,2
      --progress                              Provides progress for --top option. Should not be used on console
      --refresh                               Refreshes output of --outstanding-io
      --target            <target_fcid>       Specifies target FCID in the format 0xDDAAPP
      --vsan              <vsan_number>       Specifies vsan number

Note: --interface can take range of interfaces in case of --evaluate-npuload and port-channel only in case of --vsan-thput
'''.format(flow_limit=max_flow_limit)
    return True

argparse.ArgumentParser.print_help = print_util_help

# argument parsing
parser = argparse.ArgumentParser(prog='ShowAnalytics', description='ShowAnalytics')
parser.add_argument('--version', action='version', help='version', version='%(prog)s 2.1.0')
parser.add_argument('--info', action="store_true", help='--info | --errors mandatory')
parser.add_argument('--minmax', action="store_true", help='Displays Min/Max/Peak ITL view')
parser.add_argument('--errors', action="store_true", help='--info | --errors mandatory')
parser.add_argument('--errorsonly', action="store_true", help='--info | --errors | --errorsonly  mandatory')
parser.add_argument('--vsan-thput', action="store_true",help=' To display per vsan traffic rate for interface')
parser.add_argument('--initiator-it', action="store_true", help='--initiator-it | --target-it mandatory')
parser.add_argument('--target-it', action="store_true", help='--initiator-it | --target-it mandatory')
parser.add_argument('--initiator-itl', action="store_true", help='--initiator-itl | --target-itl mandatory')
parser.add_argument('--target-itl', action="store_true", help='--initiator-itl | --target-itl mandatory')
parser.add_argument('--interface', dest="interface", help='fc interface')
parser.add_argument('--vsan', dest="vsan", help='vsan')
parser.add_argument('--target', dest="target", help='target FCID')
parser.add_argument('--initiator', dest="initiator", help='initiator FCID')
parser.add_argument('--lun', dest="lun", help='lun')
parser.add_argument('--limit', dest="limit", help='Maximum number of ITL records to display. Valid range 1-{flow_limit}. Default = {flow_limit}'.format(flow_limit=max_flow_limit), default=max_flow_limit)
parser.add_argument('--alias', action="store_true", help='--alias print device-alias info')
parser.add_argument('--evaluate-npuload', action="store_true", help='To Display per port NPU load')
parser.add_argument('--module', dest="module", help='module list')
parser.add_argument('--top', action="store_true",help='Display Top ITL based on the key specified')
parser.add_argument('--key', dest="key",help='iops or thput or ect | --top mandatory')
parser.add_argument('--progress', action="store_true",help="Show progress")
parser.add_argument('--outstanding-io', action="store_true",help=' To display outstanding io per interface')
parser.add_argument('--refresh', action="store_true",help='Auto refresh')
#parser.add_argument('--intlist',dest="intlist", help='int_list')

args = parser.parse_args()

if not validateArgs (args):
    os._exit(1) 
    
sw_ver = getSwVersion()
if sw_ver is None:
    print 'Unable to get Switch software version'
    os._exit(1)

date = datetime.datetime.now()
if not args.errorsonly:
    print date

json_out = getData(args, ver=sw_ver)

if not json_out and (args.top or args.outstanding_io):
    json_out = ' '
if not json_out and not args.evaluate_npuload:
    if error_flag and 'empty' not in error['getData_str']:
        if error['getData_str'] == '':
            print "\n\t Table is empty\n"
        else:
            print error['getData_str']
    else:
        print "\n\t Table is empty\n"
else :
    if args.info:
        if args.target and args.initiator and args.lun:
            displayDetailOverlay(json_out, ver=sw_ver)
        else:
            displayFlowInfoOverlay(json_out, ver=sw_ver)

    if args.errors or args.errorsonly:
        displayErrorsOverlay(json_out, date, ver=sw_ver)

    elif args.minmax: 
        displayFlowInfoOverlay(json_out, ver=sw_ver)

    elif args.evaluate_npuload:
        displayNpuloadEvaluation(json_out, ver=sw_ver)

    elif args.vsan_thput:
        displayVsanOverlay(json_out, ver=sw_ver)

    elif args.top:
        return_vector = displayTop(args, json_out, [None,2,None], ver=sw_ver)
        while (not(return_vector[0] is None  and return_vector[2] is None) ):
            json_out = getData(args, ver=sw_ver)
            if not json_out:
                json_out = ' '
            return_vector = displayTop(args, json_out, return_vector, ver=sw_ver)
    elif args.outstanding_io:
        return_vector = displayOutstandingIo(json_out, [None, 1, None], ver=sw_ver)
        if args.refresh:
            while (not(return_vector[0] is None  and return_vector[2] is None) ):
                json_out = getData(args, ver=sw_ver)
                if not json_out:
                    json_out = ' '
                return_vector = displayOutstandingIo(json_out, return_vector, ver=sw_ver)
