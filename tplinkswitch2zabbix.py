#!/usr/bin/python3
#######################################################################################
# @author: Guille Rodriguez https://github.com/guillerg86
# @version: 2024-03-02 20:55
# @python-version: 3.x
#
# Script for monitor with Zabbix device like TL-SG108E (which doesn't have SNMP)
# just web. Care, if there are other users connected, when this script connect
# maybe one of them will be session disconnected (logout).
#
# Tested on:
# - TL-SG108E v6.0 with 20201208 and 20230218 firmware
# - TL-SG108E v3.0 with 20171214 firmware
#######################################################################################
import json
import re
import requests
import argparse
from ipaddress import ip_address

class SwitchPort:
    def __init__(self):
        self.port_number = 0
        self.admin_status = 0
        self.trunk_status = 0
        self.operation_status = 0
        self.speed_config = 0
        self.speed_actual = 0
        self.speed_bps = 0
        self.flowcontrol_config = 0
        self.flowcontrol_actual = 0
        self.transmitted_packets = 0
        self.transmitted_packets_error = 0
        self.received_packets = 0
        self.received_packets_error = 0


class TPLinkSwitch:
    def __init__(self):
        self.firmware = None
        self.hardware = None
        self.description = None
        self.mac_address = None
        self.ip_address = None
        self.netmask = None
        self.gateway = None
        self.port_number = 0
        self.ports = []

class DAOSwitchTPLink():

    def __init__(self):
        self.switch = TPLinkSwitch()
        self.ip_address = None
        self.username = None
        self.password = None
        self.login_response_code = 200

    def get_switch(self):
        return self.switch

    def get_base_url(self):
        return f"http://{str(self.ip_address)}/"

    def do_login(self):
        url_login = self.get_base_url() + "logon.cgi"
        data = {
            'username': self.username,
            'password': self.password,
            'logon': 'Login'
        }
        session = requests.Session()
        resp = session.post(url_login, data=data)
        if resp.status_code == self.login_response_code:
            return session
        else:
            raise Exception(f"Error: HTTP Status code: {str(resp.status_code)}")
    def load_sysinfo(self, session):
        response = session.get(self.get_base_url() + "SystemInfoRpm.htm")

        pattern_rawdata = re.compile(r"var info_ds = ({\n?(.*?)\n?});$", re.MULTILINE | re.DOTALL)
        data = pattern_rawdata.search(response.text)
        raw_data = data.group(1).replace("\n", "")

        pattern_values = re.compile(r"[a-zA-z]+:\[\"([a-zA-Z0-9\.\s\-:]+)\"\]")
        values = pattern_values.findall(raw_data)

        self.switch.description = values[0]
        self.switch.mac_address = values[1]
        self.switch.ip_address = values[2]
        self.switch.netmask = values[3]
        self.switch.gateway = values[4]
        self.switch.firmware = values[5]
        self.switch.hardware = values[6]


    def __get_portsinfo_values_from_raw(self,key,rawdata):
        pattern = re.compile(key+":\\[([\\d,]+)\\]", re.MULTILINE | re.DOTALL)
        return pattern.search(rawdata).group(1).split(",")

    def load_portsinfo(self, session):

        speed_actual_to_bps_translate_table = {
            "0": 0,
            "1": 0,
            "2": 10 * 1000 * 1000,
            "3": 10 * 1000 * 1000,
            "4": 100 * 1000 * 1000,
            "5": 100 * 1000 * 1000,
            "6": 1000 * 1000 * 1000
        }

        resp_port_settings = session.get(self.get_base_url() + "PortSettingRpm.htm")
        resp_port_monitor = session.get(self.get_base_url() + "PortStatisticsRpm.htm")

        pattern_portnum = re.compile(r"var max_port_num = (\d+);")
        self.switch.port_number = int(pattern_portnum.search(resp_port_settings.text).group(1))

        pattern_allinfo = re.compile(r"var all_info = {(\n?(.*?)\n?)};", re.MULTILINE | re.DOTALL)
        ports_config_raw = pattern_allinfo.search(resp_port_settings.text).group(1)

        admin_status = self.__get_portsinfo_values_from_raw("state",ports_config_raw)
        trunk_status = self.__get_portsinfo_values_from_raw("trunk_info",ports_config_raw)
        speed_config = self.__get_portsinfo_values_from_raw("spd_cfg",ports_config_raw)
        speed_actual = self.__get_portsinfo_values_from_raw("spd_act",ports_config_raw)
        flowc_config = self.__get_portsinfo_values_from_raw("fc_cfg",ports_config_raw)
        flowc_actual = self.__get_portsinfo_values_from_raw("fc_act",ports_config_raw)
        packets_info = self.__get_portsinfo_values_from_raw("pkts", resp_port_monitor.text)
        # Link status on PortStatistics is the same as speed_actual in PortSettings
        # link_status = self.__get_portsinfo_values_from_raw("link_status", resp_port_monitor.text)

        self.switch.ports = [SwitchPort() for i in range(self.switch.port_number)]

        # Getting info of each port
        for i in range(self.switch.port_number):
            self.switch.ports[i].port_number = i+1
            self.switch.ports[i].admin_status = admin_status[i]
            self.switch.ports[i].trunk_status = trunk_status[i]
            self.switch.ports[i].speed_config = speed_config[i]
            self.switch.ports[i].speed_actual = speed_actual[i]
            self.switch.ports[i].speed_bps = speed_actual_to_bps_translate_table[speed_actual[i]]
            self.switch.ports[i].operation_status = 1 if int(speed_actual[i]) > 0 else 0
            self.switch.ports[i].flowcontrol_config = flowc_config[i]
            self.switch.ports[i].flowcontrol_actual = flowc_actual[i]
            self.switch.ports[i].transmitted_packets = packets_info[i*4]
            self.switch.ports[i].transmitted_packets_error = packets_info[i*4+1]
            self.switch.ports[i].received_packets = packets_info[i*4+2]
            self.switch.ports[i].received_packets_error = packets_info[i*4+3]

class DAOSwitchTPLink_v3(DAOSwitchTPLink):
    def __init__(self):
        super().__init__()
        self.login_response_code = 401

class DAOSwitchTPLink_v6(DAOSwitchTPLink):
    def __init__(self):
        super().__init__()



def configure_parser():
    """
    Configure arguments of this script
    :return:
    """
    # Configure parser
    parser = argparse.ArgumentParser(
        prog="TP-Link SG108E to Zabbix",
        description="Export information from website to Zabbix"
    )
    parser.add_argument('-a', '--action', required=True, help="sysinfo/discovery/portinfo/allinfo",
                        choices=["sysinfo", "discovery", "portinfo", "allinfo"])
    parser.add_argument('-i', '--ip-address', required=True, type=ip_address)
    parser.add_argument('-u', '--username', required=True)
    parser.add_argument('-p', '--password', required=True)
    parser.add_argument('--port-number',required=False, type=int, default=-1)
    parser.add_argument('-hv','--hardware-version', required=False, type=int, default=6)
    args = parser.parse_args()
    args.action = args.action.lower()
    return args

def get_dao_version(version):
    if version == 3:
       return DAOSwitchTPLink_v3()
    return DAOSwitchTPLink_v6()

if __name__ == '__main__':
    args = configure_parser()
    dao = get_dao_version(args.hardware_version)

    dao.ip_address = args.ip_address
    dao.username = args.username
    dao.password = args.password

    if args.action == "sysinfo":
        session = dao.do_login()
        dao.load_sysinfo(session)
        switch = dao.get_switch()
        print(json.dumps(switch.__dict__,indent=4))
    elif args.action == "discovery":
        session = dao.do_login()
        dao.load_portsinfo(session)
        switch = dao.get_switch()
        print(json.dumps({"interfaces": [ {
            "{#JSON.INDEX}": index,
            "{#IFNUMBER}": port.port_number,
            "{#IFADMINSTATUS}": port.admin_status
        } for index, port in enumerate(switch.ports)]},indent=4))
    elif args.action == "portinfo":
        if args.port_number <= 0:
            print("Error: Port need to be bigger than 0. (1 <-> MAX_PORTS)")
            exit(3)
        session = dao.do_login()
        dao.load_portsinfo(session)
        switch = dao.get_switch()
        if args.port_number > len(switch.ports):
            print(f"Error: Port needs to be between 1 and {str(len(switch.ports))} (max-ports of this switch)")
            exit(4)
        # Substract 1 to number sent, port 1 is on position 0 of the array
        port = switch.ports[args.port_number - 1]
        print(json.dumps(port.__dict__,indent=4))
    elif args.action == "allinfo":
        session = dao.do_login()
        dao.load_sysinfo(session)
        dao.load_portsinfo(session)
        switch = dao.get_switch()
        # Converting object ports to dict
        switch.ports = [vars(port) for port in switch.ports]
        print(json.dumps(vars(switch), indent=4))

