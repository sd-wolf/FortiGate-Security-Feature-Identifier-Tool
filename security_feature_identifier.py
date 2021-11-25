import argparse
from argparse import RawTextHelpFormatter
import requests
import urllib3
import json
import configparser
import os.path
import pandas as pd
from tabulate import tabulate

"""
FortiGate Security Feature Identifier Tool.
Written by Sean Wolf, Systems Engineer, Fortinet, November 2021

This tool was written to assist customers identify the security features enabled across a FortiGate estate.

The tool relies on manual input of FortiGate details or a config file 'config.ini' containing an entry for each FortiGate to analyse.

The config file format is defined as:
   [FortiGateName]
   address=<FortiGate address>
   api_key=<FortiGate API key>
   port=<FortiGate HTTPS port>

Each FortiGate entry must have a unique name, i.e. Hostname.

It will use a series of API calls to each FortiGate to gather the necessary image, which can be a very large amount on larger installations.

Once completed it will output the results of the analysis to the screen, and save the results to a CSV file: security_features.csv

"""


urllib3.disable_warnings()
payload={}
headers = {}
fortigates = []
config_filename = 'config.ini'
csv_name = 'security_features.csv'

def import_config():
    """
    This function is used to import the config file, or if the config file is not present, prompt the user for the FortiGate details.
    """
    print('')
    print('-------------------------------------------------------')
    if os.path.isfile(config_filename):
        print('FortiGate configuration file exists. Using for parsing.')
        configParser = configparser.RawConfigParser()
        configFilePath = config_filename
        configParser.read(configFilePath)
        for x in configParser.sections():
            fortigates.append({'address': configParser.get(x, 'address'), 'api_key': configParser.get(x, 'api_key'), 'port': configParser.get(x, 'port')})
    else:
        print('No config file exists, prompting for credentials.')
        fortigate_input = input('Enter FortiGate IP/FQDN address: ')
        api_input = input('Enter FortiGate API key: ')
        port_input = input('Enter FortiGate HTTPS port: ')
        fortigate_details = [[fortigate_input, api_input]]
        fortigates.append({'address': fortigate_input, 'api_key': api_input, 'port': port_input})
    print('-------------------------------------------------------')
    print('')

def get_fortigate_hostname(address, token, port):
    """
    This function is used to grab details about a FortiGate, such as: hostname, firmware version, and vdom names. The result is then returned.
    """
    vdoms = []
    version_url = 'https://' + address + ':' + port + '/api/v2/monitor/system/status?access_token=' + token
    hostname_url = 'https://' + address + ':' + port + '/api/v2/cmdb/system/global?access_token=' + token
    vdom_url = 'https://' + address + ':' + port + '/api/v2/cmdb/system/vdom?access_token=' + token
    try:
        version_response = json.loads(requests.request("GET", version_url, headers=headers, data=payload, verify=False).text)['version']
    except Exception as e:
        print(e)
    try:
        hostname_response = json.loads(requests.request("GET", hostname_url, headers=headers, data=payload, verify=False).text)['results']['hostname']
    except Exception as e:
        print(e)
    try:
        vdom_response = json.loads(requests.request("GET", vdom_url, headers=headers, data=payload, verify=False).text)['results']
        for x in vdom_response:
            vdoms.append(x['name'])
    except Exception as e:
        print(e)
    return {'hostname': hostname_response, 'version': version_response, 'vdoms': vdoms} 

def check_object_usage(address, token, qpath, qname, mkey, port='443', vdom=None):
    """
    This function is passed an object name, such as a webfiltering profile, and then queries where the object is used in the FortiGate and returns the results.
    """
    if vdom is None:
        vdom = 'vdom=*'
    check_url = 'https://' + address + ':' + port + '/api/v2/monitor/system/object/usage?vdom=' + vdom +'&q_path=' + qpath + '&q_name=' + qname + '&mkey=' + mkey + '&access_token=' + token
    try:
        response = json.loads((requests.request("GET", check_url, headers=headers, data=payload, verify=False)).text)
    except Exception as e:
        print(e)
    used_where = []
    used_count = 0
    for x in response['results']['currently_using']:
        if x['vdom'] == vdom:
            if response['mkey'] != 'no-inspection':
                used_where.append({'vdom': x['vdom'], 'path': x['path'], 'name': x['name'], 'attribute': x['attribute'], 'mkey': x['mkey']})
                used_count += 1
    used_response = {'used_count': used_count, 'used_where': used_where}
    return used_response

def check_security_feature(address, token, qpath, qname, port='443', vdom=None):
    """
    This function is passed a security feature to test, i.e. antivirus, and then gets a list of names of the security feature.
    It then iterates through the list of names and calls the check_object_usage function on each to determine where each name is used.
    It then returns the resulting list of names and where they are used.
    """
    if vdom is None:
        vdom = 'vdom=*'
    else:
        vdom = 'vdom=' + vdom
    check_url = 'https://' + address + ':' + port + '/api/v2/cmdb/' + qpath + '/' + qname + '?' + vdom + '&access_token=' + token
    try:
        response = json.loads((requests.request("GET", check_url, headers=headers, data=payload, verify=False)).text)
    except Exception as e:
        print(e)
    return_results = []
    for x in response:
        return_vdom_results = []
        for y in x['results']:
            try:
                check_profile = check_object_usage(address, token, qpath, qname, y['name'], port, x['vdom'])
            except Exception as e:
                print(e)
            return_vdom_results.append({'name': y['name'], 'used': check_profile})
        return_results.append({'vdom': x['vdom'], 'results': return_vdom_results})
    return return_results


def collect_config():
    """
    This function iterates through the list of FortiGates provided by the config.ini or the user.
    For each FortiGate it calls the check_security_features function for each security function to get back a list of the objects for that function,
    and where they are used. It then compiles this information into a single response.
    """
    fgt_config_output = []
    for x in fortigates:
        try:
            fortigate_details = get_fortigate_hostname(x['address'], x['api_key'], port=x['port'])
            print('Collecting config from: ' + x['address'])
            antivirus = check_security_feature(x['address'], x['api_key'], 'antivirus', 'profile', port=x['port'])
            webfilter = check_security_feature(x['address'], x['api_key'], 'webfilter', 'profile', port=x['port'])
            if 'v7' in fortigate_details['version']:
                vidfilter = check_security_feature(x['address'], x['api_key'], 'videofilter', 'profile', port=x['port'])
            else:
                vidfilter = [{'vdom': 'root', 'results': []}]
            dnsfilter = check_security_feature(x['address'], x['api_key'], 'dnsfilter', 'profile', port=x['port'])
            appcontrl = check_security_feature(x['address'], x['api_key'], 'application', 'list', port=x['port'])
            ipssensor = check_security_feature(x['address'], x['api_key'], 'ips', 'sensor', port=x['port'])
            dlpsensor = check_security_feature(x['address'], x['api_key'], 'dlp', 'sensor', port=x['port'])
            sslinspec = check_security_feature(x['address'], x['api_key'], 'firewall', 'ssl-ssh-profile', port=x['port'])
            fgt_config_output.append({'hostname': fortigate_details['hostname'], 'version': fortigate_details['version'], 'address': x['address'], 'vdoms': fortigate_details['vdoms'], 'antivirus': antivirus,'webfilter': webfilter, 'videofilter': vidfilter, 'dnsfilter': dnsfilter, 'appcontrol': appcontrl, 'ips': ipssensor, 'dlp': dlpsensor, 'ssl': sslinspec})
        except Exception as e:
            print(e)
    print('')
    return fgt_config_output

def confirm_usage(security, vdom):
    """
    This function takes the input results, and then uses it to determine whether the security feature is enabled, and returns Yes or No.
    Note: There is a small issue identified with profiles with the name 'g-wifi-default' and 'wifi-default', these have been excluded from results.
    """
    security_used = 'No'
    used_count = 0
    for x in security:
        if x['vdom'] == vdom:
            for y in x['results']:
                used_count = y['used']['used_count']
                if 'wifi-default' in y['name']:
                    for z in y['used']['used_where']:
                        if (z['path'] == 'wireless-controller' and z['name'] == 'utm-profile'):
                            used_count = -1
                if used_count > 0:
                    security_used = 'Yes'
        used_count = 0
    return security_used

def create_output(fgt_config_output):
    """
    This function takes the results of all the FortiGates from collect_config, and for each FortiGate, uses the confirm_usage function to determine
    if the security feature is enabled for each security feature. 

    It then outputs a table for each FortiGate whether the feature is enabled or not, and the same table in a CSV file called 'security_features.csv'.
    """
    print('-----------------------------------')
    print('|    FortiGate Security Report    |')
    print('-----------------------------------')
    print('')
    full_output = []
    full_df = pd.DataFrame()
    for x in fgt_config_output:
        fg_details = []
        security_output = []
        for y in x['vdoms']:
            av_security = confirm_usage(x['antivirus'], y)
            wf_security = confirm_usage(x['webfilter'], y)
            if 'v7' in x['version']:
                vf_security = confirm_usage(x['videofilter'], y)
            else:
                vf_security = 'N/A'
            dns_security = confirm_usage(x['dnsfilter'], y)
            ac_security = confirm_usage(x['appcontrol'], y)
            ips_security = confirm_usage(x['ips'], y)
            dlp_security = confirm_usage(x['dlp'], y)
            ssl_security = confirm_usage(x['ssl'], y)
            security_output.append({'VDOM': y,'Anti-Virus': av_security, 'Web Filtering': wf_security, 'Video Filtering': vf_security, 'DNS Filtering': dns_security, 'Application Control': ac_security, 'Intrusion Prevention': ips_security, 'Data Leak Prevention': dlp_security, 'SSL/SSH Inspection': ssl_security})
        full_output.append({'hostname': x['hostname'], 'version': x['version'], 'address': x['address'] ,'security': security_output})
        fg_details.append({'FortiGate': x['hostname'], 'Version': x['version'], 'Address': x['address']})
        fg_df = pd.DataFrame(fg_details)
        security_df = pd.DataFrame(security_output)
        print(tabulate(fg_df, showindex=False, headers=fg_df.columns))
        print('')
        print(tabulate(security_df, showindex=False, headers=security_df.columns))
        print('')
        print('----------------------------------------------------------------------------------------------------------------------------------------------------------------------')
        print('')
        full_df = full_df.append(fg_df).append(security_df).fillna('')
    full_df.to_csv(csv_name, index=False)

def main():
    """
    The main function that calls all the functions.
    """
    parser = argparse.ArgumentParser(description='\033[1;37;40mFortiGate Security Feature Identifier.\n\033[1;34;40mWritten by Sean Wolf, Systems Engineer, \033[1;31;40mFortinet\033[1;34;40m, November 2021.\n\n\033[1;36;40mThis tool was written to assist customers identify the security features enabled across a FortiGate estate.\n\nThe tool relies on manual input of FortiGate details or a config file \'\033[1;33;40mconfig.ini\033[1;36;40m\' containing an entry for each FortiGate to analyse.\n\nThe config file format is defined as:\n\033[1;33;40m[FortiGateName]\naddress=<FortiGate address>\napi_key=<FortiGate API key>\nport=<FortiGate HTTPS port>\033[1;36;40m\n\nEach FortiGate entry must have a unique name, i.e. Hostname.\n\nIt will use a series of API calls to each FortiGate to gather the necessary image, which can be a very large amount on larger installations.\n\nOnce completed it will output the results of the analysis to the screen, and save the results to a CSV file: security_features.csv \033[0;0m', formatter_class=RawTextHelpFormatter)
    args = parser.parse_args()
    import_config()
    fgt_config = collect_config()
    create_output(fgt_config)

if __name__=="__main__":
    main()
