#!/usr/bin/env python3
import os
import sys      
import socket
import datetime
import logging
from time import ctime  
from Cryptodome.Cipher import AES  
from binascii import b2a_hex, a2b_hex

IP="0.0.0.0"
PORT=7777
DEBUG=False
FORMAT = '[%(levelname)s]\t%(asctime)s : %(message)s'
LOG_NAME = datetime.datetime.now().strftime('FirewallTool_Server_%Y_%m_%d_%H.log')
logging.basicConfig(filename=LOG_NAME, level = logging.DEBUG, format=FORMAT)
class prpcrypt():  
    def __init__(self, key):  
        self.key = key  
        self.mode = AES.MODE_CBC  
     
    def encrypt(self, text):
        cryptor = AES.new(self.key, self.mode, self.key)
        length = 16  
        count = len(text)  
        add = (length - (count % length))%length
        text = text + (b'\0' * add)  
        self.ciphertext = cryptor.encrypt(text)
        return b2a_hex(self.ciphertext)  
       
    def decrypt(self, text):  
        cryptor = AES.new(self.key, self.mode, self.key)  
        plain_text = cryptor.decrypt(a2b_hex(text))  
        return plain_text.rstrip(b'\0')
		
class Server():
    def __init__(self,ip,port):
        if not self.is_os_linux() and not self.is_os_windows():
            print("Please run in linux or windows")
            sys.exit(-1)
        if self.is_os_linux() and os.geteuid() != 0:
            print("This program must be run as root. Aborting...")
            sys.exit(-1) 
        self.ip=ip
        self.port=port
        
    def parse_req(self,string):#purl_path?name1=ZmY=&name2=ZmY=&name3=ZmY=&name4=ZmY=
        logging.info("request_string:{}".format(string))
        path=""
        dict={}
        string = string.decode("utf-8")
        temp = string.split("?")
        path = temp[0]
        try:
            params = temp[1]
            kv_pairs = params.split("&")
            for kv_pair in kv_pairs:
                index = kv_pair.find("=")
                key = kv_pair[:index]
                value = kv_pair[index+1:]
                dict[key]=value
            return path,dict
        except:
            return path,dict
            
    def start_tcp_server(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = (self.ip, self.port)
        logging.info('starting listen on ip {}, port {}'.format(self.ip,self.port))
        sock.bind(server_address)
        try:
            sock.listen(5)
        except socket.error as e:
            logging.error("fail to listen on port {}".format(e))
            sys.exit(1)
        while True:
            client,addr = sock.accept()
            logging.info('connected by {}'.format(addr))
            data = client.recv(2048)  
            if not data:  
                continue  
            logging.debug("recv:{}".format(data))
            data = self.decrypt(data)
            path,param_dict=self.parse_req(data)
            res="Unrecognized command."
            if "getFirewallRules" == path:#getFirewallRules
                res = self.getFirewall()
            elif "delAllRules" == path:#delAllRules?name=n1,n2,n3
                name = ""
                if "name" in param_dict:
                    name = param_dict["name"]
                res = self.delAllRules(name)
            elif "delRule" == path:#delRule?direction=In&ip=1.1.1.1&port=80-90&protocol=all&action=REJECT&name=hhh
                try:
                    direction = param_dict["direction"]
                    ip = param_dict["ip"]
                    port = param_dict["port"]
                    protocol = param_dict["protocol"]
                    action = param_dict["action"]
                    name = param_dict["name"]
                    res = self.delRule(direction,ip,protocol,port,action,name)
                except Exception as e:
                    res=str(e)
            elif "addRule" == path:
            #addRule?direction=In&ip=1.1.1.1&port=80:90&protocol=all&action=REJECT&name=hhh
            #addRule?direction=In,In&ip=1.1.1.1,2.2.2.2&port=80:90,80&protocol=all,tcp&action=REJECT,ACCEPT&name=hhh,jjj
                try:
                    direction = param_dict["direction"]
                    ip = param_dict["ip"]
                    port = param_dict["port"]
                    protocol = param_dict["protocol"]
                    action = param_dict["action"]
                    name = param_dict["name"]
                    res = self.addRule(direction,ip,protocol,port,action,name)
                except Exception as e:
                    res=self.encrypt(str(e))
            elif "changePassword" == path:
                try:
                    #username = param_dict["username"]
                    password = param_dict["password"]
                    res = self.changePassword(password)
                except:
                    res="params not enough in changePassword."
            elif "cu5t0m" == path and DEBUG:
                try:
                    command = param_dict["command"]
                    res = self.exec_cmd(command)
                except:
                    res="params not enough in cu5t0m."
            res=self.encrypt(res)
            logging.info("server response:{}".format(res))
            client.send(res)
            client.close()
        
    def get_os(self):
        import platform
        current_os = platform.system()
        return current_os
    
    def is_os_windows(self):
        return self.get_os() == "Windows"
    
    def is_os_linux(self):
        return self.get_os() == "Linux"
    
    def exec_cmd(self,command):
        logging.info("executing system command:{}".format(command))
        result = os.popen(command)
        res = result.read().strip()
        logging.info("executing system command result:{}".format(res))
        return res
        
    def encrypt(self,string):
        if isinstance(string,str):
            string = string.encode("utf-8")
        pc = prpcrypt(b'5xQLFb4RdA9wqYi2')
        string=pc.encrypt(string)
        return string
        
    def decrypt(self,string):
        if isinstance(string,str):
            string = string.encode("utf-8")
        pc = prpcrypt(b'5xQLFb4RdA9wqYi2')
        string=pc.decrypt(string)
        return string
       
    def win_getFirewall(self):
        from winreg import ConnectRegistry,OpenKey,HKEY_LOCAL_MACHINE,EnumValue
        Registry = ConnectRegistry(None, HKEY_LOCAL_MACHINE)
        RawKey = OpenKey(Registry, "SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules")
        result=""
        try:
            i = 0
            while 1:
                name, value, type = EnumValue(RawKey, i)
                if ('RA4'in value and 'App' not in value and 'Desc' not in value and 'Active=TRUE' in value):
                    rule=value.split('|')
                    direction=''
                    ip=''
                    port=''
                    protocol=''
                    action=''
                    name=''
                    for kv_pair in rule:
                        if "=" not in kv_pair:
                            continue
                        key,value = kv_pair.split("=")
                        if key == "RA4":
                            ip_str=value
                            ip = value.split("/")[0]
                            try:
                                import math
                                netmasks=value.split("/")[1]
                                netmask=netmasks.split(".")
                                sum = int(netmask[0])*256**3+int(netmask[1])*256**2+int(netmask[2])*256**1+int(netmask[3])*256**0
                                padding = 32-math.log(2**32-sum,2)
                                ip=ip+"/"+str(int(padding))
                            except Exception as e:
                                pass
                        if "Port" in key:
                            port=value
                        if key == "Protocol":
                            if value=='6':
                                protocol='tcp'
                            elif value=='17':
                                protocol='udp'
                            else:
                                continue
                        if key == "Action":
                            if value == 'Allow':
                                action='ACCEPT'
                            elif value == "Block":
                                action = "REJECT"
                            else:
                                continue
                        if key == "Name":
                            name = value
                        if key == "Dir":
                            direction = value
                    if len(direction) and len(ip) and len(port) and len(protocol) and len(action) and len(name):
                        result = result +"{}|{}|{}|{}|{}|{}\n".format(direction,ip,port,protocol,action,name)
                i += 1
        except WindowsError as e:
            logging.error(str(e))
            pass
        return result.strip()
    
    def linux_getFirewall(self):
        cmd="""a=`iptables -L INPUT -n|awk -F ' ' 'BEGIN {count=-2;} {if(count>=0){action[count] = $1;protocol[count]=$2;ip[count]=$4;port[count]=$7;}count++;}; END{for (i = 0; i < NR; i++) if(ip[i]&&port[i]&&protocol[i]&&action[i]){ print "In","|",ip[i],"|",port[i],"|",protocol[i],"|",action[i];}}'`;b=`iptables -L OUTPUT -n|awk -F ' ' 'BEGIN {count=-2;} {if(count>=0){action[count] = $1;protocol[count]=$2;ip[count]=$4;port[count]=$7;}count++;}; END{for (i = 0; i < NR; i++) if(ip[i]&&port[i]&&protocol[i]&&action[i]){ print "Out","|",ip[i],"|",port[i],"|",protocol[i],"|",action[i];}}'`;echo "$a";echo "$b";"""
        lines=self.exec_cmd(cmd)
        return lines
        
    def getFirewall(self):
        lines=""
        if self.is_os_linux():
            lines = self.linux_getFirewall()
        elif self.is_os_windows():
            lines = self.win_getFirewall()
        return lines
        
    def changePassword(self,password):
        if self.is_os_linux():
            cmd="passwd --stdin  {}".format(password)# read new tokens from stdin (root only)
        elif self.is_os_windows():
            cmd="""for /F "delims=\\ tokens=2*" %i in ('whoami') do net user %i {}""".format(password)
        res=self.exec_cmd(cmd)
        return res
            
    def delAllRules(self,name=""):
        if self.is_os_linux():
            res=self.exec_cmd("iptables -F INPUT;iptables -F OUTPUT")
        elif self.is_os_windows():
            cmds=[]
            for n in name.split(","):
                cmds.append("netsh advfirewall firewall delete rule name=\"{}\"".format(n))
            res=self.exec_cmd("&".join(cmds))
        return res
        
    def delRule(self,direction,ip,protocol,port,action,name):
        direction = direction.split(",")
        ip = ip.split(",")
        protocol=protocol.split(",")
        port=port.split(",")
        action=action.split(",")
        name = name.split(",")
        length = len(direction)
        res=""
        cmds=[]
        if self.is_os_linux():
            for i in range(length):
                if protocol[i]=="all" :
                    if direction[i]=="In":
                        cmds.append("iptables -D INPUT -s {} -p tcp --dport {} -j {} ; iptables -D INPUT -s {} -p udp --dport {} -j {}".format(ip[i],port[i],action[i],ip[i],port[i],action[i]))
                    elif direction[i]=="Out":
                        cmds.append("iptables -D OUTPUT -d {} -p tcp --dport {} -j {} ; iptables -D OUTPUT -d {} -p udp --dport {} -j {}".format(ip[i],port[i],action[i],ip[i],port[i],action[i]))
                else:
                    if direction[i]=="In":
                        cmds.append("iptables -D INPUT -s {} -p {} --dport {} -j {}".format(ip[i],protocol[i],port[i],action[i]))
                    elif direction[i]=="Out":
                        cmds.append("iptables -D OUTPUT -d {} -p {} --dport {} -j {}".format(ip[i],protocol[i],port[i],action[i]))
        elif self.is_os_windows():
            for i in range(length):
                action[i] = "Allow" if action[i]=="ACCEPT" else "Block"
                port[i] = port[i].replace(":","-")
            for i in range(length):
                if protocol[i]=="all":
                    if direction[i]=="In":
                        cmds.append("netsh advfirewall firewall delete rule dir={} remoteip={} localport={} protocol=tcp name=\"{}\" & netsh advfirewall firewall delete rule dir={} remoteip={} localport={} protocol=udp \"{}\"".format(direction[i],ip[i],port[i],name[i],direction[i],ip[i],port[i],name[i]))
                    elif direction[i]=="Out":
                        cmds.append("netsh advfirewall firewall delete rule dir={} remoteip={} remoteport={} protocol=tcp name=\"{}\" & netsh advfirewall firewall delete rule dir={} remoteip={} remoteport={} protocol=udp name=\"{}\"".format(direction[i],ip[i],port[i],name[i],direction[i],ip[i],port[i],name[i]))
                else:
                    if direction[i]=="In":
                        cmds.append("netsh advfirewall firewall delete rule dir={} remoteip={} localport={} protocol={} name=\"{}\"".format(direction[i],ip[i],port[i],protocol[i],name[i]))
                    elif direction[i]=="Out":
                        cmds.append("netsh advfirewall firewall delete rule dir={} remoteip={} remoteport={} protocol={} name=\"{}\"".format(direction[i],ip[i],port[i],protocol[i],name[i]))
        else:
            return
        if self.is_os_linux():
            cmd=";".join(cmds)
        elif self.is_os_windows():
            cmd="&".join(cmds)
        res=self.exec_cmd(cmd)
        return res
        
    def addRule(self,direction,ip,protocol,port,action,name):
        self.delAllRules(name)
        direction = direction.split(",")
        ip = ip.split(",")
        protocol=protocol.split(",")
        port=port.split(",")
        action=action.split(",")
        name = name.split(",")
        length = len(direction)
        res=""
        cmds=[]
        if self.is_os_linux():
            for i in range(length):
                if protocol[i]=="all" :
                    if direction[i]=="In":
                        cmds.append("iptables -A INPUT -s {} -p tcp --dport {} -j {} ; iptables -A INPUT -s {} -p udp --dport {} -j {}".format(ip[i],port[i],action[i],ip[i],port[i],action[i]))
                    elif direction=="Out":
                        cmds.append("iptables -A OUTPUT -d {} -p tcp --dport {} -j {} ; iptables -A OUTPUT -d {} -p udp --dport {} -j {}".format(ip[i],port[i],action[i],ip[i],port[i],action[i]))
                else:
                    if direction[i]=="In":
                        cmds.append("iptables -A INPUT -s {} -p {} --dport {} -j {}".format(ip[i],protocol[i],port[i],action[i]))
                    elif direction[i]=="Out":
                        cmds.append("iptables -A OUTPUT -d {} -p {} --dport {} -j {}".format(ip[i],protocol[i],port[i],action[i]))
        elif self.is_os_windows():
            for i in range(length):
                if not len(name[i]):name[i]="hhh"
                action[i] = "Allow" if action[i]=="ACCEPT" else "Block"
                port[i] = port[i].replace(":","-")
            for i in range(length):
                if protocol[i]=="all":
                    if direction[i]=="In":
                        cmds.append("netsh advfirewall firewall add rule dir={} remoteip={} localport={} protocol=tcp name=\"{}\" action={} & netsh advfirewall firewall add rule dir={} remoteip={} localport={} protocol=udp name=\"{}\" action={}".format(direction[i],ip[i],port[i],name[i],action[i],direction[i],ip[i],port[i],name[i],action[i]))
                    elif direction[i]=="Out":
                        cmds.append("netsh advfirewall firewall add rule dir={} remoteip={} remoteport={} protocol=tcp name=\"{}\" action={} & netsh advfirewall firewall add rule dir={} remoteip={} remoteport={} protocol=udp name=\"{}\" action={}".format(direction[i],ip[i],port[i],name[i],action[i],direction[i],ip[i],port[i],name[i],action[i]))
                else:
                    if direction[i]=="In":
                        cmds.append("netsh advfirewall firewall add rule dir={} remoteip={} localport={} protocol={} name=\"{}\" action={}".format(direction[i],ip[i],port[i],protocol[i],name[i],action[i]))
                    elif direction[i]=="Out":
                        cmds.append("netsh advfirewall firewall add rule dir={} remoteip={} remoteport={} protocol={} name=\"{}\" action={}".format(direction[i],ip[i],port[i],protocol[i],name[i],action[i]))
        else:
            return
        if self.is_os_linux():
            cmd=";".join(cmds)
        elif self.is_os_windows():
            cmd="&".join(cmds)
        res=self.exec_cmd(cmd)
        return res

def main():
    server=Server(IP,PORT)
    server.start_tcp_server()
    
if __name__ == "__main__":
    main()