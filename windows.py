def win_updateDB():
    from winreg import ConnectRegistry,OpenKey,HKEY_LOCAL_MACHINE,EnumValue
    Registry = ConnectRegistry(None, HKEY_LOCAL_MACHINE)
    RawKey = OpenKey(Registry, "SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules")
    result=""
    try:
        i = 0
        while 1:
            name, value, type = EnumValue(RawKey, i)
            #print(value)
            if ('RA4'in value and 'App' not in value and 'Dir=In' in value and 'Desc' not in value and 'Active=TRUE' in value):
                rule=value.split('|')
                ip=''
                port=''
                protocol=''
                action=''
                for kv_pair in rule:
                    if "=" not in kv_pair:
                        continue
                    key,value = kv_pair.split("=")
                    if key == "RA4":
                        ip=value
                    if key =="LPort":
                        port=value
                    if key == "Protocol":
                        if value=='6':
                            protocol='tcp'
                        elif value=='17':
                            protocol='udp'
                        else:
                            protocol=value
                    if key == "Action":
                        if value == 'Allow':
                            action='ACCEPT'
                        elif value == "Block":
                            action = "REJECT"
                        else:
                            action=value
                if len(ip) and len(port) and len(protocol) and len(action):
                    result = result +"{} {} {} {}\n".format(ip,port,protocol,action)
            i += 1
    except WindowsError:
        pass
    return result
    
if __name__ == "__main__":
    print(win_updateDB())