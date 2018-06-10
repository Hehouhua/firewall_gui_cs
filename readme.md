����ǽ���ӻ����ù��ߵ��;���
===============================

-------------------------
## ����
����ǽ���Ը����绷��������������������windows����linux����������ǽ���ñȽϸ��ӣ���ֱ�ۣ�����ά��Ա���������ѣ�����Ч�ʹ��͡�
������ּ��ͨ�����ض�ip���˿ڣ�Э��Ŀ��ӻ����ƣ��򻯷���ǽ�����á�

## ��������
* ��ͬ����ϵͳ�ķ���ǽ�����������һ��
* ����������д���׳���
* ��������鿴�Ѿ����ù��Ĺ���

## ֧�ֹ���<br>
* ���ӻ���ʾ���༭����ǽ����
* ����ip���˿ڣ�Э����Ʒ���ǽ���򣬰�����ӣ�ɾ�����༭
* ֧�����Σ��˿ڷ�Χ�Ĺ������
* ����ǽ�����ڲ�ͬ����֮�����Ǩ��

## ��������<br>
����ʹ��Python3������PyQt5��ΪGUI����
![���˼·ͼ](�ܹ�.png "���˼·ͼ")<br>
��ͼ�Ǹù��ߵ����˼·��ͨ����������ǽ��ǰ�Ĺ��򣬰ѹ���ṹ����������sqlite3���ݿ��ͨ���ڹ��߽���༭���޸����ݿ�����ݣ�Ȼ������ݿ�Ĺ���push������ǽ����ȥ�����������������л���ѡ��ͬ�����ͨ���������ݿ��ļ�����ʵ�ַ���ǽ����������֮��Ŀ���Ǩ�ơ�

## ���Ĵ��빦�ܽ���
```python
def win_getFirewall(): #������windows�����¶�ȡ����ǽ���Բ������ض���ʽ����
    ....
```
```python
def createDB(): #�����ڳ���ʹ�û���û�����ݿ��ʱ�򴴽����ݿ�
    ....
```
```python
class MainForm(QDialog):
    ...
    def updateDB(self): #Pull from Firewall�İ�ť����¼���Ӧ����
        ...
    def updateFirewall(self): #Push to Firewall�İ�ť����¼���Ӧ����
        ...
    def addRule(self): #Add Rule�İ�ť����¼���Ӧ����
        ...
    def deleteRule(self): #Delete Rule�İ�ť����¼���Ӧ����
        ...
    ...
```
## �����ܽ�
### Push��ʱ����Ҫʹ�õ����<br>
Linux����:<br>
```shell
iptables -F INPUT #���INPUT������
```

```shell
iptables -A INPUT -s {ip} -p {protocol} --dport {port} -j {action} #�������ӵ�INPUT������ĩβ
```

Windows����:
```shell
netsh advfirewall firewall delete rule name=hhh #����ض����ֵĹ�����
``` 

```shell
netsh advfirewall firewall add rule name=hhh dir=in remoteip={ip} protocol={protocol} localport={port} action={action} name={name} #�������ӵ�INPUT������ĩβ
```

### Pull��ʱ����Ҫʹ�õ����<br>
Linux���棺
```shell
iptables -L INPUT -n|awk -F ' ' 'BEGIN {count=-2;} {if(count>=0){action[count] = $1;protocol[count]=$2;ip[count]=$4;port[count]=$7;}count++;}; END{for (i = 0; i < NR; i++) print ip[i],port[i],protocol[i],action[i];}'
```

Windows���棺<br>
ͨ����ȡע��������ǽ�����ע������ȡ����

### Delete��ʱ����Ҫʹ�õ����<br>
Linux���棺
```shell
iptables -D INPUT -s {ip} -p {protocol} --dport {port} -j {action}
```

Windows���棺
```shell
netsh advfirewall firewall delete rule remoteip={ip} localport={port} protocol={protocol} name={name}
```

## ʹ���ֲ�<br>
### ���л���:<br>
python3,PyQt5,Windows����Linux��Windows7��Windows10��Ubuntu16.04�Ѳ��ԣ�
### ��ʾ����<br>
���Pull from Firewall��ѷ���ǽ�Ĺ�����ʾ�ڱ����<br>
![](��ʾ����.jpg "��ʾ����")<br>
### ɾ������<br>
ѡ������һ�����򣬵��delete rule��ɾ��ѡ�еĹ���<br>
![](ɾ������.jpg "ɾ������")<br>
![](ɾ���ɹ�.jpg "ɾ���ɹ�")<br>

### ��ӹ���<br>
���Add Rule��ӹ���<br>
![](��ӹ���.jpg "��ӹ���")<br>
�����ӳɹ���id��һ�л���ʾ�����id
![](��ӳɹ�.jpg "��ӳɹ�")<br>
��ӳɹ��󣬵��Push to Firewall�ѹ�������ݿ�ͬ��������ǽ

## ע�����
* ÿ�����/�༭������ɺ󣬵��Push to Firewall�ѹ�������ݿ�ͬ��������ǽ
* ɾ���������Ҫ���Push to FirewallҲ���Զ���firewall��ɾ��
* ��ӹ����ʱ��id��һ����ʾһ�����ֱ�ʾ������ӳɹ���
* ����rules.db������ڲ�ͬ����ϵͳ֮�乲�����ù���