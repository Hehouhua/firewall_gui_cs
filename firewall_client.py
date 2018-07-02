#!/usr/bin/env python3
#encoding=utf-8
from Cryptodome.Cipher import AES
from netaddr import IPNetwork
from binascii import b2a_hex, a2b_hex
import os,sys,socket,threading,time,datetime,logging,struct
from PyQt5.QtCore import (PYQT_VERSION_STR, QDate, QFile, QRegExp, QVariant, QModelIndex,Qt)
from PyQt5.QtWidgets import (QApplication,QComboBox,
                             QDateTimeEdit, QDialog, QGridLayout, QHBoxLayout, QLabel,
                             QLineEdit, QDateEdit,QMessageBox, QPushButton,
                             QStyleOptionViewItem, QTableView,QVBoxLayout)
from PyQt5.QtGui import QPixmap,QCursor,QRegExpValidator
from PyQt5.QtSql import (QSqlDatabase, QSqlQuery, QSqlRelation,
                         QSqlRelationalDelegate, QSqlRelationalTableModel,QSqlTableModel)
FORMAT = '[%(levelname)s]\t%(asctime)s : %(message)s'
LOG_NAME = datetime.datetime.now().strftime('Firewall_Client_%Y_%m_%d_%H.log')
logging.basicConfig(filename=LOG_NAME, level = logging.DEBUG, format=FORMAT)
MAC = True
try:
    from PyQt5.QtGui import qt_mac_set_native_menubar
except ImportError:
    MAC = False

#password表
PASSWORD_ID = 0
PASSWORD_HOST = 1
PASSWORD_PASSWORD=2
PASSWORD_TIME =3
#password_log表
PASSWORD_LOG_ID = 0
PASSWORD_LOG_HOST = 1
PASSWORD_LOG_USERNAME = 2
PASSWORD_LOG_PASSWORD=3
PASSWORD_LOG_TIME=4
#hosts表
HOSTS_ID = 0
HOSTS_HOST = 1
HOSTS_USERNAME = 2
HOSTS_DESCRIPTION= 3
HOSTS_TIME = 4
#rules表
RULES_ID = 0
RULES_HOST = 1
RULES_DIRECTION = 2
RULES_IP  = 3
RULES_PORT = 4
RULES_PROTOCOL = 5
RULES_ACTION =6
RULES_NAME = 7
RULES_TIME = 8
RULES_PUSHED = 9
#服务器监听的端口
SERVER_PORT=7777
#几天修改一次密码
CHANGE_PASSWORD_FREQUENCY=7
#几秒检查一次密码是否到期了，8*60*60表示8小时
CHECK_CHANGE_PASSWORD_INTERVAL=8*60*60
AES_KEY=b'5xQLFb4RdA9wqYi2'

ip2num = lambda ip:sum([256**j*int(i) for j,i in enumerate(ip.split('.')[::-1])])
num2ip = lambda num:socket.inet_ntoa(struct.pack('I',socket.htonl(num))) 
def parseSubnet(subnetStr):
    cidr=subnetStr.strip()
    ip_list=[]
    if len(cidr)>0:
        if cidr.find('-') != -1: #检查是否有-
            ip=[]                
            ip_range=cidr.split('-')
            ip_start=ip_range[0] #设定起始IP地址
            ip_end=ip_range[1]
            ip_start_num=ip2num(ip_start)
            ip_end_num=ip2num(ip_end)
            num=ip_start_num
            while num <= ip_end_num:
                ip.append(num2ip(num)) #把数字转换成ip       
                num+=1
        elif cidr.lower()==cidr.upper():#ip address
            ip = IPNetwork(cidr)
            ip = list(ip)
        else:
            ip=[cidr]#hostname
        for each_ip in ip:
            ip_list.append(str(each_ip))
    return ip_list
    
def gen_random_name():
    import random
    import string
    ran_str = ''.join(random.sample(string.ascii_letters + string.digits, 10))
    return ran_str

def createDB():
    query = QSqlQuery()
    QApplication.processEvents()
    logging.info("Creating tables...")
    query.exec_("""CREATE TABLE if not exists protocol (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name VARCHAR(20) NOT NULL,
                description VARCHAR(40) NOT NULL,
                UNIQUE(name))""")
    query.exec_("""INSERT INTO protocol (name,description) VALUES("tcp","tcp protocol")""")
    query.exec_("""INSERT INTO protocol (name,description) VALUES("udp","udp protocol")""")
    query.exec_("""INSERT INTO protocol (name,description) VALUES("all","tcp or udp")""")
    query.exec_("""CREATE TABLE if not exists action (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name VARCHAR(20) NOT NULL,
                description VARCHAR(40) NOT NULL,
                UNIQUE(name))""")
    query.exec_("""INSERT INTO action (name,description) VALUES("REJECT","reject this packet")""")
    query.exec_("""INSERT INTO action (name,description) VALUES("ACCEPT","accept this packet")""")
    query.exec_("""CREATE TABLE if not exists direction (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name VARCHAR(20) NOT NULL,
                description VARCHAR(40) NOT NULL,
                UNIQUE(name))""")
    query.exec_("""INSERT INTO direction (name,description) VALUES("In","Input")""")
    query.exec_("""INSERT INTO direction (name,description) VALUES("Out","Output")""")
    query.exec_("""CREATE TABLE if not exists hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host VARCHAR(32) NOT NULL,
                username VARCHAR(32) NOT NULL,
                description VARCHAR(40) ,
                time DATETIME DEFAULT (datetime('now', 'localtime')),
                UNIQUE(host))""")
    query.exec_("""CREATE TABLE if not exists rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host VARCHAR(32) NOT NULL,
                direction VARCHAR(20) NOT NULL,
                ip VARCHAR(20) NOT NULL,
                port VARCHAR(64) NOT NULL,
                protocol VARCHAR(16) NOT NULL,
                action VARCHAR(10) NOT NULL,
                name VARCHAR(200) ,
                time DATETIME DEFAULT (datetime('now', 'localtime')),
                pushed VARCHAR(2) DEFAULT(0),
                UNIQUE(host,direction,ip,port,protocol),
                FOREIGN KEY (host) REFERENCES hosts(host),
                FOREIGN KEY (direction) REFERENCES direction(name),
                FOREIGN KEY (protocol) REFERENCES protocol(name),
                FOREIGN KEY (action) REFERENCES action(name))""")
    query.exec_("""CREATE TRIGGER [rules_UpdateLastTime]  
                   AFTER UPDATE ON rules
                   FOR EACH ROW WHEN OLD.host!=NEW.host or OLD.direction!=NEW.direction or OLD.ip!=NEW.ip or OLD.port!=NEW.port or OLD.protocol!=NEW.protocol or OLD.action!=NEW.action  
                BEGIN  
                    update rules set pushed=(0) where id=OLD.id;  
                END""")
    #query.exec_("""CREATE TRIGGER [rules_UpdateLastTime]  
    #               AFTER UPDATE ON rules
    #               FOR EACH ROW WHEN NEW.name <= OLD.name  
    #            BEGIN  
    #                update rules set name=(datetime('now', 'localtime')) where id=OLD.id;  
    #            END""")
    query.exec_("""CREATE TRIGGER [hosts_UpdateLastTime]  
                   AFTER UPDATE ON hosts
                   FOR EACH ROW WHEN NEW.time <= OLD.time  
                BEGIN  
                    update hosts set time=(datetime('now', 'localtime')) where id=OLD.id;  
                END""")
    query.exec_("""CREATE TABLE if not exists password_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host VARCHAR(32) NOT NULL,
                username VARCHAR(32) NOT NULL,
                password VARCHAR(32) NOT NULL,
                time DATETIME DEFAULT (datetime('now', 'localtime')),
                FOREIGN KEY (host) REFERENCES hosts(host)
                )""")
    query.exec_("""CREATE TABLE if not exists password (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host VARCHAR(32) NOT NULL,
                password VARCHAR(32) NOT NULL,
                time DATETIME DEFAULT (datetime('now', 'localtime')),
                FOREIGN KEY (host) REFERENCES hosts(host),
                UNIQUE(host))""")
    query.exec_("""CREATE TRIGGER [password_UpdateLastTime]  
                   AFTER UPDATE ON password
                   FOR EACH ROW WHEN NEW.time <= OLD.time  
                BEGIN  
                    update password set time=(datetime('now', 'localtime')) where id=OLD.id;  
                END""")
    QApplication.processEvents()

def reloadModel(form):
    form.ruleModel.setTable("rules")
    #将rules表的第HOST个属性设为hosts表的host属性外键，并将其显示为hosts表的host属性的值
    form.ruleModel.setRelation(RULES_HOST,QSqlRelation("hosts", "host", "host"))
    form.ruleModel.setRelation(RULES_DIRECTION,QSqlRelation("direction", "name", "name"))
    form.ruleModel.setRelation(RULES_PROTOCOL,QSqlRelation("protocol", "name", "name"))
    form.ruleModel.setRelation(RULES_ACTION,QSqlRelation("action", "name", "name"))
    form.ruleModel.setSort(RULES_ID, Qt.AscendingOrder)
    form.ruleModel.setHeaderData(RULES_ID, Qt.Horizontal,"id")
    form.ruleModel.setHeaderData(RULES_HOST, Qt.Horizontal,"主机ip")
    form.ruleModel.setHeaderData(RULES_DIRECTION, Qt.Horizontal,"方向")
    form.ruleModel.setHeaderData(RULES_IP, Qt.Horizontal,"ip/网段")
    form.ruleModel.setHeaderData(RULES_PORT, Qt.Horizontal,"端口号/端口范围")
    form.ruleModel.setHeaderData(RULES_PROTOCOL, Qt.Horizontal,"协议")
    form.ruleModel.setHeaderData(RULES_ACTION, Qt.Horizontal,"策略")
    form.ruleModel.setHeaderData(RULES_NAME, Qt.Horizontal,"规则名字")
    form.ruleModel.setHeaderData(RULES_TIME, Qt.Horizontal,"规则时间")
    form.ruleModel.setHeaderData(RULES_PUSHED, Qt.Horizontal,"已推送")
    form.ruleModel.select()
    
def reloadView(form):
    form.ruleView.setModel(form.ruleModel)
    form.ruleView.setItemDelegate(RuleDelegate(form))
    form.ruleView.setSelectionMode(QTableView.SingleSelection)
    form.ruleView.setSelectionBehavior(QTableView.SelectRows)
    #form.ruleView.setColumnHidden(NAME, True)
    #form.ruleView.resizeColumnsToContents()
    form.ruleView.setColumnWidth(RULES_ID, 60)
    form.ruleView.setColumnWidth(RULES_HOST, 242)
    form.ruleView.setColumnWidth(RULES_DIRECTION, 50)
    form.ruleView.setColumnWidth(RULES_IP, 168)
    form.ruleView.setColumnWidth(RULES_PORT, 128)
    form.ruleView.setColumnWidth(RULES_PROTOCOL, 66)
    form.ruleView.setColumnWidth(RULES_ACTION, 72)
    form.ruleView.setColumnWidth(RULES_NAME, 128)
    form.ruleView.setColumnWidth(RULES_TIME, 168)
    form.ruleView.setColumnWidth(RULES_PUSHED, 52)
    
class SecComm():
    def __init__(self,key):
        self.key=key

    def encrypt(self,string):
        if isinstance(string,str):
            string = string.encode("utf-8")
        pc = prpcrypt(self.key)
        string=pc.encrypt(string)
        return string
        
    def decrypt(self,string):
        if isinstance(string,str):
            string = string.encode("utf-8")
        pc = prpcrypt(self.key)
        string=pc.decrypt(string)
        return string
        
    def remoteExecute(self,host,port,command):
        if not command:  
            return
        if "/" in host or "-" in host:
            return
        try:
            clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            clientsocket.settimeout(1.5)
            clientsocket.connect((host, port))
        except socket.error as e:
            msg='fail to setup socket connection {}:{},because:{}'.format(host,port,str(e))
            logging.error(msg)
            clientsocket.close()
            raise e
            return
        except Exception as e:
            logging.error("Exception in remoteExecute,{0}".format(str(e)))
            raise(e)
        logging.info("send to {}:{}>>>>>>>>>>>>\n{}".format(host,port,command))
        command=bytes(command,encoding="utf-8")
        command = self.encrypt(command)
        clientsocket.send(command)
        res = clientsocket.recv(65536) 
        res=self.decrypt(res)        
        res = res.decode("utf-8")
        logging.info("recv from {}:{}<<<<<<<<<<<<\n{}".format(host,port,res))
        clientsocket.close()
        if (not res.startswith("0,") and not res.startswith("1,")):
            err_msg = "Error Occurred in Executing in Remote System"
            logging.error(err_msg)
            raise Exception(err_msg)
        elif (not res.startswith("0,")):
            err_msg = "Execute in remote but error occurred,please check logs"
            logging.error(err_msg)
            raise Exception(err_msg)
        res=res[2:]
        return res
        
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

class PasswordLogDlg(QDialog):
    def __init__(self, table, title, parent=None):
        super(PasswordLogDlg, self).__init__(parent)
        self.model = QSqlRelationalTableModel(self)
        self.setWindowTitle("密码修改日志")
        self.model.setTable(table)
        self.model.setRelation(PASSWORD_LOG_HOST,QSqlRelation("hosts", "host", "host"))
        self.model.setSort(PASSWORD_LOG_TIME, Qt.DescendingOrder)
        self.model.setHeaderData(PASSWORD_LOG_ID, Qt.Horizontal,"ID")
        self.model.setHeaderData(PASSWORD_LOG_HOST, Qt.Horizontal, "主机ip")
        self.model.setHeaderData(PASSWORD_LOG_USERNAME, Qt.Horizontal,"用户名")
        self.model.setHeaderData(PASSWORD_LOG_PASSWORD, Qt.Horizontal,"密码")
        self.model.setHeaderData(PASSWORD_LOG_TIME, Qt.Horizontal,"时间")
        self.model.select()

        self.view = QTableView()
        self.view.setModel(self.model)
        self.view.setItemDelegate(PasswordLogDelegate(self))#设置所有列不可修改
        self.view.setSelectionMode(QTableView.SingleSelection)
        self.view.setSelectionBehavior(QTableView.SelectRows)
        self.view.setColumnWidth(PASSWORD_LOG_ID, 50)
        self.view.setColumnWidth(PASSWORD_LOG_HOST, 168)
        self.view.setColumnWidth(PASSWORD_LOG_USERNAME, 144)
        self.view.setColumnWidth(PASSWORD_LOG_PASSWORD, 144)
        self.view.setColumnWidth(PASSWORD_LOG_TIME, 168)
        self.setMinimumWidth(740)
        self.setMinimumHeight(480)
        
        label_ip=QLabel("主机过滤器: ")#绑定label到窗口
        self.textbox_ip = QLineEdit()
        self.textbox_ip.setPlaceholderText("例如：1.1.1.1 或 1.1.1 或 1.%.1,按下回车后生效")
        self.textbox_ip.setClearButtonEnabled(True)
        
        dataLayout = QVBoxLayout()
        filterLayout = QHBoxLayout()
        filterLayout.addWidget(label_ip)
        filterLayout.addWidget(self.textbox_ip)
        dataLayout.addLayout(filterLayout)
        dataLayout.addWidget(self.view, 1)
        self.setLayout(dataLayout)
        self.textbox_ip.editingFinished.connect(self.hostFilterEditingFinished)

    def hostFilterEditingFinished(self):
        filter=self.textbox_ip.text()
        self.model.setFilter(("password_log.host like '%{}%'".format(filter)))
        self.model.select()

class SetPasswordDlg(QDialog):
    def __init__(self, table, title, parent=None):
        super(SetPasswordDlg, self).__init__(parent)
        self.setWindowTitle("编辑密码")
        self.model = QSqlRelationalTableModel(self)
        self.model.setTable(table)
        self.model.setEditStrategy(QSqlTableModel.OnFieldChange)
        self.model.dataChanged.connect(self.model.submitAll)#在model变化时写入数据库
        self.model.setRelation(PASSWORD_HOST,QSqlRelation("hosts", "host", "host"))
        self.model.setSort(PASSWORD_TIME, Qt.DescendingOrder)
        self.model.setHeaderData(PASSWORD_ID, Qt.Horizontal,"ID")
        self.model.setHeaderData(PASSWORD_HOST, Qt.Horizontal, "主机ip")
        self.model.setHeaderData(PASSWORD_PASSWORD, Qt.Horizontal,"密码")
        self.model.setHeaderData(PASSWORD_TIME, Qt.Horizontal,"时间")
        self.model.select()

        self.view = QTableView()
        self.view.setModel(self.model)
        self.view.setItemDelegate(PasswordDelegate(self))#设置ID,time列不可修改
        self.view.setSelectionMode(QTableView.SingleSelection)
        self.view.setSelectionBehavior(QTableView.SelectRows)
        self.view.setColumnWidth(PASSWORD_ID, 50)
        self.view.setColumnWidth(PASSWORD_HOST, 242)
        self.view.setColumnWidth(PASSWORD_PASSWORD, 144)
        self.view.setColumnWidth(PASSWORD_TIME, 168)
        self.setMinimumWidth(648)
        self.setMinimumHeight(480)
        
        label_ip=QLabel("主机过滤器: ")#绑定label到窗口
        self.textbox_ip = QLineEdit()
        self.textbox_ip.setPlaceholderText("例如：1.1.1.1 或 1.1.1 或 1.%.1,按下回车后生效")
        self.textbox_ip.setClearButtonEnabled(True)
        addButton = QPushButton("&添加")
        deleteButton = QPushButton("&删除")
        expandButton = QPushButton("&展开网段")
        backButton = QPushButton("&不修改并返回")
        okButton = QPushButton("&修改并返回")
        
        buttonLayout = QHBoxLayout()
        buttonLayout.addWidget(addButton)
        buttonLayout.addWidget(deleteButton)
        buttonLayout.addWidget(expandButton)
        buttonLayout.addWidget(backButton)
        buttonLayout.addStretch()
        buttonLayout.addWidget(okButton)
        dataLayout = QVBoxLayout()
        filterLayout = QHBoxLayout()
        filterLayout.addWidget(label_ip)
        filterLayout.addWidget(self.textbox_ip)
        dataLayout.addLayout(filterLayout)
        dataLayout.addWidget(self.view, 1)
        dataLayout.addLayout(buttonLayout)
        self.setLayout(dataLayout)
        
        self.textbox_ip.editingFinished.connect(self.hostFilterEditingFinished)
        addButton.clicked.connect(self.addRecord)
        deleteButton.clicked.connect(self.deleteRecord)
        expandButton.clicked.connect(self.expandHosts)
        backButton.clicked.connect(self.back)
        okButton.clicked.connect(self.ok)

    def hostFilterEditingFinished(self):
        filter=self.textbox_ip.text()
        self.model.setFilter(("password.host like '%{}%'".format(filter)))
        self.model.select()
        
    def back(self):
        self.model.select()
        self.accept()#退出对话框
    
    #修改并返回
    def ok(self):
        row =self.model.rowCount()#返回qtableview显示的行数
        if row==0:return
        passwords={}
        query=QSqlQuery()
        for r in range(row):
            host=self.model.data(self.model.index(r, PASSWORD_HOST))
            password=self.model.data(self.model.index(r, PASSWORD_PASSWORD))
            if host not in passwords:
                passwords[host]={"host":host,"password":password}
        for host in passwords:
            password = passwords[host]["password"]
            if "/" in host or "-" in host:
                continue
            query.exec_("select username from hosts where host='{0}'".format(host))
            if not query.next():
                continue
            username = query.value(0)
            if len(username)==0:
                err_msg = "请为host:{0}指定username".format(host)
                message=QMessageBox(QMessageBox.NoIcon, "异常", err_msg)
                logging.error(err_msg)
                message.exec()
                continue
            cmd="changePassword?username={0}&password={1}".format(username,password)
            if "/" not in host and "-" not in host:
                try:
                    form.seccomm.remoteExecute(host,SERVER_PORT,cmd)
                    QSqlDatabase.database().transaction()
                    query.exec_("insert into password_log('host','username','password') values('{0}','{1}','{2}')".format(host,username,password))
                    QSqlDatabase.database().commit()
                except socket.error as e:
                    err_msg = "{0}\n由于 {1}:{2} 连接异常，无法修改该主机的用户名密码".format(str(e),host,SERVER_PORT)
                    message=QMessageBox(QMessageBox.NoIcon, "异常", err_msg)
                    logging.error(err_msg)
                    message.exec()
                except Exception as e:
                    err_msg = "{0}".format(e)
                    message=QMessageBox(QMessageBox.NoIcon, "异常", err_msg)
                    logging.error(err_msg)
                    message.exec()
        self.accept()#退出对话框
        
    def addRecord(self):
        row = self.model.rowCount()
        self.model.insertRow(row)
        index = self.model.index(row, PASSWORD_HOST)
        self.view.setCurrentIndex(index)
        self.view.edit(index)
        self.model.submitAll()

    def deleteRecord(self):
        index = self.view.currentIndex()
        if not index.isValid():
            return
        self.model.removeRow(index.row())
        self.model.submitAll()
        self.model.select()
        #QSqlDatabase.database().commit()
        
    def expandHosts(self):
        row =self.model.rowCount()#返回qtableview显示的行数
        if row==0:return
        hosts=[]
        query=QSqlQuery()
        #query.exec_("""select host,password from password""")
        for r in range(row):
            subnet=self.model.data(self.model.index(r, PASSWORD_HOST))
            password=self.model.data(self.model.index(r, PASSWORD_PASSWORD))
            if "/" not in subnet and "-" not in subnet:
                continue
            subnet=parseSubnet(subnet)
            for host in subnet:
                hosts.append({"host":host,"password":password})
        for host in hosts:
            #此段代码展开host会覆盖原来host
            QSqlDatabase.database().transaction()
            query.exec_("insert or replace into password (host,password) values('{0}','{1}')".format(host["host"],host["password"]))
            QSqlDatabase.database().commit()
        self.model.select()
        return
    
class PasswordDelegate(QSqlRelationalDelegate):
    def __init__(self, parent=None):
        super(PasswordDelegate, self).__init__(parent)

    def paint(self, painter, option, index):
        myoption = QStyleOptionViewItem(option)
        QSqlRelationalDelegate.paint(self, painter, myoption, index)

    def createEditor(self, parent, option, index):
        if index.column() == PASSWORD_ID or index.column()==PASSWORD_TIME:
            return
        return QSqlRelationalDelegate.createEditor(self, parent,option, index)

    def setEditorData(self, editor, index):
        if index.column() == PASSWORD_ID or index.column()==PASSWORD_TIME:
            return
        QSqlRelationalDelegate.setEditorData(self, editor, index)

    def setModelData(self, editor, model, index):
        QSqlRelationalDelegate.setModelData(self, editor, model,index)
        
class HostReferenceDataDlg(QDialog):
    def __init__(self, table, title, parent=None):
        super(HostReferenceDataDlg, self).__init__(parent)
        self.model = QSqlTableModel(self)
        self.model.setEditStrategy(QSqlTableModel.OnFieldChange)
        #self.model.setEditStrategy(QSqlTableModel.OnManualSubmit)#设置更新数据库的策略，手动更新数据库
        self.model.dataChanged.connect(self.model.submitAll)#在model变化时写入数据库
        self.model.setTable(table)
        self.model.setSort(HOSTS_HOST, Qt.AscendingOrder)
        self.model.setHeaderData(HOSTS_ID, Qt.Horizontal,"ID")
        self.model.setHeaderData(HOSTS_HOST, Qt.Horizontal, "主机ip")
        self.model.setHeaderData(HOSTS_USERNAME, Qt.Horizontal, "用户名")
        self.model.setHeaderData(HOSTS_DESCRIPTION, Qt.Horizontal,"描述")
        self.model.setHeaderData(HOSTS_TIME, Qt.Horizontal,"时间")
        self.model.select()

        self.view = QTableView()
        self.view.setModel(self.model)
        self.view.setItemDelegate(HostDelegate(self))#设置id,time列不可修改
        self.view.setSelectionMode(QTableView.SingleSelection)
        self.view.setSelectionBehavior(QTableView.SelectRows)
        #self.view.setColumnHidden(ID, True)
        #self.view.resizeColumnsToContents()
        self.view.setColumnWidth(HOSTS_ID, 50)
        self.view.setColumnWidth(HOSTS_HOST, 242)
        self.view.setColumnWidth(HOSTS_USERNAME, 144)
        self.view.setColumnWidth(HOSTS_DESCRIPTION, 144)
        self.view.setColumnWidth(HOSTS_TIME, 168)
        self.setMinimumWidth(814)
        self.setMinimumHeight(480)
        label_ip=QLabel("主机过滤器: ")#绑定label到窗口
        self.textbox_ip = QLineEdit()
        self.textbox_ip.setPlaceholderText("例如：1.1.1.1 或 1.1.1 或 1.%.1,按下回车后生效")
        self.textbox_ip.setClearButtonEnabled(True)
        addButton = QPushButton("&添加")
        deleteButton = QPushButton("&删除")
        expandButton = QPushButton("&展开网段")
        okButton = QPushButton("&完成")
        if not MAC:
            addButton.setFocusPolicy(Qt.NoFocus)
            deleteButton.setFocusPolicy(Qt.NoFocus)
            expandButton.setFocusPolicy(Qt.NoFocus)
            okButton.setFocusPolicy(Qt.NoFocus)
        buttonLayout = QHBoxLayout()
        buttonLayout.addWidget(addButton)
        buttonLayout.addWidget(deleteButton)
        buttonLayout.addWidget(expandButton)
        buttonLayout.addStretch()
        buttonLayout.addWidget(okButton)
        dataLayout = QVBoxLayout()
        filterLayout = QHBoxLayout()
        filterLayout.addWidget(label_ip)
        filterLayout.addWidget(self.textbox_ip)
        dataLayout.addLayout(filterLayout)
        dataLayout.addWidget(self.view, 1)
        dataLayout.addLayout(buttonLayout)
        self.setLayout(dataLayout)
        self.textbox_ip.editingFinished.connect(self.hostFilterEditingFinished)
        addButton.clicked.connect(self.addRecord)
        deleteButton.clicked.connect(self.deleteRecord)
        expandButton.clicked.connect(self.expandHosts)
        okButton.clicked.connect(self.ok)
        self.setWindowTitle("防火墙规则管理器 - 编辑 {0} 引用数据".format(title))

    def hostFilterEditingFinished(self):
        filter=self.textbox_ip.text()
        self.model.setFilter(("hosts.host like '%{}%'".format(filter)))
        self.model.select()
                
    def ok(self):
        global form
        reloadModel(form)
        reloadView(form)
        self.model.select()
        self.accept()#退出对话框
        
    def addRecord(self):
        row = self.model.rowCount()
        self.model.insertRow(row)
        index = self.model.index(row, RULES_HOST)
        self.view.setCurrentIndex(index)
        self.view.edit(index)
        #QApplication.processEvents()
        self.model.submitAll()

    def deleteRecord(self):
        index = self.view.currentIndex()
        if not index.isValid():
            return
        #QSqlDatabase.database().transaction()
        record = self.model.record(index.row())
        host = record.value(RULES_HOST)
        table = self.model.tableName()
        query = QSqlQuery()
        if table == "hosts":
            query.exec_("SELECT COUNT(*) FROM rules WHERE host = '{0}'".format(host))
        count = 0
        if query.next():
            count = query.value(0)
            #print(count)
        if count:
            err_msg = "不能从数据表<br>{1}删除{0}，这是由于主机还有{2}条防火墙规则没有删除".format(record.value(RULES_HOST),table,count)
            QMessageBox.information(self,
                    "删除 {0}".format(table),
                    err_msg)
            #QSqlDatabase.database().rollback()
            return
        self.model.removeRow(index.row())
        self.model.submitAll()
        self.model.select()
        #QSqlDatabase.database().commit()
        
    def expandHosts(self):
        row =self.model.rowCount()#返回qtableview显示的行数
        if row==0:return
        hosts=[]
        query=QSqlQuery()
        #query.exec_("""select host,username,description from hosts""")
        for r in range(row):
            subnet=self.model.data(self.model.index(r, HOSTS_HOST))
            username=self.model.data(self.model.index(r, HOSTS_USERNAME))            
            description=self.model.data(self.model.index(r, HOSTS_DESCRIPTION))
            if "/" not in subnet and "-" not in subnet:
                continue
            subnet=parseSubnet(subnet)
            for host in subnet:
                hosts.append({"host":host,"username":username,"description":description})
        for host in hosts:
            #此段代码展开不会覆盖原来host
            #query.exec_("select count(*) from hosts where host='{0}'".format(host["host"]))
            #if query.next() and query.value(0)!=0:
            #    continue
            
            #此段代码展开会覆盖原来host
            QSqlDatabase.database().transaction()
            query.exec_("insert or replace into hosts (host,username,description) values('{0}','{1}','{2}')".format(host["host"],host["username"],host["description"]))
            QSqlDatabase.database().commit()
        self.model.select()
        return
            
class HostDelegate(QSqlRelationalDelegate):
    def __init__(self, parent=None):
        super(HostDelegate, self).__init__(parent)

    def paint(self, painter, option, index):
        myoption = QStyleOptionViewItem(option)
        QSqlRelationalDelegate.paint(self, painter, myoption, index)

    def createEditor(self, parent, option, index):
        if index.column() == HOSTS_ID or index.column()==HOSTS_TIME:
            return
        if index.column() == HOSTS_HOST:
            editor = QLineEdit(parent)
            editor.setPlaceholderText('1.1.1.1或1.1.1.1/24或1.1.1.1-1.1.1.22')
            editor.setAlignment(Qt.AlignRight|Qt.AlignVCenter)
            return editor
        return QSqlRelationalDelegate.createEditor(self, parent,option, index)

    def setEditorData(self, editor, index):
        if index.column() == HOSTS_ID:
            return
        QSqlRelationalDelegate.setEditorData(self, editor, index)

    def setModelData(self, editor, model, index):
        QSqlRelationalDelegate.setModelData(self, editor, model,index)
        
class PasswordLogDelegate(QSqlRelationalDelegate):
    def __init__(self, parent=None):
        super(PasswordLogDelegate, self).__init__(parent)

    def paint(self, painter, option, index):
        myoption = QStyleOptionViewItem(option)
        QSqlRelationalDelegate.paint(self, painter, myoption, index)

    def createEditor(self, parent, option, index):
        return

    def setEditorData(self, editor, index):
        return

    def setModelData(self, editor, model, index):
        return
        
class RuleDelegate(QSqlRelationalDelegate):
    def __init__(self, parent=None):
        super(RuleDelegate, self).__init__(parent)

    def paint(self, painter, option, index):
        myoption = QStyleOptionViewItem(option)
        if index.column() == RULES_ACTION:
            myoption.displayAlignment |= (Qt.AlignRight|Qt.AlignVCenter)
        QSqlRelationalDelegate.paint(self, painter, myoption, index)

    def createEditor(self, parent, option, index):
        if index.column() == RULES_ID or index.column()==RULES_TIME or index.column()==RULES_PUSHED:
            return
        if index.column() == RULES_IP:
            editor = QLineEdit(parent)
            editor.setPlaceholderText('1.1.1.1或1.1.1.1/24')
            editor.setAlignment(Qt.AlignRight|Qt.AlignVCenter)
            return editor
        if index.column() == RULES_PORT:
            editor = QLineEdit(parent)
            regex = QRegExp(r"^(([1-9]\d{0,3})|([1-5]\d{4})|(6[1-4]\d{3})|(65[1-4]\d{2})|(655[1-2]\d)|(6553[1-5]))(:(([1-9]\d{0,3})|([1-5]\d{4})|(6[1-4]\d{3})|(65[1-4]\d{2})|(655[1-2]\d)|(6553[1-5])))?$")
            validator = QRegExpValidator(regex, parent)
            editor.setValidator(validator)
            editor.setPlaceholderText('80或8080:8090')
            editor.setAlignment(Qt.AlignRight|Qt.AlignVCenter)
            return editor
        return QSqlRelationalDelegate.createEditor(self, parent,option, index)

    def setEditorData(self, editor, index):
        QSqlRelationalDelegate.setEditorData(self, editor, index)

    def setModelData(self, editor, model, index):
        QSqlRelationalDelegate.setModelData(self, editor, model,index)

class MainForm(QDialog):
    def __init__(self):
        super(MainForm, self).__init__()
        self.seccomm=SecComm(AES_KEY)
        query=QSqlQuery()
        query.exec_("PRAGMA foreign_keys = ON;")
        self.ruleModel = QSqlRelationalTableModel(self)
        self.ruleModel.setEditStrategy(QSqlTableModel.OnFieldChange)#设置更新数据库的策略，在属性变化时写入数据库
        #self.ruleModel.setEditStrategy(QSqlTableModel.OnManualSubmit)#设置更新数据库的策略，手动更新数据库
        self.ruleModel.dataChanged.connect(self.ruleModel.submitAll)#在model变化时写入数据库
        reloadModel(self)
        self.ruleView = QTableView()
        reloadView(self)
        ruleLabel = QLabel("")
        ruleLabel.setBuddy(self.ruleView)

        label_ip=QLabel("主机过滤器: ")#绑定label到窗口
        self.textbox_ip = QLineEdit()
        self.textbox_ip.setPlaceholderText("例如：1.1.1.1 或 1.1.1 或 1.%.1,按下回车后生效")
        self.textbox_ip.setClearButtonEnabled(True)
        setPasswordButton = QPushButton("修改密码")
        viewPasswordButton = QPushButton("密码修改日志")
        editHostsButton = QPushButton("编辑主机")
        addRuleButton = QPushButton("添加规则")
        deleteRuleButton = QPushButton("删除规则")
        expandRuleButton = QPushButton("展开规则")
        pushButton = QPushButton("把规则推送给防火墙")
        pullButton = QPushButton("从防火墙读取规则")
        quitButton = QPushButton("退出")
        for button in (setPasswordButton,viewPasswordButton,editHostsButton,addRuleButton,deleteRuleButton,expandRuleButton,pushButton,pullButton,quitButton):
            if MAC:
                button.setDefault(False)
                button.setAutoDefault(False)
            else:
                button.setFocusPolicy(Qt.NoFocus)

        dataLayout = QVBoxLayout()
        filterLayout = QHBoxLayout()
        filterLayout.addWidget(ruleLabel)
        filterLayout.addWidget(label_ip)
        filterLayout.addWidget(self.textbox_ip)
        dataLayout.addLayout(filterLayout)
        dataLayout.addWidget(self.ruleView, 1)
        buttonLayout = QVBoxLayout()
        buttonLayout.addWidget(setPasswordButton)
        buttonLayout.addWidget(viewPasswordButton)
        buttonLayout.addWidget(editHostsButton)
        buttonLayout.addWidget(addRuleButton)
        buttonLayout.addWidget(deleteRuleButton)
        buttonLayout.addWidget(expandRuleButton)
        buttonLayout.addWidget(pushButton)
        buttonLayout.addWidget(pullButton)
        buttonLayout.addStretch()
        buttonLayout.addWidget(quitButton)
        layout = QHBoxLayout()
        layout.addLayout(dataLayout, 1)
        layout.addLayout(buttonLayout)
        self.setLayout(layout)

        self.textbox_ip.editingFinished.connect(self.hostFilterEditingFinished)
        self.ruleView.selectionModel().currentRowChanged.connect(self.ruleChanged)
        setPasswordButton.clicked.connect(self.setPassword)
        viewPasswordButton.clicked.connect(self.viewPasswordLog)
        editHostsButton.clicked.connect(self.editHosts)
        addRuleButton.clicked.connect(self.addRule)
        deleteRuleButton.clicked.connect(self.deleteRule)
        expandRuleButton.clicked.connect(self.expandRule)
        pushButton.clicked.connect(self.updateFirewall)
        pullButton.clicked.connect(self.updateDB)
        quitButton.clicked.connect(self.done)

        self.ruleChanged(self.ruleView.currentIndex())
        self.setMinimumWidth(1336)
        self.setMinimumHeight(480)
        self.setWindowTitle("防火墙规则管理器")
        #self.updateDB()
        
    def getFirewallRules(self,host):
        try:
            res=self.seccomm.remoteExecute(host,SERVER_PORT,"getFirewallRules")
        except socket.error as e:
            message=QMessageBox(QMessageBox.NoIcon, "异常", "{}\n由于 {}:{} 连接异常，无法获取该机器的防火墙规则".format(str(e),host,SERVER_PORT))
            message.exec()
            raise e
        return res
        
    def hostFilterEditingFinished(self):
        filter=self.textbox_ip.text()
        self.ruleModel.setFilter(("rules.host like '%{}%'".format(filter)))
        self.ruleModel.select()
    
    def expandRule(self):
        row =self.ruleModel.rowCount()#返回qtableview显示的行数
        if row==0:return
        hosts=[]
        query=QSqlQuery()
        #query.exec_("""select host,direction,ip,port,protocol,action,name from rules""")
        for r in range(row):
            subnet=self.ruleModel.data(self.ruleModel.index(r, RULES_HOST))
            direction = self.ruleModel.data(self.ruleModel.index(r, RULES_DIRECTION))
            ip = self.ruleModel.data(self.ruleModel.index(r, RULES_IP))
            port = self.ruleModel.data(self.ruleModel.index(r, RULES_PORT))
            protocol = self.ruleModel.data(self.ruleModel.index(r, RULES_PROTOCOL))
            action = self.ruleModel.data(self.ruleModel.index(r, RULES_ACTION))
            name = self.ruleModel.data(self.ruleModel.index(r, RULES_NAME))
            if "/" not in subnet and "-" not in subnet:
                continue
            subnet=parseSubnet(subnet)
            for host in subnet:
                hosts.append({"host":host,"direction":direction,"ip":ip,"port":port,"protocol":protocol,"action":action,"name":name})
        for host in hosts:
            #query.exec_("select count(*) from hosts where host='{0}'".format(host["host"]))
            #if query.next() and query.value(0)!=0:
            #    continue
            QSqlDatabase.database().transaction()
            query.exec_("insert into rules(host,direction,ip,port,protocol,action,name) values('{0}','{1}','{2}','{3}','{4}','{5}','{6}')".format(host["host"],host["direction"],host["ip"],host["port"],host["protocol"],host["action"],host["name"]))
            QSqlDatabase.database().commit()
        self.ruleModel.select()
        return
            
    def updateDB(self):
        #row =self.ruleModel.rowCount()#返回qtableview显示的行数
        #if row==0:return
        hosts=[]
        query=QSqlQuery()
        query.exec_("""select host from hosts""")
        while query.next():
            host=query.value(0)
            hosts.append(host)
        #for r in range(row):
        #    host=self.ruleModel.data(self.ruleModel.index(r, HOST))
        #    if host not in hosts:
        #        hosts.append(host)
        #for i in range(row-1,-1,-1):
        #    self.ruleModel.removeRow(i)
        #self.ruleModel.submitAll()
        for host in hosts:
            query=QSqlQuery()
            QSqlDatabase.database().transaction()
            query.exec_("DELETE FROM rules where host='{0}' and pushed='0'".format(host))
            self.ruleModel.select()
            try:
                if "/" in host or "-" in host:
                    continue
                lines = self.getFirewallRules(host)
            except Exception as e:
                msg="\"{}\" occurs while getFirewallRules in {}:{},rollback...".format(str(e),host,SERVER_PORT)
                print(msg)
                logging.error(msg)
                QSqlDatabase.database().rollback()
                self.ruleModel.select()
                continue
            for line in lines.split("\n"):
                if not len(line):
                    continue
                tmp = line.split("|")
                direction = tmp[0].strip()
                ip = tmp[1].strip()
                port= tmp[2].replace("dpts:","").replace("dpt:","").replace("-",":").strip()
                protocol=tmp[3].strip()
                action=tmp[4].strip()
                try:
                    rule_time=tmp[5]
                except:
                    rule_time=''
                logging.info("pull from remote firewall:({},{},{},{},{},{},{})".format(host,direction,ip,port,protocol,action,rule_time))
                query.exec_("update rules set pushed='temp' where host='{0}' and direction='{1}' and ip='{2}' and port='{3}' and protocol='{4}' and action='{5}'".format(host,direction,ip,port,protocol,action))
                query.exec_("select host from rules where host='{0}' and direction='{1}' and ip='{2}' and port='{3}' and protocol='{4}' and action='{5}'".format(host,direction,ip,port,protocol,action))
                if not query.next():
                    if len(rule_time)!=0:
                        logging.info("INSERT into rules(host,direction,ip,port,protocol,action,time,pushed) values('{}','{}','{}','{}','{}','{}','{}','{}')".format(host,direction,ip,port,protocol,action,rule_time,'temp'))
                        query.exec_("INSERT into rules(host,direction,ip,port,protocol,action,time,pushed) values('{}','{}','{}','{}','{}','{}','{}','{}')".format(host,direction,ip,port,protocol,action,rule_time,'temp'))
                    else:
                        logging.info("INSERT into rules(host,direction,ip,port,protocol,action,pushed) values('{}','{}','{}','{}','{}','{}','{}')".format(host,direction,ip,port,protocol,action,'temp'))
                        query.exec_("INSERT into rules(host,direction,ip,port,protocol,action,pushed) values('{}','{}','{}','{}','{}','{}','{}')".format(host,direction,ip,port,protocol,action,'temp'))
            query.exec_("DELETE FROM rules where host='{0}' and pushed='1'".format(host))
            #self.ruleModel.select()
            #time.sleep(1)
            query.exec_("update rules set pushed='1' where host='{0}' and pushed='{1}'".format(host,'temp'))
            QSqlDatabase.database().commit()
            self.ruleModel.select()
            #time.sleep(1)
        #self.ruleModel.select()
        
    def updateFirewall(self):#direction,ip,protocol,port,action,time
        row =self.ruleModel.rowCount()#返回qtableview显示的行数
        if row==0:return
        hosts=[]
        rules={}
        query=QSqlQuery()
        for r in range(row):
            host=self.ruleModel.data(self.ruleModel.index(r, RULES_HOST))
            if host not in hosts:
                hosts.append(host)
                rules[host]=[]
            direction=self.ruleModel.data(self.ruleModel.index(r, RULES_DIRECTION))
            ip=self.ruleModel.data(self.ruleModel.index(r, RULES_IP))
            protocol=self.ruleModel.data(self.ruleModel.index(r, RULES_PROTOCOL))
            port=self.ruleModel.data(self.ruleModel.index(r, RULES_PORT))
            action=self.ruleModel.data(self.ruleModel.index(r, RULES_ACTION))
            rule_time=self.ruleModel.data(self.ruleModel.index(r, RULES_TIME))
            rules[host].append({"direction":direction,"ip":ip,"protocol":protocol,"port":port,"action":action,"time":rule_time})
        for host in hosts:
            directions=[]
            ips=[]
            protocols=[]
            ports=[]
            actions=[]
            times=[]
            for rule in rules[host]:
                directions.append(rule['direction'])
                ips.append(rule['ip'])
                protocols.append(rule['protocol'])
                ports.append(rule['port'])
                actions.append(rule['action'])
                times.append(rule['time'])
            directions=",".join(directions)
            ips=",".join(ips)
            protocols=",".join(protocols)
            ports=",".join(ports)
            actions=",".join(actions)
            times=",".join(times)
            #cmd1="".format(names)
            cmd="addRule?direction={}&ip={}&protocol={}&port={}&action={}&name={}".format(directions,ips,protocols,ports,actions,times)
            if "/" not in host and "-" not in host:
                try:
                    self.seccomm.remoteExecute(host,SERVER_PORT,cmd)
                    QSqlDatabase.database().transaction()
                    sql="update rules set pushed='1' where host='{0}'".format(host)
                    query.exec_(sql)
                    QSqlDatabase.database().commit()
                    self.ruleModel.select()
                except socket.error as e:
                    err_msg = "{0}\n由于 {1}:{2} 连接异常，无法更新该主机的防火墙规则".format(e,host,SERVER_PORT)
                    message=QMessageBox(QMessageBox.NoIcon, "异常", err_msg)
                    logging.error(err_msg)
                    message.exec()
                except Exception as e:
                    err_msg = "异常{0}\n{1}:{2}".format(e,host,SERVER_PORT)
                    message=QMessageBox(QMessageBox.NoIcon, "异常", err_msg)
                    logging.error(err_msg)
                    message.exec()
            
    def done(self, result=1):
        QDialog.done(self, 1)
        
    def setPassword(self):
        form = SetPasswordDlg("password", "password", self)
        form.exec_()
        
    def viewPasswordLog(self):
        form = PasswordLogDlg("password_log", "password_log", self)
        form.exec_()
        
    def editHosts(self):
        form = HostReferenceDataDlg("hosts", "host", self)
        form.exec_()
        
    def ruleChanged(self, index):
        if index.isValid():
            record = self.ruleModel.record(index.row())
            #print(index.row())
            id = record.value("id")

    def addRule(self):
        #print("current index:{}".format(self.ruleView.currentIndex().row()))
        QSqlDatabase.database().transaction()
        row = 0
        query = QSqlQuery()
        query.exec_("SELECT COUNT(id) FROM rules")
        if query.next():
            row = query.value(0)
        self.ruleModel.insertRow(row)
        index = self.ruleModel.index(row, RULES_HOST)
        self.ruleView.setCurrentIndex(index)
        self.ruleView.edit(index)
        self.ruleModel.submitAll()
        QSqlDatabase.database().commit()
        #self.ruleModel.select()
        #self.ruleView.resizeColumnsToContents()
        
    def deleteRule(self):
        index = self.ruleView.currentIndex()
        if not index.isValid():
            return
        QSqlDatabase.database().transaction()
        record = self.ruleModel.record(index.row())
        ruleid = record.value(RULES_ID)
        msg = ("<font color=red>删除</font><br><b>规则 {0}</b>?").format(record.value(RULES_ID))
        if (QMessageBox.question(self, "删除规则", msg,QMessageBox.Yes|QMessageBox.No) ==QMessageBox.No):
            QSqlDatabase.database().rollback()
            return
        host = record.value(RULES_HOST)
        direction = record.value(RULES_DIRECTION)
        ip=record.value(RULES_IP)
        port=record.value(RULES_PORT)
        protocol=record.value(RULES_PROTOCOL)
        action=record.value(RULES_ACTION)
        rule_time=record.value(RULES_TIME)
        pushed = record.value(RULES_PUSHED)
        cmd="delRule?direction={}&ip={}&protocol={}&port={}&action={}&name={}".format(direction,ip,protocol,port,action,rule_time)
        if ("/" not in host and "-" not in host and pushed == '1'):
            try:
                self.seccomm.remoteExecute(host,SERVER_PORT,cmd)
            except socket.error as e:
                QSqlDatabase.database().rollback()
                err_msg = "{0}\n由于 {1}:{2} 连接异常，此规则暂时无法删除".format(str(e),host,SERVER_PORT)
                logging.error(err_msg)
                message=QMessageBox(QMessageBox.NoIcon, "异常", err_msg)
                message.exec()
                return
            except Exception as e:
                QSqlDatabase.database().rollback()
                err_msg = "异常{0}\n{1}:{2}".format(e,host,SERVER_PORT)
                message=QMessageBox(QMessageBox.NoIcon, "异常", err_msg)
                logging.error(err_msg)
                message.exec()
        self.ruleModel.removeRow(index.row())
        self.ruleModel.submitAll()
        QSqlDatabase.database().commit()
        self.ruleModel.select()
        self.ruleChanged(self.ruleView.currentIndex())
        
def changePasswordThread():
    seccomm = SecComm(AES_KEY)
    while True:
        query = QSqlQuery()
        QSqlDatabase.database().transaction()
        query.exec_("""select host,username,time from (SELECT host,username,time FROM password_log union select host,username,0 from hosts) group by host having julianday(datetime('now', 'localtime')) - julianday(time) >={}""".format(CHANGE_PASSWORD_FREQUENCY))
        while query.next():
            host = query.value(0)
            username = query.value(1)
            #logging.info(host)
            new_password=gen_random_name()
            #new_password="abcd1234"
            try:
                if len(username):
                    res=seccomm.remoteExecute(host,SERVER_PORT,"changePassword?username={0}&password={1}".format(username,new_password))
                    query.exec_("""INSERT INTO password_log (host,username,password) VALUES("{0}","{1}","{2}")""".format(host,username,new_password))
                else:
                    res=seccomm.remoteExecute(host,SERVER_PORT,"changePassword?password={0}".format(new_password))
                    query.exec_("""INSERT INTO password_log (host,password) VALUES("{0}","{1}")""".format(host,new_password))
                logging.info("set password in host {0} to {1}".format(host,new_password))
                if host.strip()=="127.0.0.1":
                    print("主机{0}的密码已经修改为{1}，请谨记！".format(host,new_password))
            except Exception as e:
                logging.error(e)
                QSqlDatabase.database().rollback()
        QSqlDatabase.database().commit()
        logging.info("begin to sleep")
        time.sleep(CHECK_CHANGE_PASSWORD_INTERVAL)

def main():
    global form
    app = QApplication(sys.argv)
    filename = os.path.join(os.path.dirname(__file__), "rules.db")
    create = not QFile.exists(filename)
    db = QSqlDatabase.addDatabase("QSQLITE")
    db.setDatabaseName(filename)
    if not db.open():
        QMessageBox.warning(None, "防火墙规则管理器",("Database Error: {0}".format(db.lastError().text())))
        sys.exit(1)
    if create:
        app.setOverrideCursor(QCursor(Qt.WaitCursor))
        app.processEvents()
        createDB()
    form = MainForm()
    form.show()
    if create:
        app.processEvents()
        app.restoreOverrideCursor()
    #应客户要求，此处不使用定期修改随机密码的形式
    #chgPwdTread= threading.Thread(target=changePasswordThread)
    #chgPwdTread.start()
    app.exec_()
    del form
    del db

main()