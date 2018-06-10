#!/usr/bin/env python3
#encoding=utf-8
from Cryptodome.Cipher import AES  
from binascii import b2a_hex, a2b_hex
import os,sys,socket,threading,time,datetime,logging
from PyQt5.QtCore import (PYQT_VERSION_STR, QDate, QFile, QRegExp, QVariant, QModelIndex,Qt)
from PyQt5.QtWidgets import (QApplication,QComboBox,
                             QDateTimeEdit, QDialog, QGridLayout, QHBoxLayout, QLabel,
                             QLineEdit, QDateEdit,QMessageBox, QPushButton,
                             QStyleOptionViewItem, QTableView,QVBoxLayout)
from PyQt5.QtGui import QPixmap,QCursor,QRegExpValidator
from PyQt5.QtSql import (QSqlDatabase, QSqlQuery, QSqlRelation,
                         QSqlRelationalDelegate, QSqlRelationalTableModel,QSqlTableModel)
FORMAT = '[%(levelname)s]\t%(asctime)s : %(message)s'
LOG_NAME = datetime.datetime.now().strftime('FirewallTool_Client_%Y_%m_%d_%H.log')
logging.basicConfig(filename=LOG_NAME, level = logging.DEBUG, format=FORMAT)
MAC = True
try:
    from PyQt5.QtGui import qt_mac_set_native_menubar
except ImportError:
    MAC = False

#password表
ID = 0
HOST = 1
PASSWORD=2
#hosts表
ID = 0
HOST = 1
DESCRIPTION= 2 
TIME=3
#rules表
ID = 0
HOST = 1
DIRECTION = 2
IP  = 3
PORT = 4
PROTOCOL = 5
ACTION =6
NAME = 7
#服务器监听的端口
SERVER_PORT=7777
#几天修改一次密码
CHANGE_PASSWORD_FREQUENCY=7
#几秒检查一次密码是否到期了，8*60*60表示8小时
CHECK_CHANGE_PASSWORD_INTERVAL=8*60*60

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
                description VARCHAR(40) NOT NULL,
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
                name DATETIME DEFAULT (datetime('now', 'localtime')),
                UNIQUE(host,direction,ip,port,protocol),
                FOREIGN KEY (host) REFERENCES hosts(host),
                FOREIGN KEY (direction) REFERENCES direction(name),
                FOREIGN KEY (protocol) REFERENCES protocol(name),
                FOREIGN KEY (action) REFERENCES action(name))""")
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
    query.exec_("""CREATE TABLE if not exists password (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host VARCHAR(32) NOT NULL,
                password VARCHAR(20) NOT NULL,
                time DATETIME DEFAULT (datetime('now', 'localtime')),
                FOREIGN KEY (host) REFERENCES hosts(host)
                )""")
    QApplication.processEvents()

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
        try:
            clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            clientsocket.settimeout(1)
            clientsocket.connect((host, port))
        except socket.error as e:
            msg='fail to setup socket connection {}:{},because:{}'.format(host,port,str(e))
            logging.error(msg)
            #print(msg)
            clientsocket.close()
            raise e
            return
        logging.info("send to {}:{}>>>>>>>>>>>>\n{}".format(host,port,command))
        command=bytes(command,encoding="utf-8")
        command = self.encrypt(command)
        clientsocket.send(command)
        res = clientsocket.recv(65536) 
        res=self.decrypt(res)        
        res = res.decode("utf-8")
        logging.info("recv from {}:{}<<<<<<<<<<<<\n{}".format(host,port,res))
        clientsocket.close()
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

class PasswordDlg(QDialog):
    def __init__(self, table, title, parent=None):
        super(PasswordDlg, self).__init__(parent)
        self.model = QSqlRelationalTableModel(self)
        self.model.setTable(table)
        self.model.setRelation(HOST,QSqlRelation("hosts", "host", "host"))
        self.model.setSort(TIME, Qt.DescendingOrder)
        self.model.setHeaderData(ID, Qt.Horizontal,"ID")
        self.model.setHeaderData(HOST, Qt.Horizontal, "主机ip")
        self.model.setHeaderData(DESCRIPTION, Qt.Horizontal,"密码")
        self.model.setHeaderData(TIME, Qt.Horizontal,"时间")
        self.model.select()

        self.view = QTableView()
        self.view.setModel(self.model)
        self.view.setItemDelegate(PasswordRuleDelegate(self))#设置所有列不可修改
        self.view.setSelectionMode(QTableView.SingleSelection)
        self.view.setSelectionBehavior(QTableView.SelectRows)
        self.view.setColumnWidth(ID, 30)
        self.view.setColumnWidth(HOST, 168)
        self.view.setColumnWidth(PASSWORD, 144)
        self.view.setColumnWidth(TIME, 168)
        self.setMinimumWidth(640)
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
        self.model.setFilter(("password.host like '%{}%'".format(filter)))
        self.model.select()
        
class ReferenceDataDlg(QDialog):
    def __init__(self, table, title, parent=None):
        super(ReferenceDataDlg, self).__init__(parent)
        self.model = QSqlTableModel(self)
        #self.model.setEditStrategy(QSqlTableModel.OnFieldChange)
        self.model.setEditStrategy(QSqlTableModel.OnManualSubmit)#设置更新数据库的策略，手动更新数据库
        self.model.dataChanged.connect(self.model.submitAll)#在model变化时写入数据库
        self.model.setTable(table)
        self.model.setSort(HOST, Qt.AscendingOrder)
        self.model.setHeaderData(ID, Qt.Horizontal,"ID")
        self.model.setHeaderData(HOST, Qt.Horizontal, "主机ip")
        self.model.setHeaderData(DESCRIPTION, Qt.Horizontal,"描述")
        self.model.setHeaderData(TIME, Qt.Horizontal,"时间")
        self.model.select()

        self.view = QTableView()
        self.view.setModel(self.model)
        self.view.setItemDelegate(RuleDelegate(self))#设置id列不可修改
        self.view.setSelectionMode(QTableView.SingleSelection)
        self.view.setSelectionBehavior(QTableView.SelectRows)
        #self.view.setColumnHidden(ID, True)
        #self.view.resizeColumnsToContents()
        self.view.setColumnWidth(ID, 30)
        self.view.setColumnWidth(HOST, 168)
        self.view.setColumnWidth(DESCRIPTION, 144)
        self.view.setColumnWidth(TIME, 168)
        self.setMinimumWidth(640)
        self.setMinimumHeight(480)
        addButton = QPushButton("&添加")
        deleteButton = QPushButton("&删除")
        okButton = QPushButton("&完成")
        if not MAC:
            addButton.setFocusPolicy(Qt.NoFocus)
            deleteButton.setFocusPolicy(Qt.NoFocus)

        buttonLayout = QHBoxLayout()
        buttonLayout.addWidget(addButton)
        buttonLayout.addWidget(deleteButton)
        buttonLayout.addStretch()
        buttonLayout.addWidget(okButton)
        layout = QVBoxLayout()
        layout.addWidget(self.view)
        layout.addLayout(buttonLayout)
        self.setLayout(layout)

        addButton.clicked.connect(self.addRecord)
        deleteButton.clicked.connect(self.deleteRecord)
        okButton.clicked.connect(self.ok)

        self.setWindowTitle("防火墙规则管理器 - 编辑 {0} 引用数据".format(title))
                
    def ok(self):
        self.model.select()
        self.accept()#退出对话框
        
    def addRecord(self):
        row = self.model.rowCount()
        self.model.insertRow(row)
        index = self.model.index(row, HOST)
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
        host = record.value(HOST)
        table = self.model.tableName()
        query = QSqlQuery()
        if table == "hosts":
            query.exec_("SELECT COUNT(*) FROM rules WHERE host = '{0}'".format(host))
        count = 0
        if query.next():
            count = query.value(0)
            #print(count)
        if count:
            QMessageBox.information(self,
                    "删除 {0}".format(table),
                    ("不能从数据表<br>{1}删除{0}，这是由于主机还有{2}条防火墙规则没有删除").format(record.value(HOST),table,count))
            #QSqlDatabase.database().rollback()
            return
        self.model.removeRow(index.row())
        self.model.submitAll()
        self.model.select()
        #QSqlDatabase.database().commit()
        
class PasswordRuleDelegate(QSqlRelationalDelegate):
    def __init__(self, parent=None):
        super(PasswordRuleDelegate, self).__init__(parent)

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
        if index.column() == ACTION:
            myoption.displayAlignment |= (Qt.AlignRight|Qt.AlignVCenter)
        QSqlRelationalDelegate.paint(self, painter, myoption, index)

    def createEditor(self, parent, option, index):
        if index.column() == ID or index.column()==NAME:
            return
        if index.column() == IP:
            editor = QLineEdit(parent)
            editor.setPlaceholderText('1.1.1.1或1.1.1.1/24')
            editor.setAlignment(Qt.AlignRight|Qt.AlignVCenter)
            return editor
        if index.column() == PORT:
            editor = QLineEdit(parent)
            regex = QRegExp(r"^(([1-9]\d{0,3})|([1-5]\d{4})|(6[1-4]\d{3})|(65[1-4]\d{2})|(655[1-2]\d)|(6553[1-5]))(:(([1-9]\d{0,3})|([1-5]\d{4})|(6[1-4]\d{3})|(65[1-4]\d{2})|(655[1-2]\d)|(6553[1-5])))?$")
            validator = QRegExpValidator(regex, parent)
            editor.setValidator(validator)
            editor.setPlaceholderText('80或8080:8090')
            editor.setAlignment(Qt.AlignRight|Qt.AlignVCenter)
            return editor
        return QSqlRelationalDelegate.createEditor(self, parent,option, index)

    def setEditorData(self, editor, index):
        if index.column() == ID:
            return
        QSqlRelationalDelegate.setEditorData(self, editor, index)

    def setModelData(self, editor, model, index):
        QSqlRelationalDelegate.setModelData(self, editor, model,index)

class MainForm(QDialog):
    def __init__(self):
        super(MainForm, self).__init__()
        self.seccomm=SecComm(b'5xQLFb4RdA9wqYi2')
        query=QSqlQuery()
        query.exec_("PRAGMA foreign_keys = ON;")
        self.ruleModel = QSqlRelationalTableModel(self)
        #self.ruleModel.setEditStrategy(QSqlTableModel.OnFieldChange)#设置更新数据库的策略，在属性变化时写入数据库
        self.ruleModel.setEditStrategy(QSqlTableModel.OnManualSubmit)#设置更新数据库的策略，手动更新数据库
        self.ruleModel.dataChanged.connect(self.ruleModel.submitAll)#在model变化时写入数据库
        self.ruleModel.setTable("rules")
        #将rules表的第HOST个属性设为hosts表的host属性外键，并将其显示为hosts表的host属性的值
        self.ruleModel.setRelation(HOST,QSqlRelation("hosts", "host", "host"))
        self.ruleModel.setRelation(DIRECTION,QSqlRelation("direction", "name", "name"))
        self.ruleModel.setRelation(PROTOCOL,QSqlRelation("protocol", "name", "name"))
        self.ruleModel.setRelation(ACTION,QSqlRelation("action", "name", "name"))
        self.ruleModel.setSort(ID, Qt.AscendingOrder)
        self.ruleModel.setHeaderData(ID, Qt.Horizontal,"id")
        self.ruleModel.setHeaderData(HOST, Qt.Horizontal,"主机ip")
        self.ruleModel.setHeaderData(DIRECTION, Qt.Horizontal,"方向")
        self.ruleModel.setHeaderData(IP, Qt.Horizontal,"ip/网段")
        self.ruleModel.setHeaderData(PORT, Qt.Horizontal,"端口号/端口范围")
        self.ruleModel.setHeaderData(PROTOCOL, Qt.Horizontal,"协议")
        self.ruleModel.setHeaderData(ACTION, Qt.Horizontal,"策略")
        self.ruleModel.setHeaderData(NAME, Qt.Horizontal,"规则名字")
        self.ruleModel.select()

        self.ruleView = QTableView()
        self.ruleView.setModel(self.ruleModel)
        self.ruleView.setItemDelegate(RuleDelegate(self))
        self.ruleView.setSelectionMode(QTableView.SingleSelection)
        self.ruleView.setSelectionBehavior(QTableView.SelectRows)
        #self.ruleView.setColumnHidden(NAME, True)
        #self.ruleView.resizeColumnsToContents()
        self.ruleView.setColumnWidth(ID, 54)
        self.ruleView.setColumnWidth(HOST, 128)
        self.ruleView.setColumnWidth(DIRECTION, 50)
        self.ruleView.setColumnWidth(IP, 168)
        self.ruleView.setColumnWidth(PORT, 128)
        self.ruleView.setColumnWidth(PROTOCOL, 72)
        self.ruleView.setColumnWidth(ACTION, 72)
        self.ruleView.setColumnWidth(NAME, 168)
        ruleLabel = QLabel("")
        ruleLabel.setBuddy(self.ruleView)

        label_ip=QLabel("主机过滤器: ")#绑定label到窗口
        self.textbox_ip = QLineEdit()
        self.textbox_ip.setPlaceholderText("例如：1.1.1.1 或 1.1.1 或 1.%.1,按下回车后生效")
        self.textbox_ip.setClearButtonEnabled(True)
        passwordButton = QPushButton("密码修改日志")
        #refreshButton = QPushButton("刷新规则显示")
        editHostsButton = QPushButton("编辑主机")
        addRuleButton = QPushButton("添加规则")
        deleteRuleButton = QPushButton("删除规则")
        pushButton = QPushButton("把规则推送给防火墙")
        pullButton = QPushButton("从防火墙读取规则")
        quitButton = QPushButton("退出")
        for button in (passwordButton,editHostsButton,addRuleButton, deleteRuleButton,pushButton,pullButton,quitButton):
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
        buttonLayout.addWidget(passwordButton)
        buttonLayout.addWidget(editHostsButton)
        buttonLayout.addWidget(addRuleButton)
        buttonLayout.addWidget(deleteRuleButton)
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
        #refreshButton.clicked.connect(self.refreshView)
        passwordButton.clicked.connect(self.viewPassword)
        editHostsButton.clicked.connect(self.editHosts)
        addRuleButton.clicked.connect(self.addRule)
        deleteRuleButton.clicked.connect(self.deleteRule)
        pushButton.clicked.connect(self.updateFirewall)
        pullButton.clicked.connect(self.updateDB)
        quitButton.clicked.connect(self.done)

        self.ruleChanged(self.ruleView.currentIndex())
        self.setMinimumWidth(1040)
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
            
    #def refreshView(self):
    #    self.ruleModel.select()
        
    def updateDB(self):
        row =self.ruleModel.rowCount()#返回qtableview显示的行数
        if row==0:return
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
            query.exec_("DELETE FROM rules where host='{}'".format(host))
            self.ruleModel.select()
            try:
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
                    name=tmp[5]
                except:
                    name=''
                logging.info("pull from remote firewall:({},{},{},{},{},{},{})".format(host,direction,ip,port,protocol,action,name))
                logging.info("INSERT into rules(host,direction,ip,port,protocol,action,name) values('{}','{}','{}','{}','{}','{}','{}')".format(host,direction,ip,port,protocol,action,name))
                query.exec_("INSERT into rules(host,direction,ip,port,protocol,action,name) values('{}','{}','{}','{}','{}','{}','{}')".format(host,direction,ip,port,protocol,action,name))
            QSqlDatabase.database().commit()
        self.ruleModel.select()
        
    def updateFirewall(self):#direction,ip,protocol,port,action,name
        row =self.ruleModel.rowCount()#返回qtableview显示的行数
        if row==0:return
        hosts=[]
        rules={}
        for r in range(row):
            host=self.ruleModel.data(self.ruleModel.index(r, HOST))
            if host not in hosts:
                hosts.append(host)
                rules[host]=[]
            direction=self.ruleModel.data(self.ruleModel.index(r, DIRECTION))
            ip=self.ruleModel.data(self.ruleModel.index(r, IP))
            protocol=self.ruleModel.data(self.ruleModel.index(r, PROTOCOL))
            port=self.ruleModel.data(self.ruleModel.index(r, PORT))
            action=self.ruleModel.data(self.ruleModel.index(r, ACTION))
            name=self.ruleModel.data(self.ruleModel.index(r, NAME))
            rules[host].append({"direction":direction,"ip":ip,"protocol":protocol,"port":port,"action":action,"name":name})
        for host in hosts:
            directions=[]
            ips=[]
            protocols=[]
            ports=[]
            actions=[]
            names=[]
            for rule in rules[host]:
                directions.append(rule['direction'])
                ips.append(rule['ip'])
                protocols.append(rule['protocol'])
                ports.append(rule['port'])
                actions.append(rule['action'])
                names.append(rule['name'])
            directions=",".join(directions)
            ips=",".join(ips)
            protocols=",".join(protocols)
            ports=",".join(ports)
            actions=",".join(actions)
            names=",".join(names)
            #cmd1="".format(names)
            cmd="addRule?direction={}&ip={}&protocol={}&port={}&action={}&name={}".format(directions,ips,protocols,ports,actions,names)
            try:
                self.seccomm.remoteExecute(host,SERVER_PORT,cmd)
            except socket.error as e:
                message=QMessageBox(QMessageBox.NoIcon, "异常", "{}\n由于 {}:{} 连接异常，无法更新该主机的防火墙规则".format(str(e),host,SERVER_PORT));
                message.exec();
            
    def done(self, result=1):
        QDialog.done(self, 1)
        
    def viewPassword(self):
        form = PasswordDlg("password", "password", self)
        form.exec_()
        
    def editHosts(self):
        form = ReferenceDataDlg("hosts", "host", self)
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
        index = self.ruleModel.index(row, HOST)
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
        ruleid = record.value(ID)
        msg = ("<font color=red>删除</font><br><b>规则 {0}</b>?").format(record.value(ID))
        if (QMessageBox.question(self, "删除规则", msg,QMessageBox.Yes|QMessageBox.No) ==QMessageBox.No):
            QSqlDatabase.database().rollback()
            return
        host = record.value(HOST)
        direction = record.value(DIRECTION)
        ip=record.value(IP)
        port=record.value(PORT)
        protocol=record.value(PROTOCOL)
        action=record.value(ACTION)
        name=record.value(NAME)
        cmd="delRule?direction={}&ip={}&protocol={}&port={}&action={}&name={}".format(direction,ip,protocol,port,action,name)
        try:
            self.seccomm.remoteExecute(host,SERVER_PORT,cmd)
        except socket.error as e:
            QSqlDatabase.database().rollback()
            message=QMessageBox(QMessageBox.NoIcon, "异常", "{}\n由于 {}:{} 连接异常，此规则暂时无法删除".format(str(e),host,SERVER_PORT))
            message.exec()
            return
        self.ruleModel.removeRow(index.row())
        self.ruleModel.submitAll()
        QSqlDatabase.database().commit()
        self.ruleModel.select()
        self.ruleChanged(self.ruleView.currentIndex())
        
def changePasswordThread():
    seccomm = SecComm(b'5xQLFb4RdA9wqYi2')
    while True:
        query = QSqlQuery()
        QSqlDatabase.database().transaction()
        query.exec_("""select host,time from (SELECT host,time FROM password union select host,0 from hosts) group by host having julianday(datetime('now', 'localtime')) - julianday(time) >={}""".format(CHANGE_PASSWORD_FREQUENCY))
        while query.next():
            host = query.value(0)
            #logging.info(host)
            new_password=gen_random_name()
            #new_password="abcd1234"
            try:
                res=seccomm.remoteExecute(host,SERVER_PORT,"changePassword?password={}".format(new_password))
                query.exec_("""INSERT INTO password (host,password) VALUES("{}","{}")""".format(host,new_password))
                logging.info("set password in host {} to {}".format(host,new_password))
                if host.strip()=="127.0.0.1":
                    print("主机{0}的密码已经修改为{1}，请谨记！".format(host,new_password))
            except Exception as e:
                logging.error(e)
                QSqlDatabase.database().rollback()
        QSqlDatabase.database().commit()
        logging.info("begin to sleep")
        time.sleep(CHECK_CHANGE_PASSWORD_INTERVAL)

def main():
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
    chgPwdTread= threading.Thread(target=changePasswordThread)
    chgPwdTread.start()
    app.exec_()
    del form
    del db

main()