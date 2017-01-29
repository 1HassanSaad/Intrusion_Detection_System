from PyQt4.QtCore import *
from PyQt4.QtGui import *
import sys
from LIB import sniffer

FLAG = -1
class Form(QWidget):
	def __init__(self):
		super(Form,self).__init__()
		self.showMaximized()
		f1 = open("User Interface/file_data","w")
		f1.close()
		f = open("User Interface/style","r")
		style = f.read()
		f.close()
		self.setStyleSheet(style)
		self.setWindowTitle("YacyShark")
		self.thread1 = thread()
		self.connect(self.thread1,SIGNAL('VALUE'),self.update)
		self.horizontalLayout_2 = QHBoxLayout(self)
		self.verticalLayout = QVBoxLayout()
		self.tableWidget = QTableWidget(self)
		self.verticalLayout.addWidget(self.tableWidget)
		self.horizontalLayout = QHBoxLayout()
		self.pushButton = QPushButton(self,text="Start")
		self.horizontalLayout.addWidget(self.pushButton)
		self.pushButton_2 = QPushButton(self,text="Stop")
		self.horizontalLayout.addWidget(self.pushButton_2)
		self.pushButton_3 = QPushButton(self,text="AutoSC")
		self.horizontalLayout.addWidget(self.pushButton_3)
		self.pushButton_4 = QPushButton(self,text="ManualSC")
		self.horizontalLayout.addWidget(self.pushButton_4)
		self.verticalLayout.addLayout(self.horizontalLayout)
		self.horizontalLayout_2.addLayout(self.verticalLayout)
		self.tableWidget.setEditTriggers(QAbstractItemView.NoEditTriggers)
		self.tableWidget.setShowGrid(False)
		self.tableWidget.setColumnCount(9)
		self.tableWidget.setSelectionBehavior(QAbstractItemView.SelectRows)
		self.tableWidget.setFocusPolicy(Qt.ClickFocus)
		self.tableWidget.verticalHeader().setVisible(False)
		self.tableWidget.verticalHeader().setDefaultSectionSize(18)
		self.tableWidget.doubleClicked.connect(self.viewClicked)
		self.pushButton.clicked.connect(self.start)
		self.pushButton_2.clicked.connect(self.stop)
		self.tableWidget.setColumnWidth(0, 80)
		self.tableWidget.setColumnWidth(1, 120)
		self.tableWidget.setColumnWidth(2, 100)
		self.tableWidget.setColumnWidth(3, 120)
		self.tableWidget.setColumnWidth(4, 170)
		self.tableWidget.setColumnWidth(5, 120)
		self.tableWidget.setColumnWidth(6, 170)
		self.tableWidget.setColumnWidth(7, 120)
		self.tableWidget.setColumnWidth(8, 350)
		#######Headers
		item = QTableWidgetItem("No.")
		self.tableWidget.setHorizontalHeaderItem(0, item)
		item = QTableWidgetItem("Time")
		self.tableWidget.setHorizontalHeaderItem(1, item)
		item = QTableWidgetItem("E-Type")
		self.tableWidget.setHorizontalHeaderItem(2, item)
		item = QTableWidgetItem("Protocol")
		self.tableWidget.setHorizontalHeaderItem(3, item)
		item1 = QTableWidgetItem("Source")
		self.tableWidget.setHorizontalHeaderItem(4, item1)
		item1 = QTableWidgetItem("SRC_PORT")
		self.tableWidget.setHorizontalHeaderItem(5, item1)
		item = QTableWidgetItem("Destination")
		self.tableWidget.setHorizontalHeaderItem(6, item)
		item = QTableWidgetItem("DST_PORT")
		self.tableWidget.setHorizontalHeaderItem(7, item)
		item = QTableWidgetItem("DATA")
		self.tableWidget.setHorizontalHeaderItem(8, item)
		#######Headers

	def update(self,retn_data):
		global FLAG
		rowPosition = self.tableWidget.rowCount()
		self.tableWidget.insertRow(rowPosition)
		item1 = QTableWidgetItem(str(retn_data['num']))
		self.tableWidget.setItem(rowPosition, 0, item1)
		item2 = QTableWidgetItem(str(retn_data['time']))
		self.tableWidget.setItem(rowPosition, 1, item2)
		item3 = QTableWidgetItem(str(retn_data['ether_type']))
		self.tableWidget.setItem(rowPosition, 2, item3)
		item4 = QTableWidgetItem(str(retn_data['proto']))
		self.tableWidget.setItem(rowPosition, 3, item4)
		if (retn_data['src_ip'] == ''):
			item5 = QTableWidgetItem(str(retn_data['src_mac']))
			self.tableWidget.setItem(rowPosition, 4, item5)
			item7 = QTableWidgetItem(str(retn_data['dst_mac']))
			self.tableWidget.setItem(rowPosition, 6, item7)
		else:
			item5 = QTableWidgetItem(str(retn_data['src_ip']))
			self.tableWidget.setItem(rowPosition, 4, item5)
			item7 = QTableWidgetItem(str(retn_data['dst_ip']))
			self.tableWidget.setItem(rowPosition, 6, item7)
		item6 = QTableWidgetItem(str(retn_data['src_port']))
		self.tableWidget.setItem(rowPosition, 5, item6)
		item8 = QTableWidgetItem(str(retn_data['dst_port']))
		self.tableWidget.setItem(rowPosition, 7, item8)
		item9 = QTableWidgetItem(str(retn_data['pure_data']))
		self.tableWidget.setItem(rowPosition, 8, item9)
		if retn_data['num']%2 == 0:
			x=68
			y=72
			z=76
			x1=47
			y1=145
			z1=196
			item1.setBackground(QColor(x,y,z))
			item1.setTextColor(QColor(x1,y1,z1))
			item2.setBackground(QColor(x,y,z))
			item2.setTextColor(QColor(x1,y1,z1))
			item3.setBackground(QColor(x,y,z))
			item3.setTextColor(QColor(x1,y1,z1))
			item4.setBackground(QColor(x,y,z))
			item4.setTextColor(QColor(x1,y1,z1))
			item5.setBackground(QColor(x,y,z))
			item5.setTextColor(QColor(x1,y1,z1))
			item6.setBackground(QColor(x,y,z))
			item6.setTextColor(QColor(x1,y1,z1))
			item7.setBackground(QColor(x,y,z))
			item7.setTextColor(QColor(x1,y1,z1))
			item8.setBackground(QColor(x,y,z))
			item8.setTextColor(QColor(x1,y1,z1))
			item9.setBackground(QColor(x,y,z))
			item9.setTextColor(QColor(x1,y1,z1))
		self.tableWidget.scrollToItem(item1)
		FLAG = 1


	def viewClicked(self, clickedIndex):
		row=clickedIndex.row()
		new = New(row)

	def start(self):
		self.thread1.start()

	def stop(self):
		self.thread1.terminate()

class New(QDialog):
	def __init__(self,row,parent=None):
		super(New, self).__init__(parent)
		f = open("User Interface/style","r")
		style = f.read()
		f.close()
		self.setStyleSheet(style)
		self.setWindowTitle("YacyShark")
		file_data = open("User Interface/file_data","r")
		searchlines = file_data.readlines()
		file_data.close()
		index1 = str(searchlines).index("num:"+str(row))
		index2 = str(searchlines).index("num:"+str(row+1))
		new_data = str(searchlines)[index1:index2]
		self.resize(680, 342)
		self.verticalLayout_2 = QVBoxLayout(self)
		self.verticalLayout = QVBoxLayout()
		self.textBrowser = QTextBrowser(self)
		self.textBrowser.setTabChangesFocus(True)
		self.verticalLayout.addWidget(self.textBrowser)
		self.label = QLabel(self,text="THE PACKET DATA")
		self.label.setLayoutDirection(Qt.LeftToRight)
		self.label.setFrameShape(QFrame.StyledPanel)
		self.label.setTextFormat(Qt.LogText)
		self.label.setScaledContents(True)
		self.label.setAlignment(Qt.AlignCenter)
		self.verticalLayout.addWidget(self.label)
		self.verticalLayout_2.addLayout(self.verticalLayout)
		self.textBrowser.append(str(new_data))
		self.textBrowser.setStyleSheet("color : #C0DEED;");
		self.textBrowser.moveCursor(QTextCursor.Start)
		self.show()
		self.exec_()

class thread(QThread):
	def __init__(self):
		QWidget.__init__(self)

	def run(self):
		global FLAG
		while 1:
			FLAG = 0
			retn_data = sniffer()
			self.emit(SIGNAL("VALUE"),retn_data)
			while(FLAG != 1):
				xxxxx=1

app = QApplication(sys.argv)
form = Form()
form.show()
app.exec_()
