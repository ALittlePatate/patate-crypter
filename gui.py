# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'gui.ui'
#
# Created by: PyQt5 UI code generator 5.15.6
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import QCoreApplication
from obfuscation import obfuscate
import os, shutil

class Ui_mainWindow(object):
    def __init__(self) :
        self.xor = False
        self.cflow = False
        self.junk = False
        
    def setupUi(self, mainWindow):
        mainWindow.setObjectName("mainWindow")
        mainWindow.setEnabled(True)
        mainWindow.resize(262, 289)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(mainWindow.sizePolicy().hasHeightForWidth())
        mainWindow.setSizePolicy(sizePolicy)
        mainWindow.setMinimumSize(QtCore.QSize(262, 289))
        mainWindow.setMaximumSize(QtCore.QSize(262, 289))
        self.centralwidget = QtWidgets.QWidget(mainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.pushButton = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton.setGeometry(QtCore.QRect(30, 30, 75, 23))
        self.pushButton.setObjectName("pushButton")
        self.checkBox = QtWidgets.QCheckBox(self.centralwidget)
        self.checkBox.setEnabled(True)
        self.checkBox.setGeometry(QtCore.QRect(20, 80, 81, 17))
        self.checkBox.setObjectName("checkBox")
        self.lineEdit = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit.setGeometry(QtCore.QRect(120, 90, 113, 20))
        self.lineEdit.setObjectName("lineEdit")
        self.label = QtWidgets.QLabel(self.centralwidget)
        self.label.setEnabled(True)
        self.label.setGeometry(QtCore.QRect(160, 70, 47, 13))
        self.label.setObjectName("label")
        self.pushButton_2 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_2.setGeometry(QtCore.QRect(10, 220, 241, 41))
        self.pushButton_2.setObjectName("pushButton_2")
        self.label_2 = QtWidgets.QLabel(self.centralwidget)
        self.label_2.setGeometry(QtCore.QRect(20, 200, 201, 21))
        self.label_2.setObjectName("label_2")
        self.checkBox_2 = QtWidgets.QCheckBox(self.centralwidget)
        self.checkBox_2.setGeometry(QtCore.QRect(20, 120, 91, 16))
        self.checkBox_2.setObjectName("checkBox_2")
        self.spinBox = QtWidgets.QSpinBox(self.centralwidget)
        self.spinBox.setGeometry(QtCore.QRect(155, 118, 42, 22))
        self.spinBox.setObjectName("spinBox")
        self.spinBox.setValue(5)
        self.spinBox.setMinimum(1)
        self.label_3 = QtWidgets.QLabel(self.centralwidget)
        self.label_3.setGeometry(QtCore.QRect(120, 122, 47, 13))
        self.label_3.setObjectName("label_3")
        self.checkBox_3 = QtWidgets.QCheckBox(self.centralwidget)
        self.checkBox_3.setGeometry(QtCore.QRect(20, 140, 91, 16))
        self.checkBox_3.setObjectName("checkBox_3")
        mainWindow.setCentralWidget(self.centralwidget)
        self.statusbar = QtWidgets.QStatusBar(mainWindow)
        self.statusbar.setEnabled(True)
        self.statusbar.setSizeGripEnabled(False)
        self.statusbar.setObjectName("statusbar")
        mainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(mainWindow)
        QtCore.QMetaObject.connectSlotsByName(mainWindow)
        
        # Create a QTimer to call the mainloop function every frame
        self.timer = QtCore.QTimer()
        self.timer.timeout.connect(self.mainloop)
        self.timer.start(16)  # Adjust the interval as needed (16 milliseconds for ~60 FPS)

    def retranslateUi(self, mainWindow):
        _translate = QtCore.QCoreApplication.translate
        mainWindow.setWindowTitle(_translate("mainWindow", "patate\'s crypter"))
        self.pushButton.setText(_translate("mainWindow", "Select file"))
        self.pushButton.clicked.connect(self.fileDialog)
        self.checkBox.setText(_translate("mainWindow", "XOR Encrypt"))
        self.label.setText(_translate("mainWindow", "Key :"))
        self.pushButton_2.setText(_translate("mainWindow", "Generate"))
        self.pushButton_2.clicked.connect(self.generate)
        self.label_2.setText(_translate("mainWindow", ""))
        self.label_2.hide()
        self.label_3.setText(_translate("mainWindow", "Pass :"))
        self.checkBox_2.setText(_translate("mainWindow", "Add junk code"))
        self.checkBox_3.setText(_translate("mainWindow", "Control flow"))
    
    def generate(self) :
        in_filename = self.pushButton.text()
        out_filename = in_filename.split(".")[0] + "_out.exe"
        xor_key = ''

        if self.xor :
            xor_key = self.lineEdit.text()
        
        self.label_2.show()
        
        if not os.path.exists(in_filename):
            self.label_2.setText(f"\"{in_filename}\" does not exist!")
            QCoreApplication.processEvents()
            return
    
        self.label_2.setText("Creating sample header...")
        QCoreApplication.processEvents()

        file = bytearray(open(in_filename, 'rb').read())
        with open("sample.h", 'w') as output:
            output.write("unsigned char sample[] = { ")
            for count, byte in enumerate(file, 1):
                if xor_key :
                    output.write(
                        f'{byte ^ ord(xor_key[(count - 1) % len(xor_key)]):#0{4}x},' + (
                            '\n' if not count % 16 else ' '))
                else :
                    output.write(f'{byte:#0{4}x},' + ('\n' if not count % 16 else ' '))
                    
            output.write("};")
        
        self.label_2.setText("done.")
        QCoreApplication.processEvents()
        
        # Working with a copy of main.cpp
        os.rename("main.cpp", "DO_NOT_TOUCH.cpp")
        shutil.copyfile('DO_NOT_TOUCH.cpp', 'main.cpp')
        with open("config.h", "w") as c :
            c.write(f'#pragma once\n#define KEY "{xor_key}"')
        
        if self.cflow : # Make control flow stuff
            pass
            
        if self.junk : # Add junk code
            self.label_2.setText("Adding junk code...")
            QCoreApplication.processEvents()
            print(self.spinBox.value())
            obfuscate(self.spinBox.value())
            self.label_2.setText("done.")
            QCoreApplication.processEvents()
        
        self.label_2.setText("Compiling...")
        QCoreApplication.processEvents()
        
        vs_path = os.popen("\"%ProgramFiles(x86)%/Microsoft Visual Studio/Installer/vswhere.exe\" -nologo -latest -property installationPath").read().replace("\n","") #https://stackoverflow.com/questions/46223916/msbuild-exe-not-found-cmd-exe
        cmd_line = vs_path + "\\Msbuild\\Current\\Bin\\MSBuild.exe"

        os.system("\""+cmd_line+"\" . /p:Configuration=Release;Platform=x86;OutDir=.;DebugSymbols=false;DebugType=None;TargetExt=.exe;TargetName="+out_filename.replace(".exe", "")+"  /t:Rebuild")
        # Cleaning up..
        os.remove("main.cpp")
        os.rename("DO_NOT_TOUCH.cpp", "main.cpp")
        
        self.label_2.setText(f"--> {out_filename}")
        QCoreApplication.processEvents()
    
    def fileDialog(self):
        options = QtWidgets.QFileDialog.Options()
        options |= QtWidgets.QFileDialog.ReadOnly
        filePath, _ = QtWidgets.QFileDialog.getOpenFileName(
            None, "Select a file", "", "Dll Files (*.dll);;All Files (*)", options=options)
        if filePath:
            # Display the selected file path in the QLineEdit
            self.pushButton.setText(filePath.split("/")[-1:][0])
            
    def mainloop(self) :
        self.xor = self.checkBox.isChecked()
        self.cflow = self.checkBox_3.isChecked()
        self.junk = self.checkBox_2.isChecked()

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    mainWindow = QtWidgets.QMainWindow()
    ui = Ui_mainWindow()
    ui.setupUi(mainWindow)
    mainWindow.show()
    sys.exit(app.exec_())
