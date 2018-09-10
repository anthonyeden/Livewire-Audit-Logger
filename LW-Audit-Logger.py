""" A simple Audit Logger for Livewire """

__product__     = "Livewire Audit Logger"
__author__      = "Anthony Eden"
__copyright__   = "Copyright 2018, Anthony Eden / Media Realm"
__credits__     = ["Anthony Eden"]
__license__     = "Commercial"
__version__     = "1.0.1"

import os, sys
sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/libs")

import json
from LWRPClient import LWRPClient
import AxiaLivewireAddressHelper
import Tkinter as tk
import tkinter.scrolledtext as ScrolledText
import tkMessageBox
import requests
import thread
import logging
from logging.handlers import *

class Application(tk.Frame):

    # Store the Livewire Routing Protocol (LWRP) client connections here
    LWRP = {}

    # Should we automatically check for version updates when the app starts up?
    autoCheckVersion = True
    newVersion = False

    def __init__(self, master = None):
        # Setup the application and display window
        self.root = tk.Tk()
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self.root.minsize(1100, 500)
        
        # Setup the application's icon - very important!
        if getattr(sys, 'frozen', False):
            self.application_path = os.path.dirname(sys.executable)
        elif __file__:
            self.application_path = os.path.dirname(__file__)

        iconfile = os.path.join(self.application_path, "AuditIcon.ico")

        try:
            self.root.iconbitmap(iconfile)
        except:
            # We don't care too much if the icon can't be included
            pass
        
        # Setup the main window for the application
        tk.Frame.__init__(self, master)
        self.rowconfigure(0, weight = 1)
        self.columnconfigure(0, weight = 1)
        self.grid(sticky = tk.N + tk.S + tk.E + tk.W)

        # Setup the logger
        self.logger = logging.getLogger()
        self.logger_formatter = logging.Formatter('%(asctime)s %(levelname)-8s %(device_name)-18s %(message)s')

        handler_onscreen = logging.StreamHandler()
        handler_file = TimedRotatingFileHandler(os.path.join(self.application_path, "LW-Audit.log"), when="midnight", backupCount=30)

        handler_onscreen.setFormatter(self.logger_formatter)
        handler_file.setFormatter(self.logger_formatter)

        self.logger.addHandler(handler_onscreen)
        self.logger.addHandler(handler_file)
        self.logger.setLevel(logging.INFO)

        # Setup interface
        self.setupMainInterface()

        # Welcome logger message
        self.logger.info("Start the Livewire Audit Logger", extra={'device_name': "SYSTEM"})
        self.logger.info("This software can be purchased from https://mediarealm.com.au/", extra={'device_name': "SYSTEM"})
        self.logger.info("If you have already purchased this software, THANK YOU! :)", extra={'device_name': "SYSTEM"})

        # Connect to devices
        thread.start_new_thread(self.connectLWRP, ())

        if self.autoCheckVersion is True:
            # Check for version updates in another thread
            thread.start_new_thread(self.versionCheck, ())

    def connectLWRP(self):
        # Tries to establish a connection to the LWRP on the specified devices

        if not os.path.isfile(os.path.join(self.application_path, "devices.txt")):
            devicesFile = open(os.path.join(self.application_path, "devices.txt"), "w")
            devicesFile.write("# Put one Livewire device IP Address per line\r\n")
            devicesFile.write("# Or, if you have a password - 111.222.333.444|password (separate IP and password with a 'pipe' symbol)\r\n")
            devicesFile.write("# Lines starting with a hash symbol are ignored\r\n")
            devicesFile.write("# IMPORTANT: You must restart the app for these changes to apply\r\n")
            devicesFile.close()

        # One IP per line, password after pipe (if requried)
        devicesFile = open(os.path.join(self.application_path, "devices.txt"), "r") 
        deviceList = devicesFile.read()
        devicesFile.close()

        devices = deviceList.split("\n")

        # Loop over every device in the file
        for deviceData in devices:
            # Trim up the file
            deviceData = deviceData.strip()

            if deviceData == "" or deviceData[:1] == "#":
                continue

            if "|" in deviceData:
                device = deviceData.split("|")
            else:
                device = [deviceData, ""]

            if device[0] in self.LWRP:
                continue

            try:
                # Create new connection for GPI device
                self.LWRP[device[0]] = {}
                self.LWRP[device[0]]['Connection'] = LWRPClient(device[0], 93)
                self.logger.info("Connected to LWRP", extra={'device_name': device[0]})

            except Exception, e:
                self.logger.warn("Cannot connect to LWRP", extra={'device_name': device[0]})
                continue

            try:
                self.LWRP[device[0]]['Connection'].login(device[1])
                self.logger.info("Logged in to LWRP", extra={'device_name': device[0]})
            except Exception, e:
                self.logger.warn("Cannot login to LWRP %s", extra={'device_name': device[0]})
                continue

            self.LWRP[device[0]]['Last_GPO'] = {}
            self.LWRP[device[0]]['Last_GPI'] = {}
            self.LWRP[device[0]]['Last_SOURCE_NAME'] = {}
            self.LWRP[device[0]]['Last_SOURCE_ROUTE'] = {}
            self.LWRP[device[0]]['Last_DESTINATION_NAME'] = {}
            self.LWRP[device[0]]['Last_DESTINATION_ROUTE'] = {}

            self.LWRP[device[0]]['Connection'].GPIDataSub(lambda x, y=device[0]: self.callbackLivewireGPIO(y, x))
            self.LWRP[device[0]]['Connection'].GPODataSub(lambda x, y=device[0]: self.callbackLivewireGPIO(y, x))
            self.LWRP[device[0]]['Connection'].sourceDataSub(lambda x, y=device[0]: self.callbackLivewireSrcDst(y, x))
            self.LWRP[device[0]]['Connection'].destinationDataSub(lambda x, y=device[0]: self.callbackLivewireSrcDst(y, x))


    def callbackLivewireSrcDst(self, device, ports):
        # Receive source/destination changes

        for port in ports:

            if 'rtp_destination' in port['attributes'] and port['attributes']['rtp_destination'] is not None:
                route = port['attributes']['rtp_destination']
            elif 'address' in port['attributes'] and port['attributes']['address'] is not None:
                route = port['attributes']['address']
            else:
                route = "UNKNOWN"

            # Work out the multicast address / Livewire channel number
            try:
                route_type = AxiaLivewireAddressHelper.streamFormatFromMulticastAddr(route)
                route_chnum = AxiaLivewireAddressHelper.multicastAddrToStreamNum(route)
            except:
                route_chnum = "?"
                route_type = "?"

            if str(port['num']) not in self.LWRP[device]['Last_' + port['type'] + '_ROUTE'] or str(port['num']) not in self.LWRP[device]['Last_' + port['type'] + '_NAME']:
                # Store the last state - never before seen
                self.LWRP[device]['Last_' + port['type'] + '_ROUTE'][str(port['num'])] = ""
                self.LWRP[device]['Last_' + port['type'] + '_NAME'][str(port['num'])] = ""

            if self.LWRP[device]['Last_' + port['type'] + '_ROUTE'][str(port['num'])] != route or self.LWRP[device]['Last_' + port['type'] + '_NAME'][str(port['num'])] != port['attributes']['name']:
                # Store the new last state and log it
                self.LWRP[device]['Last_' + port['type'] + '_ROUTE'][str(port['num'])] = route
                self.LWRP[device]['Last_' + port['type'] + '_NAME'][str(port['num'])] = port['attributes']['name']

                # Log it!
                try:
                    self.logger.info("%s Port %s Route Change: %s (Name: %s; LW #%s; Type: %s)", port['type'], port['num'], route, port['attributes']['name'], route_chnum, route_type, extra={'device_name': device})
                except Exception, e:
                    print "EXCEPTION:", e


    def callbackLivewireGPIO(self, device, ports):
        # Get GPIO data changes
        for port in ports:
            pinString = ""
            for pin in port['pin_states']:
                if pin['state'] == "low":
                    pinString += "L"
                else:
                    pinString += "H"

            if str(port['num']) not in self.LWRP[device]['Last_' + port['type']]:
                # Store the last state - never before seen
                self.LWRP[device]['Last_' + port['type']][str(port['num'])] = pinString

            elif self.LWRP[device]['Last_' + port['type']][str(port['num'])] == pinString:
                # If it's the same as the last state, ignore it
                continue
            
            else:
                # Store the last state
                self.LWRP[device]['Last_' + port['type']][str(port['num'])] = pinString
            
            # Log the change
            try:
                self.logger.info("%s Port %s State Change: %s", port['type'], port['num'], pinString, extra={'device_name': device})
            except Exception, e:
                print "EXCEPTION:", e
        

    def setupMainInterface(self):
        # Setup the interface with a list of source select buttons

        self.top = self.winfo_toplevel()
        self.top.rowconfigure(0, weight = 1)
        self.top.columnconfigure(0, weight = 1)
        self.top.columnconfigure(1, weight = 1)
        self.top.rowconfigure(1, weight = 10)
        self.top.rowconfigure(2, weight = 1)

        # Title Label
        titleLabel = tk.Label(
            self.top,
            text = str("Livewire Audit Logger"),
            font = ("Arial", 18, "bold")
        )
        titleLabel.pack()
        titleLabel.grid(
            column = 0,
            row = 0,
            sticky = ("N", "S", "E", "W"),
            pady = 5,
            columnspan = 2,
        )

        # Create the log viewer:
        self.logwidget = ScrolledText.ScrolledText(self.top, state='disabled')
        self.logwidget.configure(font='TkFixedFont')
        self.logwidget.grid(
            column = 0,
            row = 1,
            sticky = ("N", "S", "E", "W"),
            columnspan = 2,
        )

        widgetHandle = WidgetLogger(self.logwidget)
        widgetHandle.setFormatter(self.logger_formatter)
        self.logger.addHandler(widgetHandle)

        button_devicelist = tk.Button(
            self.top,
            text = "Configure Device List",
            font = ("Arial", 12, "bold"),
            command = self.configureDevices
        )
        button_devicelist.grid(
            column = 0,
            row = 2,
            sticky = ("N", "S", "E", "W"),
        )

        button_logfolder = tk.Button(
            self.top,
            text = "Open Log Folder",
            font = ("Arial", 12, "bold"),
            command = self.openLogFolder
        )
        button_logfolder.grid(
            column = 1,
            row = 2,
            sticky = ("N", "S", "E", "W"),
        )

        # Create the main menu
        menubar = tk.Menu()
        menubar.add_command(label = "About", command = self.about)
        menubar.add_command(label = "Updates", command = self.updates)
        menubar.add_command(label = "Quit!", command = self.close)
        self.top.config(menu = menubar)

    def configureDevices(self):
        thread.start_new_thread(os.startfile, (os.path.join(self.application_path, "devices.txt"), "edit"))
    
    def openLogFolder(self):
        thread.start_new_thread(os.startfile, (self.application_path, "explore"))

    def about(self):
        variable = tkMessageBox.showinfo('Livewire Audit Logger', 'Livewire Audit Logger\nCreated by Anthony Eden (https://mediarealm.com.au/)\nThis is commercial software - please purchase a license to use this at your station.\nVersion: ' + __version__)

    def close(self):
        # Terminate the application
        self.logger.info("Application is closing", extra={'device_name': "SYSTEM"})

        for device in self.LWRP:
            if 'Connection' in self.LWRP[device] and self.LWRP[device]['Connection'] is not None:
                self.logger.info("Disconnecting from LWRP device", extra={'device_name': device})
                self.LWRP[device]['Connection'].stop()
        
        self.root.destroy()

    def updates(self):
        if self.autoCheckVersion is False:
            # Send a check for new updates
            self.versionCheck("popup")

        elif self.newVersion is True:
            variable = tkMessageBox.showinfo('Software Updates', 'You currently have version v' + __version__ + '\r\nVersion v' + self.newVersionNum + ' is available\r\nDownload website: ' + self.newVersionURL)
        else:
            variable = tkMessageBox.showinfo('Software Updates', 'You currently have the latest version v ' + __version__)

    def versionCheck(self, mode = "toolbar"):
        # This simple version checker will prompt the user to update if required
        r_data = {
            'version': __version__,
            'product': __product__
        }

        try:
            r_version = requests.post("https://api.mediarealm.com.au/versioncheck/", data = r_data)
            r_version_response = r_version.json()

            self.autoCheckVersion = True

            if r_version_response['status'] == "update-available" and mode == "toolbar":
                self.setErrorMessage(r_version_response['message'], "append")
                self.newVersion = True
                self.newVersionNum = r_version_response['version_latest']
                self.newVersionText = r_version_response['message']
                self.newVersionURL = r_version_response['url_download']

            elif r_version_response['status'] == "update-available" and mode == "popup":
                self.newVersion = True
                self.newVersionNum = r_version_response['version_latest']
                self.newVersionText = r_version_response['message']
                self.newVersionURL = r_version_response['url_download']
                self.updates()
            
            elif mode == "popup":
                self.newVersion = False
                self.updates()
            
            else:
                self.newVersion = False
            
        except Exception, e:
            print "ERROR Checking for Updates:", e

class WidgetLogger(logging.Handler):
    def __init__(self, widget):
        logging.Handler.__init__(self)
        self.setLevel(logging.INFO)
        self.widget = widget
        self.widget.config(state='disabled')

    def emit(self, record):
        self.widget.config(state='normal')
        # Append message (record) to the widget
        self.widget.insert(tk.END, self.format(record) + '\n')

        # Only keep a maximum 100 lines in this textbox...
        try:
            while int(self.widget.index('end-1c').split('.')[0]) > 100:
                self.widget.delete("1.0", "2.0")
        except:
            pass

        self.widget.see(tk.END)  # Scroll to the bottom
        self.widget.config(state='disabled')

if __name__ == "__main__":
    app = Application()
    app.master.title('Livewire Audit Logger')
    app.mainloop()
