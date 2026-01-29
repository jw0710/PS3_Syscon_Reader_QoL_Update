from binascii import unhexlify as uhx
from Cryptodome.Cipher import AES
import os
import string
import sys
import time
import serial.tools.list_ports
import customtkinter
import datetime
import re
import webbrowser
from tkinter import messagebox


# --- PS3UART Klasse (Backend) - UNVERÄNDERT ---
class PS3UART(object):
    def __init__(self, port, sc_type, serial_speed, sandbox_mode=False):
        self.sandbox_mode = sandbox_mode
        
        if not sandbox_mode:
            try:
                import serial
            except ImportError:
                messagebox.showerror("Error", "The pyserial module is required. You can install it with 'pip install pyserial'")
                sys.exit(1)

        self.port = port
        self.sc_type = sc_type
        self.serial_speed = serial_speed
        
        if not sandbox_mode:
            self.ser = serial.Serial()
        else:
            self.ser = None

        self.sc2tb = uhx('71f03f184c01c5ebc3f6a22a42ba9525')
        self.tb2sc = uhx('907e730f4d4e0a0b7b75f030eb1d9d36')
        self.value = uhx('3350BD7820345C29056A223BA220B323')
        self.zero  = uhx('00000000000000000000000000000000')

        self.auth1r_header = uhx('10100000FFFFFFFF0000000000000000')
        self.auth2_header  = uhx('10010000000000000000000000000000')

        if not sandbox_mode:
            self.ser.port = port
            if serial_speed == '57600':
                self.ser.baudrate = 57600
            elif serial_speed == '115200':
                self.ser.baudrate = 115200
            else:
                assert False
            self.type = sc_type
            self.ser.timeout = 0.1
            self.ser.open()
            assert self.ser.isOpen()
            self.ser.flush()
        else:
            self.type = sc_type

    def aes_decrypt_cbc(self, key, iv, data):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(data)
        return decrypted_data

    def aes_encrypt_cbc(self, key, iv, data):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_data = cipher.encrypt(data)
        return encrypted_data

    def __del__(self):
        if not self.sandbox_mode and self.ser:
            self.ser.close()

    def send(self, data):
        if self.sandbox_mode:
            print(f"[SANDBOX] Sending: {data}")
        else:
            self.ser.write(data.encode('ascii'))

    def receive(self):
        if self.sandbox_mode:
            return b"w complete!\n[mullion]$"
        else:
            return self.ser.read(self.ser.inWaiting())

    def command(self, com, wait=1, verbose=False):
        if(verbose):
            print('Command: ' + com)

        if self.sandbox_mode:
            print(f"[SANDBOX] Command: {com}")
            time.sleep(0.1)
            return (0, ["Complete!"])

        if(self.type == 'CXR'):
            length = len(com)
            checksum = sum(bytearray(com, 'ascii')) % 0x100
            if(length <= 10):
                self.send('C:{:02X}:{}\r\n'.format(checksum, com))
            else:
                j = 10
                self.send('C:{:02X}:{}'.format(checksum, com[0:j]))
                for i in range(length - j, 15, -15):
                    self.send(com[j:j+15])
                    j += 15
                self.send(com[j:] + '\r\n')
        elif(self.type == 'SW'):
            length = len(com)
            if(length >= 0x40):
                if(self.command('SETCMDLONG FF FF')[0] != 0):
                    return (0xFFFFFFFF, ['Setcmdlong'])
            checksum = sum(bytearray(com, 'ascii')) % 0x100
            self.send('{}:{:02X}\r\n'.format(com, checksum))
        else:
            self.send(com + '\r\n')

        time.sleep(wait)
        answer = self.receive().decode('ascii', 'ignore').strip()
        if(verbose):
            print('Answer: ' + answer)

        if(self.type == 'CXR'):
            answer = answer.split(':')
            if(len(answer) != 3):
                return (0xFFFFFFFF, ['Answer length'])
            checksum = sum(bytearray(answer[2], 'ascii')) % 0x100
            if(answer[0] != 'R' and answer[0] != 'E'):
                return (0xFFFFFFFF, ['Magic'])
            if(answer[1] != '{:02X}'.format(checksum)):
                return (0xFFFFFFFF, ['Checksum'])
            data = answer[2].split(' ')
            if(answer[0] == 'R' and len(data) < 2 or answer[0] == 'E' and len(data) != 2):
                return (0xFFFFFFFF, ['Data length'])
            if(data[0] != 'OK' or len(data) < 2):
                return (int(data[1], 16), [])
            else:
                return (int(data[1], 16), data[2:])
        elif(self.type == 'SW'):
            answer = answer.split('\n')
            for i in range(0, len(answer)):
                answer[i] = answer[i].replace('\n', '').rsplit(':', 1)
                if(len(answer[i]) != 2):
                    return (0xFFFFFFFF, ['Answer length'])
                checksum = sum(bytearray(answer[i][0], 'ascii')) % 0x100
                if(answer[i][1] != '{:02X}'.format(checksum)):
                    return (0xFFFFFFFF, ['Checksum'])
                answer[i][0] += '\n'
            ret = answer[-1][0].replace('\n', '').split(' ')
            if(len(ret) < 2 or len(ret[1]) != 8 and not all(c in string.hexdigits for c in ret[1])):
                return (0, [x[0] for x in answer])
            elif(len(answer) == 1):
                return (int(ret[1], 16), ret[2:])
            else:
                return (int(ret[1], 16), [x[0] for x in answer[:-1]])
        else:
            return (0, [answer])

    def auth(self):
        if self.sandbox_mode:
            return 'Auth successful (Sandbox Mode)'
            
        if(self.type == 'CXR' or self.type == 'SW'):
            auth1r = self.command('AUTH1 10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
            if(auth1r[0] == 0 and auth1r[1] != []):
                auth1r = uhx(auth1r[1][0])
                if(auth1r[0:0x10] == self.auth1r_header):
                    data = self.aes_decrypt_cbc(self.sc2tb, self.zero, auth1r[0x10:0x40])
                    if(data[0x8:0x10] == self.zero[0x0:0x8] and data[0x10:0x20] == self.value and data[0x20:0x30] == self.zero):
                        new_data = data[0x8:0x10] + data[0x0:0x8] + self.zero + self.zero
                        auth2_body = self.aes_encrypt_cbc(self.tb2sc, self.zero, new_data)
                        auth2r = self.command('AUTH2 ' + ''.join('{:02X}'.format(c) for c in bytearray(self.auth2_header + auth2_body)))
                        if(auth2r[0] == 0):
                            return 'Auth successful'
                        else:
                            return 'Auth failed'
                    else:
                        return 'Auth1 response body invalid'
                else:
                    return 'Auth1 response header invalid'
            else:
                return 'Auth1 response invalid'
        else:
            scopen = self.command('scopen')
            if('SC_READY' in scopen[1][0]):
                auth1r = self.command('10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
                auth1r = auth1r[1][0].split('\r')[1][1:]
                if(len(auth1r) == 128):
                    auth1r = uhx(auth1r)
                    if(auth1r[0:0x10] == self.auth1r_header):
                        data = self.aes_decrypt_cbc(self.sc2tb, self.zero, auth1r[0x10:0x40])
                        if(data[0x8:0x10] == self.zero[0x0:0x8] and data[0x10:0x20] == self.value and data[0x20:0x30] == self.zero):
                            new_data = data[0x8:0x10] + data[0x0:0x8] + self.zero + self.zero
                            auth2_body = self.aes_encrypt_cbc(self.tb2sc, self.zero, new_data)
                            auth2r = self.command(''.join('{:02X}'.format(c) for c in bytearray(self.auth2_header + auth2_body)))
                            if('SC_SUCCESS' in auth2r[1][0]):
                                return 'Auth successful'
                            else:
                                return 'Auth failed'
                        else:
                            return 'Auth1 response body invalid'
                    else:
                        return 'Auth1 response header invalid'
                else:
                    return 'Auth1 response invalid'
            else:
                return 'scopen response invalid'


# --- Farb- und Schrift-Konstanten ---
FG_SUCCESS = "#34c759"
FG_ERROR = "#ff3b30"
FG_OUTPUT_DARK_BG = "#00aaff"

FONT_HEADING = ("Segoe UI", 20, "bold")
FONT_UI = ("Segoe UI", 12)
FONT_MONO = ("Consolas", 11)


class PS3SysconGUI:
    def __init__(self, root: customtkinter.CTk):
        self.root = root
        self.root.title("PS3 RSX Advanced Patching Tool")
        
        self.sandbox_mode = customtkinter.BooleanVar(value=False)
        self.rsx_patch_mode = customtkinter.BooleanVar(value=False)
        self.is_authenticated = False
        self.console_running = False
        
        self._build_root_layout()

    def _build_root_layout(self):
        """Baut das Hauptfenster-Layout mit customtkinter Widgets auf."""
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(2, weight=1)

        # Title
        title_frame = customtkinter.CTkFrame(self.root, fg_color="transparent")
        title_frame.grid(row=0, column=0, padx=20, pady=(10, 5), sticky="ew")
        
        customtkinter.CTkLabel(title_frame, text="PS3 RSX ADVANCED PATCHING", font=FONT_HEADING).pack()
        customtkinter.CTkLabel(title_frame, text="Autopatch • Utility Patches • Quick & Manual Commands", font=FONT_UI, text_color="gray60").pack()

        # Connection Settings
        self._build_connection_settings()

        # Tabs
        self.tab_view = customtkinter.CTkTabview(self.root, corner_radius=10)
        self.tab_view.grid(row=2, column=0, padx=20, pady=10, sticky="nsew")

        self.tab_view.add("Advanced Patching")
        self.tab_view.add("Quick Commands")
        self.tab_view.add("Manual Commands")
        self.tab_view.add("Fan Settings (FAT)")
        
        self.frame_advanced = self.tab_view.tab("Advanced Patching")
        self.frame_quick = self.tab_view.tab("Quick Commands")
        self.frame_manual = self.tab_view.tab("Manual Commands")
        self.frame_fan = self.tab_view.tab("Fan Settings (FAT)")

        self._build_advanced_tab()
        self._build_quick_tab()
        self._build_manual_tab()
        self._build_fan_tab()
        
        # Initial fan tab state based on SC Type
        self._update_fan_tab_state()

        # Bottom Frame: Sandbox + Support Link
        bottom_frame = customtkinter.CTkFrame(self.root, fg_color="transparent")
        bottom_frame.grid(row=3, column=0, pady=10)
        
        customtkinter.CTkCheckBox(bottom_frame, text="Sandbox Mode (simulate console, no real UART)", variable=self.sandbox_mode).pack()
        
        # Support Link
        support_link = customtkinter.CTkLabel(
            bottom_frame, 
            text="Support: NostaMods Instagram",
            font=("Segoe UI", 10, "underline"),
            text_color="#00aaff",
            cursor="hand2"
        )
        support_link.pack(pady=(5, 0))
        support_link.bind("<Button-1>", lambda e: webbrowser.open("https://www.instagram.com/nostamods/"))

    def _build_connection_settings(self):
        """Connection Settings Frame"""
        conn_frame = customtkinter.CTkFrame(self.root, corner_radius=10)
        conn_frame.grid(row=1, column=0, padx=20, pady=10, sticky="ew")
        conn_frame.grid_columnconfigure(1, weight=1)
        conn_frame.grid_columnconfigure(3, weight=1)
        
        # Serial Port
        customtkinter.CTkLabel(conn_frame, text="Serial Port:", font=FONT_UI).grid(row=0, column=0, padx=(15, 10), pady=15, sticky="w")
        
        available_ports = [port.device for port in serial.tools.list_ports.comports()]
        self.port_combobox = customtkinter.CTkComboBox(conn_frame, values=available_ports, width=150)
        self.port_combobox.grid(row=0, column=1, padx=10, pady=15, sticky="w")
        
        # SC Type
        customtkinter.CTkLabel(conn_frame, text="SC Type:", font=FONT_UI).grid(row=0, column=2, padx=(30, 10), pady=15, sticky="w")
        
        self.sc_type_combobox = customtkinter.CTkComboBox(
            conn_frame, 
            values=["CXR", "CXRF", "SW"], 
            width=150,
            command=self._on_sc_type_changed
        )
        self.sc_type_combobox.set("CXR")
        self.sc_type_combobox.grid(row=0, column=3, padx=10, pady=15, sticky="w")
        
        # Refresh Button
        self.refresh_btn = customtkinter.CTkButton(conn_frame, text="Refresh", command=self._refresh_ports, width=100, fg_color="gray50", hover_color="gray40")
        self.refresh_btn.grid(row=0, column=4, padx=(10, 15), pady=15)

    def _refresh_ports(self):
        """Refresh available serial ports"""
        ports = [port.device for port in serial.tools.list_ports.comports()]
        self.port_combobox.configure(values=ports)
        self._log_to_active_output(f"Refreshed ports: {len(ports)} found")

    def _on_sc_type_changed(self, choice):
        """Called when SC Type changes"""
        self._update_fan_tab_state()
    
    def _update_fan_tab_state(self):
        """Enable/disable Fan Settings tab based on SC Type"""
        sc_type = self.sc_type_combobox.get()
        
        if sc_type == "CXRF":
            # Enable Fan Settings ONLY for CXRF
            try:
                self._enable_fan_tab_widgets()
            except:
                pass
        else:
            # Disable Fan Settings tab for CXR and SW
            try:
                self.tab_view.configure(state="normal")  # Ensure we can modify
                # Disable the tab by removing ability to click on it
                # We'll gray out all widgets in the fan tab
                self._disable_fan_tab_widgets()
            except:
                pass
    
    def _disable_fan_tab_widgets(self):
        """Disable all widgets in fan tab"""
        def disable_recursive(widget):
            try:
                if isinstance(widget, (customtkinter.CTkButton, customtkinter.CTkEntry)):
                    widget.configure(state="disabled")
                for child in widget.winfo_children():
                    disable_recursive(child)
            except:
                pass
        disable_recursive(self.frame_fan)
    
    def _enable_fan_tab_widgets(self):
        """Enable all widgets in fan tab"""
        def enable_recursive(widget):
            try:
                if isinstance(widget, (customtkinter.CTkButton, customtkinter.CTkEntry)):
                    widget.configure(state="normal")
                for child in widget.winfo_children():
                    enable_recursive(child)
            except:
                pass
        enable_recursive(self.frame_fan)


    def _build_advanced_tab(self):
        """Advanced Patching Tab"""
        f = self.frame_advanced
        f.grid_columnconfigure((0, 1), weight=1)
        f.grid_rowconfigure(8, weight=1)

        # AUTH Section
        customtkinter.CTkLabel(f, text="Step 1: Authenticate before ANY RSX patching. No AUTH = high BRICK risk.", text_color=FG_ERROR, justify="center").grid(row=0, column=0, columnspan=2, sticky="ew", padx=10, pady=(10, 5))
        
        self.auth_button_adv = customtkinter.CTkButton(f, text="AUTH PS3", command=self._run_auth, font=(FONT_UI[0], 12, "bold"), fg_color="gray50", hover_color="gray40")
        self.auth_button_adv.grid(row=1, column=0, columnspan=2, padx=10, pady=5, sticky="ew")

        self.auth_status_label = customtkinter.CTkLabel(f, text="Status: NOT AUTHENTICATED", text_color=FG_ERROR, font=(FONT_UI[0], 12, "bold"))
        self.auth_status_label.grid(row=2, column=0, columnspan=2, padx=10, pady=(0, 10), sticky="ew")

        # Utility Patches
        btn_font = (FONT_UI[0], 14, "bold")
        self.cxr_button = customtkinter.CTkButton(f, text="CXR to CXRF Patcher (Mullion Only)", command=self._run_cxr_patcher, font=btn_font, height=50, fg_color="gray50", hover_color="gray40")
        self.cxr_button.grid(row=3, column=0, padx=10, pady=5, sticky="ew")

        self.checksum_button = customtkinter.CTkButton(f, text="Checksum Correction (Auto-detect & Fix)", command=self._run_checksum_correction, font=btn_font, height=50, fg_color="gray50", hover_color="gray40")
        self.checksum_button.grid(row=3, column=1, padx=10, pady=5, sticky="ew")
        
        # RSX Patch Warning
        warning_text = "Only for: CECHAxx, CECHBxx, CECHCxx, CECHExx, CECHGxx, CECHHxx, CECHJxx, CECHKxx, DECR-1400"
        customtkinter.CTkLabel(f, text=warning_text, text_color=FG_ERROR, font=(FONT_UI[0], 10)).grid(row=4, column=0, columnspan=2, padx=10, pady=(10, 0))
        
        customtkinter.CTkCheckBox(f, text="RSX Patch Mode (Enable Autopatch)", variable=self.rsx_patch_mode, command=self._update_rsx_button_state).grid(row=5, column=0, columnspan=2, padx=10, pady=(5, 0))
        
        # RSX Buttons
        self.patch40_btn = customtkinter.CTkButton(f, text="PATCH RSX 40NM", command=self._run_patch_40, fg_color="gray50", hover_color="gray40")
        self.patch65_btn = customtkinter.CTkButton(f, text="PATCH RSX 65NM", command=self._run_patch_65, fg_color="gray50", hover_color="gray40")
        self.patch40_btn.grid(row=6, column=0, padx=10, pady=10, sticky="ew")
        self.patch65_btn.grid(row=6, column=1, padx=10, pady=10, sticky="ew")
        
        # RSX Swap Checksum Correction Button - UNTER den Patch Buttons
        self.rsx_checksum_button = customtkinter.CTkButton(f, text="Checksum Correction RSX Swap (32FE/34FE)", command=self._run_rsx_checksum_correction, font=btn_font, height=50, fg_color="gray50", hover_color="gray40", state="disabled")
        self.rsx_checksum_button.grid(row=7, column=0, columnspan=2, padx=10, pady=5, sticky="ew")

        customtkinter.CTkLabel(f, text="Output Log:", font=(FONT_UI[0], 12, "bold")).grid(row=8, column=0, columnspan=2, padx=10, pady=(10, 5), sticky="nw")
        self.output_advanced = customtkinter.CTkTextbox(f, font=FONT_MONO, corner_radius=10, text_color=FG_OUTPUT_DARK_BG)
        self.output_advanced.grid(row=8, column=0, columnspan=2, padx=10, pady=(30, 10), sticky="nsew")

        self._update_rsx_button_state()

    def _update_rsx_button_state(self):
        state = "normal" if self.rsx_patch_mode.get() and self.is_authenticated else "disabled"
        self.patch40_btn.configure(state=state)
        self.patch65_btn.configure(state=state)
        self.rsx_checksum_button.configure(state=state)

    def _build_quick_tab(self):
        """Quick Commands Tab"""
        f = self.frame_quick
        f.grid_columnconfigure((0, 1), weight=1)
        f.grid_rowconfigure(6, weight=1)

        # Power Button
        self.power_button = customtkinter.CTkButton(
            f, text="Start Console (bringup)", 
            command=self._toggle_power,
            font=("Segoe UI", 16, "bold"),
            height=80,
            fg_color="gray50",
            hover_color="gray40"
        )
        self.power_button.grid(row=0, column=0, columnspan=2, padx=10, pady=20, sticky="ew")

        # Quick Command Buttons
        buttons = [
            ("Show Errorlog", self._cmd_errorlog, 1, 0),
            ("Firmware Checksum", self._cmd_checksum, 1, 1),
            ("Authentication", self._cmd_auth, 2, 0),
            ("EEPROM Checksum", self._cmd_eepcsum, 2, 1),
            ("Clear Error Log", self._cmd_clearerrlog, 3, 0),
            ("Get Temperatures", self._cmd_temperatures, 3, 1),
            ("Boot/Error Count", self._cmd_becount, 4, 0),
            ("Get RTC", self._cmd_getrtc, 4, 1),
        ]

        for text, cmd, row, col in buttons:
            btn = customtkinter.CTkButton(f, text=text, command=cmd, height=50, fg_color="gray50", hover_color="gray40")
            btn.grid(row=row, column=col, padx=10, pady=10, sticky="ew")

        # Output
        customtkinter.CTkLabel(f, text="Output Log:", font=(FONT_UI[0], 12, "bold")).grid(row=5, column=0, columnspan=2, padx=10, pady=(10, 5), sticky="w")
        self.output_quick = customtkinter.CTkTextbox(f, font=FONT_MONO, corner_radius=10, text_color=FG_OUTPUT_DARK_BG)
        self.output_quick.grid(row=6, column=0, columnspan=2, padx=10, pady=(0, 10), sticky="nsew")

    def _build_manual_tab(self):
        f = self.frame_manual
        f.grid_columnconfigure(0, weight=1)
        f.grid_rowconfigure(3, weight=1)

        customtkinter.CTkLabel(f, text="Manual Commands", font=(FONT_UI[0], 16, "bold")).grid(row=0, column=0, padx=10, pady=10, sticky="w")

        # Command Entry
        entry_frame = customtkinter.CTkFrame(f, fg_color="transparent")
        entry_frame.grid(row=1, column=0, padx=10, pady=5, sticky="ew")
        entry_frame.grid_columnconfigure(0, weight=1)

        self.command_entry = customtkinter.CTkEntry(entry_frame, placeholder_text="Enter raw UART command...", font=FONT_MONO, height=35)
        self.command_entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))
        self.command_entry.bind("<Return>", self._send_manual)

        customtkinter.CTkButton(entry_frame, text="SEND", command=self._send_manual, width=80, height=35, fg_color="gray50", hover_color="gray40").grid(row=0, column=1)
        
        # Info/Help Button - BLUE
        customtkinter.CTkButton(
            entry_frame, 
            text="Info / Help", 
            command=self._show_command_help,
            width=100,
            height=35,
            fg_color="#0078d4",
            hover_color="#005a9e"
        ).grid(row=0, column=2, padx=(10, 0))

        # Help Section
        help_frame = customtkinter.CTkFrame(f, corner_radius=10)
        help_frame.grid(row=2, column=0, padx=10, pady=10, sticky="ew")

        help_text = """Common Commands:

External Mode:
  • EEP GET <addr> <len> - Read EEPROM
  • EEP SET <addr> <len> <data> - Write EEPROM
  • ERRLOG GET 00 - Get error log (00-1F)

Internal Mode:
  • r <addr> - Read from EEPROM address
  • w <addr> <data> - Write to EEPROM address
  • errlog - Get error log
  • clearerrlog - Clear error log
  • fantbl - Fan table commands
  • patchvereep - Get patched version"""

        customtkinter.CTkLabel(help_frame, text=help_text, font=("Consolas", 9), justify="left").pack(padx=15, pady=10, anchor="w")

        # Output
        customtkinter.CTkLabel(f, text="Output Log:", font=(FONT_UI[0], 12, "bold")).grid(row=3, column=0, padx=10, pady=(10, 5), sticky="nw")
        self.output_manual = customtkinter.CTkTextbox(f, font=FONT_MONO, corner_radius=10, text_color=FG_OUTPUT_DARK_BG)
        self.output_manual.grid(row=3, column=0, padx=10, pady=(30, 10), sticky="nsew")

    # --- HELPER METHODS ---
    def _get_ps3_connection(self):
        """Get PS3UART instance with current settings"""
        port = self.port_combobox.get()
        sc_type = self.sc_type_combobox.get()
        sandbox = self.sandbox_mode.get()
        
        if not sandbox and (not port or not sc_type):
            messagebox.showerror("Error", "Please select serial port and SC type.")
            return None
        
        if sc_type == "CXR" or sc_type == "CXRF":
            serial_speed = "57600"
        else:
            serial_speed = "115200"
        
        return PS3UART(port, sc_type, serial_speed, sandbox_mode=sandbox)

    def _log_to_active_output(self, text, output_widget=None):
        """Logs text to the specified output widget or tries to find active one"""
        if output_widget:
            output_widget.insert("end", text + "\n")
            output_widget.see("end")
        elif hasattr(self, 'output_quick') and self.output_quick:
            self.output_quick.insert("end", text + "\n")
            self.output_quick.see("end")

    def _format_command_output(self, ret, sc_type):
        """
        Formatiert die Command-Ausgabe wie im alten GUI
        Diese Methode ist der Schlüssel zur korrekten Output-Darstellung!
        """
        if ret[0] == 0xFFFFFFFF:
            return f"ERROR: {ret[1][0] if ret[1] else 'Unknown error'}"
        
        if sc_type == 'CXR' or sc_type == 'CXRF':
            # CXR Format: HEX-Code + Daten
            output = '{:08X}'.format(ret[0]) + ' ' + ' '.join(ret[1])
        elif sc_type == 'SW':
            # SW Format: Unterscheidung mit/ohne Newlines
            if len(ret[1]) > 0 and '\n' not in ret[1][0]:
                output = '{:08X}'.format(ret[0]) + ' ' + ' '.join(ret[1])
            else:
                output = '{:08X}'.format(ret[0]) + '\n' + ''.join(ret[1])
        else:
            # Default Format
            output = ret[1][0] if ret[1] else str(ret[0])
        
        return output

    # --- QUICK COMMANDS TAB ---
    def _toggle_power(self):
        """Toggle console power (bringup/shutdown)"""
        ps3 = self._get_ps3_connection()
        if not ps3:
            return
        
        try:
            if not self.console_running:
                self.output_quick.insert("end", "Starting Console (bringup)...\n")
                self.output_quick.see("end")
                ret = ps3.command("bringup", wait=1)
                
                output = self._format_command_output(ret, self.sc_type_combobox.get())
                self.output_quick.insert("end", output + "\n")
                self.output_quick.see("end")
                
                if ret[0] != 0xFFFFFFFF:
                    self.console_running = True
                    self.power_button.configure(
                        fg_color=FG_SUCCESS,
                        text="Console Running (Click to Shutdown)"
                    )
            else:
                self.output_quick.insert("end", "Shutting Down Console...\n")
                self.output_quick.see("end")
                ret = ps3.command("shutdown", wait=1)
                
                output = self._format_command_output(ret, self.sc_type_combobox.get())
                self.output_quick.insert("end", output + "\n")
                self.output_quick.see("end")
                
                if ret[0] != 0xFFFFFFFF:
                    self.console_running = False
                    self.power_button.configure(
                        fg_color="gray50",
                        text="Start Console (bringup)"
                    )
        except Exception as e:
            self.output_quick.insert("end", f"Error: {str(e)}\n")
            messagebox.showerror("Error", str(e))

    def _cmd_errorlog(self):
        """Show errorlog"""
        ps3 = self._get_ps3_connection()
        if not ps3:
            return
        
        try:
            self.output_quick.insert("end", "Command: errlog\n")
            self.output_quick.see("end")
            ret = ps3.command("errlog", wait=1)
            
            output = self._format_command_output(ret, self.sc_type_combobox.get())
            self.output_quick.insert("end", output + "\n")
            self.output_quick.see("end")
        except Exception as e:
            self.output_quick.insert("end", f"Error: {str(e)}\n")

    def _cmd_checksum(self):
        """Run firmware checksum (csum)"""
        ps3 = self._get_ps3_connection()
        if not ps3:
            return
        
        try:
            self.output_quick.insert("end", "Command: csum\n")
            self.output_quick.see("end")
            ret = ps3.command("csum", wait=1)
            
            output = self._format_command_output(ret, self.sc_type_combobox.get())
            self.output_quick.insert("end", output + "\n")
            self.output_quick.see("end")
        except Exception as e:
            self.output_quick.insert("end", f"Error: {str(e)}\n")

    def _cmd_auth(self):
        """Run authentication from Quick Commands"""
        self._run_auth()

    def _cmd_eepcsum(self):
        """Run EEPROM checksum"""
        ps3 = self._get_ps3_connection()
        if not ps3:
            return
        
        try:
            self.output_quick.insert("end", "Command: eepcsum\n")
            self.output_quick.see("end")
            ret = ps3.command("eepcsum", wait=1)
            
            output = self._format_command_output(ret, self.sc_type_combobox.get())
            self.output_quick.insert("end", output + "\n")
            self.output_quick.see("end")
        except Exception as e:
            self.output_quick.insert("end", f"Error: {str(e)}\n")

    def _cmd_clearerrlog(self):
        """Clear error log with warning"""
        if not messagebox.askyesno("Warning", 
            "This will delete all previously recorded Errors!\n\nContinue?"):
            return
        
        ps3 = self._get_ps3_connection()
        if not ps3:
            return
        
        try:
            self.output_quick.insert("end", "\n=== Clearing Error Log ===\n")
            self.output_quick.see("end")
            ret = ps3.command("clearerrlog", wait=0.5)
            
            output = self._format_command_output(ret, self.sc_type_combobox.get())
            self.output_quick.insert("end", output + "\n")
            self.output_quick.see("end")
            
            messagebox.showinfo("Success", "Error log cleared!")
        except Exception as e:
            self.output_quick.insert("end", f"Error: {str(e)}\n")

    def _cmd_temperatures(self):
        """Get temperatures using tsensor"""
        ps3 = self._get_ps3_connection()
        if not ps3:
            return
        
        try:
            self.output_quick.insert("end", "\n=== Reading Temperatures ===\n")
            self.output_quick.see("end")
            ret = ps3.command("tsensor", wait=0.5)
            
            output = self._format_command_output(ret, self.sc_type_combobox.get())
            self.output_quick.insert("end", output + "\n")
            self.output_quick.see("end")
        except Exception as e:
            self.output_quick.insert("end", f"Error: {str(e)}\n")
    
    def _cmd_getrtc(self):
        """Get RTC"""
        ps3 = self._get_ps3_connection()
        if not ps3:
            return
        
        try:
            self.output_quick.insert("end", "\n=== Reading RTC ===\n")
            self.output_quick.see("end")
            ret = ps3.command("getrtc", wait=0.5)
            
            output = self._format_command_output(ret, self.sc_type_combobox.get())
            self.output_quick.insert("end", output + "\n")
            self.output_quick.see("end")
        except Exception as e:
            self.output_quick.insert("end", f"Error: {str(e)}\n")

    def _cmd_becount(self):
        """Get boot/error count"""
        ps3 = self._get_ps3_connection()
        if not ps3:
            return
        
        try:
            self.output_quick.insert("end", "\n=== Reading Boot/Error Count ===\n")
            self.output_quick.see("end")
            ret = ps3.command("becount", wait=0.5)
            
            output = self._format_command_output(ret, self.sc_type_combobox.get())
            self.output_quick.insert("end", output + "\n")
            self.output_quick.see("end")
        except Exception as e:
            self.output_quick.insert("end", f"Error: {str(e)}\n")
    
    def _show_command_help(self):
        """Show internal commands help in popup"""
        help_window = customtkinter.CTkToplevel(self.root)
        help_window.title("Internal Commands Reference")
        help_window.geometry("900x700")
        help_window.transient(self.root)
        help_window.grab_set()
        
        # Center the window
        help_window.update_idletasks()
        x = (help_window.winfo_screenwidth() // 2) - (900 // 2)
        y = (help_window.winfo_screenheight() // 2) - (700 // 2)
        help_window.geometry(f"900x700+{x}+{y}")
        
        # Title
        customtkinter.CTkLabel(
            help_window, 
            text="Internal Commands Reference", 
            font=(FONT_UI[0], 16, "bold")
        ).pack(pady=15)
        
        # Scrollable text area with commands
        text_frame = customtkinter.CTkScrollableFrame(help_window, width=850, height=580)
        text_frame.pack(padx=20, pady=(0, 20), fill="both", expand=True)
        
        commands_text = """INTERNAL COMMANDS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

becount          Display bringup/shutdown count + Power-on time
bepgoff          BE power grid off
bepkt            Packet permissions (show/set/unset/mode/debug/help)
bestat           Get status of BE
boardconfig      Displays board configuration
bootbeep         Boot beep (stat/on/off)
bringup          Turn PS3 on
bsn              Get board serial number
bstatus          HDMI related status
buzz             Activate buzzer [freq]
buzzpattern      Buzzer pattern [freq] [pattern] [count]
clear_err        Clear errors (last/eeprom/all)
clearerrlog      Clears error log
comm             Communication mode
commt            Manual BE communication (help/start/stop/send)
cp               CP control commands (ready/busy/reset/beepremote/beep2kn1n3/beep2kn2n3)
csum             Firmware checksum
devpm            Device power management (ata/pci/pciex/rsx)
diag             Diag (execute without param to show help)
disp_err         Displays errors
duty             Fan policy (get/set/getmin/setmin/getmax/setmax/getinmin/setinmin/getinmax/setinmax)
dve              DVE chip parameters (help/set/save/show)
eepcsum          Shows eeprom checksum
eepromcheck      Check eeprom [id]
eeprominit       Init eeprom [id]
ejectsw          Eject switch
errlog           Gets the error log
fancon           Does nothing
fanconautotype   Does nothing
fanconmode       Get Fan control mode
fanconpolicy     Fan control policy (get/set/getini/setini)
fandiag          Fan test
faninictrl       Does nothing
fanpol           Does nothing
fanservo         Does nothing
fantbl           Fan table (get/set/getini/setini/gettable/settable)
firmud           Firmware update
geterrlog        Gets error log [id]
getrtc           Gets rtc
halt             Halts syscon
hdmi             HDMI (various commands, use help)
hdmiid           Get HDMI id's
hdmiid2          Get HDMI id's
hversion         Platform ID
hyst             Temperature zones (get/set/getini/setini)
lasterrlog       Last error from log
ledmode          Get led mode [id] [id]
LS               LabStation Mode
ltstest          ?Temp related? values (get/set be/rsx)
osbo             Sets 0x2000F60
patchcsum        Patch checksum
patchvereep      Patch version eeprom
patchverram      Patch version ram
poll             Poll log
portscan         Scan port [port]
powbtnmode       Power button mode [mode (0/1)]
powerstate       Get power state
powersw          Power switch
powupcause       Power up cause
printmode        Set printmode [mode (0/1/2/3)]
printpatch       Prints patch
r                Read byte from SC [offset] [length]
r16              Read word from SC [offset] [length]
r32              Read dword from SC [offset] [length]
r64              Read qword from SC [offset] [length]
r64d             Read ?qword data? from SC [offset] [length]
rbe              Read from BE [offset]
recv             Receive something
resetsw          Reset switch
restartlogerrtoeep   Reenable error logging to eeprom
revision         Get softid
rrsxc            Read from RSX [offset] [length]
rtcreset         Reset RTC
scagv2           Auth related?
scasv2           Auth related?
scclose          Auth related?
scopen           Auth related?
send             Send something [variable]
shutdown         PS3 shutdown
startlogerrtsk   Start error log task
stoplogerrtoeep  Stop error logging to eeprom
stoplogerrtsk    Stop error log task
syspowdown       System power down (3 params 0 0 0)
task             Print tasks
thalttest        Does nothing
thermfatalmode   Set thermal boot mode (canboot/cannotboot)
therrclr         Thermal register clear
thrm             Does nothing
tmp              Get temperature [zone]
trace            Trace tasks (use help)
trp              Temperature zones (get/set/getini/setini)
tsensor          Get raw temperature [sensor]
tshutdown        Thermal shutdown (get/set/getini/setini)
tshutdowntime    Thermal shutdown time [time]
tzone            Show thermal zones
version          SC firmware version
w                Write byte to SC [offset] [value]
w16              Write word to SC [offset] [value]
w32              Write dword to SC [offset] [value]
w64              Write qword to SC [offset] [value]
wbe              Write to BE [offset] [value]
wmmto            Get watch dog timeout
wrsxc            Write to RSX [offset] [value]
xdrdiag          XDR diag (start/info/result)
xiodiag          XIO diag
xrcv             Xmodem receive

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Note: Commands can be sent via Manual Commands tab
"""
        
        text_label = customtkinter.CTkLabel(
            text_frame,
            text=commands_text,
            font=("Consolas", 10),
            justify="left",
            anchor="w"
        )
        text_label.pack(padx=10, pady=10, fill="both", expand=True)
        
        # Close button
        customtkinter.CTkButton(
            help_window,
            text="Close",
            command=help_window.destroy,
            width=200,
            height=40,
            fg_color="gray50",
            hover_color="gray40"
        ).pack(pady=(0, 15))


    # --- ADVANCED PATCHING TAB ---
    def _run_auth(self):
        """Run authentication"""
        ps3 = self._get_ps3_connection()
        if not ps3:
            return
        
        try:
            # Log to both outputs
            self.output_advanced.insert("end", "Running Authentication...\n")
            self.output_advanced.see("end")
            if hasattr(self, 'output_quick') and self.output_quick:
                self.output_quick.insert("end", "Running Authentication...\n")
                self.output_quick.see("end")
            
            result = ps3.auth()
            
            self.output_advanced.insert("end", result + "\n")
            self.output_advanced.see("end")
            if hasattr(self, 'output_quick') and self.output_quick:
                self.output_quick.insert("end", result + "\n")
                self.output_quick.see("end")
            
            if "successful" in result:
                self.is_authenticated = True
                self.auth_status_label.configure(text="Status: AUTHENTICATED", text_color=FG_SUCCESS)
                self._update_rsx_button_state()
                messagebox.showinfo("Auth Result", result)
            else:
                self.is_authenticated = False
                self.auth_status_label.configure(text="Status: AUTH FAILED", text_color=FG_ERROR)
                messagebox.showerror("Auth Failed", result)
                
        except Exception as e:
            error_msg = f"Error: {str(e)}"
            self.output_advanced.insert("end", error_msg + "\n")
            if hasattr(self, 'output_quick') and self.output_quick:
                self.output_quick.insert("end", error_msg + "\n")
            messagebox.showerror("Error", str(e))

    def _check_safe_auth(self):
        if not self.is_authenticated:
            self.output_advanced.insert("end", "ERROR: AUTH required before any RSX patching!\n")
            self.output_advanced.see("end")
            messagebox.showerror("Authentication Required", "You must authenticate before RSX patching to prevent bricking!")
            return False
        return True
    
    def _run_cxr_patcher(self):
        """CXR to CXRF patcher - mit korrekter Output-Formatierung"""
        ps3 = self._get_ps3_connection()
        if not ps3:
            return
        
        self.output_advanced.insert("end", "\n=== CXR to CXRF Patcher (Mullion Only) ===\n")
        self.output_advanced.see("end")
        
        try:
            # Step 1: Check current value
            self.output_advanced.insert("end", "Step 1: Checking current value...\n")
            self.output_advanced.insert("end", "Command: EEP GET 3961 01\n")
            self.output_advanced.see("end")
            
            ret = ps3.command("EEP GET 3961 01", wait=1)
            
            if ret[0] == 0xFFFFFFFF:
                messagebox.showerror("Error", f"Command failed: {ret[1][0]}")
                return
            
            # Korrekte Formatierung wie im alten GUI
            response = ' '.join(str(x) for x in ret[1])
            self.output_advanced.insert("end", f"Response: {response}\n")
            self.output_advanced.see("end")
            
            if self.sandbox_mode.get() or "FF" in response.upper():
                self.output_advanced.insert("end", "✓ Current value is FF - proceeding with patch\n")
                self.output_advanced.see("end")
                
                # Step 2: Patch
                self.output_advanced.insert("end", "\nStep 2: Patching to 00...\n")
                self.output_advanced.insert("end", "Command: EEP SET 3961 01 00\n")
                self.output_advanced.see("end")
                
                ret = ps3.command("EEP SET 3961 01 00", wait=1)
                
                if ret[0] == 0xFFFFFFFF:
                    messagebox.showerror("Error", f"Patch failed: {ret[1][0]}")
                    return
                
                self.output_advanced.insert("end", "✓ Patch command sent\n")
                self.output_advanced.see("end")
                time.sleep(0.5)
                
                # Step 3: Verify
                self.output_advanced.insert("end", "\nStep 3: Verifying patch...\n")
                self.output_advanced.insert("end", "Command: EEP GET 3961 01\n")
                self.output_advanced.see("end")
                
                ret = ps3.command("EEP GET 3961 01", wait=1)
                response = ' '.join(str(x) for x in ret[1])
                self.output_advanced.insert("end", f"Response: {response}\n")
                self.output_advanced.see("end")
                
                if self.sandbox_mode.get() or "00000000 00" in response or " 00" in response:
                    self.output_advanced.insert("end", "✓ Patch verified successfully!\n\n")
                    self.output_advanced.see("end")
                    
                    messagebox.showinfo("Success", "Patch successful!\n\nPlease turn off console at the PSU switch.")
                    messagebox.showinfo("Next Step", 
                                      "Please:\n"
                                      "1. Connect diag wire to ground\n"
                                      "2. Switch mode to CXRF in the GUI\n"
                                      "3. Turn console back on")
                    
                    self.output_advanced.insert("end", "=== CXR to CXRF Patch Complete ===\n\n")
                    self.output_advanced.see("end")
                else:
                    messagebox.showerror("Error", "Verification failed! Value is not 00")
            else:
                messagebox.showwarning("Warning", 
                                     f"Current value is not FF!\n"
                                     f"Response: {response}\n\n"
                                     f"Cannot proceed with patch.")
            
        except Exception as e:
            error_msg = f"Error during CXR to CXRF patch: {str(e)}"
            self.output_advanced.insert("end", f"\nERROR: {error_msg}\n")
            messagebox.showerror("Error", error_msg)

    def _run_checksum_correction(self):
        """Automatische Checksum-Korrektur - mit korrekter Output-Formatierung"""
        ps3 = self._get_ps3_connection()
        if not ps3:
            return
        
        self.output_advanced.insert("end", "\n=== Checksum Correction ===\n")
        self.output_advanced.see("end")
        
        try:
            self.output_advanced.insert("end", "Running: eepcsum\n")
            self.output_advanced.see("end")
            
            ret = ps3.command("eepcsum", wait=1)
            
            if ret[0] == 0xFFFFFFFF:
                messagebox.showerror("Error", f"eepcsum failed: {ret[1][0]}")
                return
            
            # Korrekte Formatierung des eepcsum outputs
            sc_type = self.sc_type_combobox.get()
            if sc_type == 'SW':
                response_lines = ''.join(ret[1]).split('\n')
            else:
                response_lines = ' '.join(ret[1]).split('\n')
            
            self.output_advanced.insert("end", "eepcsum output:\n")
            for line in response_lines:
                self.output_advanced.insert("end", f"{line}\n")
            self.output_advanced.see("end")
            
            # Parse for corrections
            corrections_found = False
            
            for i, line in enumerate(response_lines):
                if "sum:" in line.lower():
                    if i + 1 < len(response_lines):
                        next_line = response_lines[i + 1]
                        match = re.search(r'Addr:\s*0x([0-9a-fA-F]+)\s+should be\s+0x([0-9a-fA-F]+)', next_line)
                        
                        if match:
                            corrections_found = True
                            address = match.group(1).upper()
                            value = match.group(2).upper()
                            
                            address_clean = address[-4:] if len(address) >= 4 else address
                            value_clean = value[-4:] if len(value) >= 4 else value
                            
                            self.output_advanced.insert("end", f"\n✓ Found correction needed:\n")
                            self.output_advanced.insert("end", f"  Address: 0x{address_clean}\n")
                            self.output_advanced.insert("end", f"  Value: 0x{value_clean}\n")
                            self.output_advanced.see("end")
                            
                            if len(value_clean) == 4:
                                byte1 = value_clean[2:4]
                                byte2 = value_clean[0:2]
                                command = f"w {address_clean} {byte1} {byte2}"
                                
                                self.output_advanced.insert("end", f"  Command: {command}\n")
                                self.output_advanced.see("end")
                                
                                confirm = messagebox.askyesno("Checksum Correction", 
                                                             f"Apply correction?\n\n"
                                                             f"Address: 0x{address_clean}\n"
                                                             f"Value: 0x{value_clean}\n"
                                                             f"Command: {command}\n\n"
                                                             f"Apply this fix?")
                                
                                if confirm:
                                    ret = ps3.command(command, wait=1)
                                    
                                    if ret[0] != 0xFFFFFFFF:
                                        self.output_advanced.insert("end", "✓ Correction applied!\n")
                                        self.output_advanced.see("end")
                                        messagebox.showinfo("Success", "Checksum correction applied successfully!")
                                    else:
                                        self.output_advanced.insert("end", f"Failed: {ret[1]}\n")
                                        messagebox.showerror("Error", f"Correction failed: {ret[1][0]}")
                                else:
                                    self.output_advanced.insert("end", "✗ Correction cancelled by user\n")
            
            if not corrections_found:
                if self.sandbox_mode.get():
                    self.output_advanced.insert("end", "\n[SANDBOX] Simulating - no real corrections needed\n")
                else:
                    self.output_advanced.insert("end", "\n✓ Checksum is OK - no corrections needed\n")
                messagebox.showinfo("Checksum OK", "No checksum corrections needed!")
            
            self.output_advanced.insert("end", "\n=== Checksum Correction Complete ===\n\n")
            self.output_advanced.see("end")
            
        except Exception as e:
            error_msg = f"Error during checksum correction: {str(e)}"
            self.output_advanced.insert("end", f"\nERROR: {error_msg}\n")
            messagebox.showerror("Error", error_msg)

    def _run_rsx_checksum_correction(self):
        """RSX Swap Checksum Correction - Speziell für Adressen 32FE und 34FE mit Endian-Swapping"""
        ps3 = self._get_ps3_connection()
        if not ps3:
            return
        
        self.output_advanced.insert("end", "\n=== RSX Swap Checksum Correction (32FE/34FE) ===\n")
        self.output_advanced.see("end")
        
        # Die beiden RSX-spezifischen Adressen
        rsx_addresses = ["32FE", "34FE"]
        
        try:
            for address in rsx_addresses:
                self.output_advanced.insert("end", f"\nChecking address 0x{address}...\n")
                self.output_advanced.see("end")
                
                # Lese die aktuellen 2 Bytes an der Adresse
                command = f"r {address}"
                self.output_advanced.insert("end", f"Command: {command}\n")
                self.output_advanced.see("end")
                
                ret = ps3.command(command, wait=1)
                
                if ret[0] == 0xFFFFFFFF:
                    self.output_advanced.insert("end", f"✗ Failed to read address {address}: {ret[1][0]}\n")
                    continue
                
                # Parse die Response
                output = self._format_command_output(ret, self.sc_type_combobox.get())
                self.output_advanced.insert("end", f"Response: {output}\n")
                self.output_advanced.see("end")
                
                # Extrahiere die Hex-Werte aus der Response
                # Format ist typischerweise: "00000000 XX YY" oder ähnlich
                parts = output.split()
                
                if len(parts) >= 3:
                    # Die letzten 2 Teile sind die Bytes
                    byte1 = parts[-2]  # Erstes Byte
                    byte2 = parts[-1]  # Zweites Byte
                    
                    # Original value (wie es gelesen wurde)
                    original_value = f"{byte2}{byte1}"  # Big Endian Format
                    
                    self.output_advanced.insert("end", f"  Current bytes: {byte1} {byte2}\n")
                    self.output_advanced.insert("end", f"  Current value (Big Endian): 0x{original_value}\n")
                    
                    # Endian Swap: Bytes tauschen
                    swapped_byte1 = byte2
                    swapped_byte2 = byte1
                    swapped_value = f"{swapped_byte2}{swapped_byte1}"
                    
                    self.output_advanced.insert("end", f"  Swapped bytes: {swapped_byte1} {swapped_byte2}\n")
                    self.output_advanced.insert("end", f"  Swapped value (Little Endian): 0x{swapped_value}\n")
                    self.output_advanced.see("end")
                    
                    # Frage den User ob er swappen möchte
                    confirm = messagebox.askyesno(
                        "RSX Checksum Swap", 
                        f"Address: 0x{address}\n\n"
                        f"Current bytes: {byte1} {byte2}\n"
                        f"Current value: 0x{original_value}\n\n"
                        f"Swapped bytes: {swapped_byte1} {swapped_byte2}\n"
                        f"Swapped value: 0x{swapped_value}\n\n"
                        f"Apply endian swap for this address?"
                    )
                    
                    if confirm:
                        # Schreibe die geswappten Bytes zurück
                        write_command = f"w {address} {swapped_byte1} {swapped_byte2}"
                        self.output_advanced.insert("end", f"  Writing: {write_command}\n")
                        self.output_advanced.see("end")
                        
                        ret = ps3.command(write_command, wait=1)
                        
                        if ret[0] != 0xFFFFFFFF:
                            self.output_advanced.insert("end", f"✓ Swap applied successfully for 0x{address}!\n")
                            self.output_advanced.see("end")
                            
                            # Verify
                            self.output_advanced.insert("end", f"  Verifying...\n")
                            self.output_advanced.see("end")
                            
                            ret_verify = ps3.command(f"r {address}", wait=1)
                            output_verify = self._format_command_output(ret_verify, self.sc_type_combobox.get())
                            self.output_advanced.insert("end", f"  Verification: {output_verify}\n")
                            self.output_advanced.see("end")
                        else:
                            self.output_advanced.insert("end", f"✗ Failed to write: {ret[1]}\n")
                            self.output_advanced.see("end")
                    else:
                        self.output_advanced.insert("end", f"✗ Swap cancelled by user for 0x{address}\n")
                        self.output_advanced.see("end")
                else:
                    self.output_advanced.insert("end", f"✗ Could not parse response for address {address}\n")
                    self.output_advanced.see("end")
            
            self.output_advanced.insert("end", "\n=== RSX Swap Checksum Correction Complete ===\n\n")
            self.output_advanced.see("end")
            messagebox.showinfo("Complete", "RSX Swap Checksum Correction process completed!")
            
        except Exception as e:
            error_msg = f"Error during RSX checksum correction: {str(e)}"
            self.output_advanced.insert("end", f"\nERROR: {error_msg}\n")
            self.output_advanced.see("end")
            messagebox.showerror("Error", error_msg)


    def _run_patch_40(self):
        if not self._check_safe_auth(): 
            return
        
        # Create popup dialog for model selection
        dialog = customtkinter.CTkToplevel(self.root)
        dialog.title("Select PS3 Model")
        dialog.geometry("420x220")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center the dialog
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (420 // 2)
        y = (dialog.winfo_screenheight() // 2) - (220 // 2)
        dialog.geometry(f"420x220+{x}+{y}")
        
        customtkinter.CTkLabel(dialog, text="Select your RSX Model:", font=(FONT_UI[0], 14, "bold")).pack(pady=20)
        
        result = {"value": None}
        
        def select_standard():
            result["value"] = "standard"
            dialog.destroy()
        
        def select_ggb():
            result["value"] = "ggb"
            dialog.destroy()
        
        customtkinter.CTkButton(
            dialog, 
            text="AGB / BGB / CGB / DGB",
            command=select_standard,
            width=320,
            height=45,
            font=(FONT_UI[0], 12)
        ).pack(pady=8)
        
        customtkinter.CTkButton(
            dialog, 
            text="Use For GGB Only",
            command=select_ggb,
            width=320,
            height=45,
            font=(FONT_UI[0], 12)
        ).pack(pady=8)
        
        # Wait for dialog to close
        self.root.wait_window(dialog)
        
        if result["value"] is None:
            return  # User closed dialog without selecting
        
        # Execute patch based on selection
        if result["value"] == "standard":
            # Original code for AGB/BGB/CGB/DGB (EC value)
            PATCH_40NM = [
                "w 3242 03 61 82 80 01 91",
                "w 3254 21 EC",
                "w 348B 8B",
                "w 34AF 8B"
            ]
            self._execute_patch(PATCH_40NM, "40NM RSX Patch (AGB/BGB/CGB/DGB)")
        else:  # GGB
            # Modified code for GGB (EB value)
            PATCH_40NM_GGB = [
                "w 3242 03 61 82 80 01 91",
                "w 3254 21 EB",
                "w 348B 8B",
                "w 34AF 8B"
            ]
            self._execute_patch(PATCH_40NM_GGB, "40NM RSX Patch (GGB Only)")

    def _run_patch_65(self):
        if not self._check_safe_auth(): 
            return
        
        PATCH_65NM = [
            "w 3242 03 A2 03 B0 07 71",
            "w 3254 21 E8",
            "w 348B 88",
            "w 34AF 88"
        ]
        self._execute_patch(PATCH_65NM, "65NM RSX Patch")

    def _execute_patch(self, commands, patch_name):
        """Execute patch commands - mit korrekter Output-Formatierung"""
        ps3 = self._get_ps3_connection()
        if not ps3:
            return
        
        self.output_advanced.insert("end", f"\n=== Starting {patch_name} ===\n")
        self.output_advanced.see("end")
        
        try:
            for i, cmd in enumerate(commands, 1):
                self.output_advanced.insert("end", f"[{i}/{len(commands)}] Executing: {cmd}\n")
                self.output_advanced.see("end")
                
                ret = ps3.command(cmd, wait=1)
                
                if ret[0] == 0xFFFFFFFF:
                    error_msg = f"Command failed: {ret[1][0]}"
                    self.output_advanced.insert("end", f"ERROR: {error_msg}\n")
                    self.output_advanced.see("end")
                    messagebox.showerror("Patch Error", error_msg)
                    return
                
                # Korrekte Output-Formatierung
                output = self._format_command_output(ret, self.sc_type_combobox.get())
                self.output_advanced.insert("end", f"✓ Response: {output}\n")
                self.output_advanced.see("end")
                
                time.sleep(0.3)
            
            self.output_advanced.insert("end", f"\n=== {patch_name} completed successfully! ===\n\n")
            self.output_advanced.see("end")
            messagebox.showinfo("Success", f"{patch_name} completed successfully!")
            
        except Exception as e:
            error_msg = f"Error during patch execution: {str(e)}"
            self.output_advanced.insert("end", f"\nERROR: {error_msg}\n")
            messagebox.showerror("Error", error_msg)

    # --- MANUAL COMMANDS TAB ---
    def _send_manual(self, event=None):
        """Send manual command - mit korrekter Output-Formatierung wie im alten GUI"""
        ps3 = self._get_ps3_connection()
        if not ps3:
            return
        
        command = self.command_entry.get().strip()
        if not command:
            messagebox.showwarning("Warning", "Please enter a command")
            return
        
        try:
            self.output_manual.insert("end", f"Command: {command}\n")
            self.output_manual.see("end")
            
            ret = ps3.command(command, wait=1)
            
            # DIES IST DER SCHLÜSSEL: Verwende die korrekte Formatierung wie im alten GUI
            output = self._format_command_output(ret, self.sc_type_combobox.get())
            
            self.output_manual.insert("end", output + "\n")
            self.output_manual.see("end")
            
            self.command_entry.delete(0, "end")
            
        except Exception as e:
            self.output_manual.insert("end", f"Error: {str(e)}\n")
            self.output_manual.see("end")

    # === FAN SETTINGS TAB - BRAND NEW CLEAN IMPLEMENTATION ===
    def _build_fan_tab(self):
        """Fan Settings Tab - Light theme for matplotlib compatibility"""
        f = self.frame_fan
        f.grid_columnconfigure(0, weight=1)
        f.grid_rowconfigure(2, weight=1)
        
        # Configure light background for this tab
        f.configure(fg_color="white")
        
        # Title - WHITE text for dark background outside the tab
        title = customtkinter.CTkLabel(f, text="Fan Curve Editor for FAT PS3 (COK-001/002)", 
                                       font=(FONT_UI[0], 16, "bold"), text_color="white")
        title.grid(row=0, column=0, padx=20, pady=(20, 5), sticky="w")
        
        warning = customtkinter.CTkLabel(f, text="WARNING: For CXRF Mullion Syscons on FAT consoles only! Modify with caution.", 
                                        text_color="#ff3333", font=(FONT_UI[0], 10))
        warning.grid(row=1, column=0, padx=20, pady=(0, 10), sticky="w")
        
        # Main container - light theme
        main_frame = customtkinter.CTkFrame(f, corner_radius=10, fg_color="#f0f0f0")
        main_frame.grid(row=2, column=0, padx=20, pady=10, sticky="nsew")
        main_frame.grid_columnconfigure((0,1), weight=1)
        main_frame.grid_rowconfigure(1, weight=1)
        
        # Control buttons
        btn_frame = customtkinter.CTkFrame(main_frame, fg_color="transparent")
        btn_frame.grid(row=0, column=0, columnspan=2, padx=10, pady=10, sticky="ew")
        btn_frame.grid_columnconfigure((0,1,2,3), weight=1)
        
        customtkinter.CTkButton(btn_frame, text="Load from Console", command=self._fan_load, height=40, 
                              fg_color="#0078d4", hover_color="#005a9e", text_color="white").grid(row=0, column=0, padx=5, sticky="ew")
        customtkinter.CTkButton(btn_frame, text="Save to Console", command=self._fan_save, height=40, 
                              fg_color="#0078d4", hover_color="#005a9e", text_color="white").grid(row=0, column=1, padx=5, sticky="ew")
        customtkinter.CTkButton(btn_frame, text="Load Preset", command=self._fan_preset, height=40, 
                              fg_color="#0078d4", hover_color="#005a9e", text_color="white").grid(row=0, column=2, padx=5, sticky="ew")
        customtkinter.CTkButton(btn_frame, text="Reset to Stock", command=self._fan_reset, height=40, 
                              fg_color="#0078d4", hover_color="#005a9e", text_color="white").grid(row=0, column=3, padx=5, sticky="ew")
        
        # Left: Graph
        graph_frame = customtkinter.CTkFrame(main_frame, corner_radius=10, fg_color="white", border_width=2, border_color="#cccccc")
        graph_frame.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")
        
        # Initialize data - 5 PHASES with INTEGER temperatures
        self.cell_data = [[0, 70, 51], [65, 75, 90], [72, 80, 128], [75, 85, 200], [80, 90, 255]]
        self.rsx_data = [[0, 78, 51], [70, 82, 90], [75, 87, 128], [80, 90, 200], [85, 95, 255]]
        self.cell_tshutdown = 85
        self.rsx_tshutdown = 95
        self.cell_entries = []
        self.rsx_entries = []
        
        # Try to create matplotlib graph with LIGHT theme
        self.has_graph = False
        try:
            import matplotlib
            matplotlib.use('TkAgg')
            from matplotlib.figure import Figure
            from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
            
            # Light theme figure - LARGER SIZE
            self.fig = Figure(figsize=(6.5, 5.5), facecolor='white', dpi=95)
            self.ax = self.fig.add_subplot(111)
            self.canvas = FigureCanvasTkAgg(self.fig, master=graph_frame)
            self.canvas_widget = self.canvas.get_tk_widget()
            self.canvas_widget.pack(fill="both", expand=True, padx=10, pady=10)
            
            self.dragging = False
            self.drag_point = None
            self.drag_curve = None
            
            self.canvas.mpl_connect('button_press_event', self._graph_press)
            self.canvas.mpl_connect('motion_notify_event', self._graph_move)
            self.canvas.mpl_connect('button_release_event', self._graph_release)
            
            # Draw initial graph with default data
            self.has_graph = True
            # Delay initial draw to ensure everything is set up
            self.root.after(100, self._update_graph)
            
        except Exception as e:
            customtkinter.CTkLabel(graph_frame, text=f"Matplotlib error\n\n{str(e)}\n\nInstall: pip install matplotlib", 
                                 font=(FONT_UI[0], 11), text_color="#cc0000").pack(expand=True, pady=50)
        
        # Right: Data table in scrollable frame - light theme, TALLER
        scroll_frame = customtkinter.CTkScrollableFrame(main_frame, width=400, height=580, fg_color="white", 
                                                       border_width=2, border_color="#cccccc")
        scroll_frame.grid(row=1, column=1, padx=10, pady=10, sticky="nsew")
        
        # CELL Table - 5 PHASES
        customtkinter.CTkLabel(scroll_frame, text="CELL (CPU) Fan Table", font=(FONT_UI[0], 13, "bold"), 
                             text_color="#cc0000").pack(pady=(5,3))
        
        cell_frame = customtkinter.CTkFrame(scroll_frame, fg_color="white")
        cell_frame.pack(fill="x", padx=5, pady=5)
        
        # Headers
        headers = customtkinter.CTkFrame(cell_frame, fg_color="white")
        headers.pack(fill="x")
        customtkinter.CTkLabel(headers, text="Phase", font=(FONT_UI[0], 10, "bold"), text_color="black", width=50).pack(side="left", padx=2)
        customtkinter.CTkLabel(headers, text="TMin(C)", font=(FONT_UI[0], 10, "bold"), text_color="black", width=70).pack(side="left", padx=2)
        customtkinter.CTkLabel(headers, text="TMax(C)", font=(FONT_UI[0], 10, "bold"), text_color="black", width=70).pack(side="left", padx=2)
        customtkinter.CTkLabel(headers, text="Speed", font=(FONT_UI[0], 10, "bold"), text_color="black", width=70).pack(side="left", padx=2)
        
        for i in range(5):
            row = customtkinter.CTkFrame(cell_frame, fg_color="white")
            row.pack(fill="x", pady=2)
            customtkinter.CTkLabel(row, text=f"p{i}", text_color="black", width=50, font=(FONT_UI[0], 10)).pack(side="left", padx=2)
            e1 = customtkinter.CTkEntry(row, width=70, height=28, border_color="#cccccc", font=(FONT_UI[0], 10))
            e1.pack(side="left", padx=2)
            e1.insert(0, str(int(self.cell_data[i][0])))
            e2 = customtkinter.CTkEntry(row, width=70, height=28, border_color="#cccccc", font=(FONT_UI[0], 10))
            e2.pack(side="left", padx=2)
            e2.insert(0, str(int(self.cell_data[i][1])))
            e3 = customtkinter.CTkEntry(row, width=70, height=28, border_color="#cccccc", font=(FONT_UI[0], 10))
            e3.pack(side="left", padx=2)
            e3.insert(0, str(self.cell_data[i][2]))
            self.cell_entries.append((e1, e2, e3))
        
        # T-Shutdown
        tshut_row = customtkinter.CTkFrame(cell_frame, fg_color="white")
        tshut_row.pack(fill="x", pady=5)
        customtkinter.CTkLabel(tshut_row, text="T-Shutdown:", font=(FONT_UI[0], 10, "bold"), text_color="black").pack(side="left", padx=2)
        self.cell_tshut_entry = customtkinter.CTkEntry(tshut_row, width=70, height=28, border_color="#cccccc", font=(FONT_UI[0], 10))
        self.cell_tshut_entry.pack(side="left", padx=2)
        self.cell_tshut_entry.insert(0, str(self.cell_tshutdown))
        
        # Separator
        customtkinter.CTkFrame(scroll_frame, height=2, fg_color="#999999").pack(fill="x", pady=10)
        
        # RSX Table - 5 PHASES
        customtkinter.CTkLabel(scroll_frame, text="RSX (GPU) Fan Table", font=(FONT_UI[0], 13, "bold"), 
                             text_color="#0066cc").pack(pady=(5,3))
        
        rsx_frame = customtkinter.CTkFrame(scroll_frame, fg_color="white")
        rsx_frame.pack(fill="x", padx=5, pady=5)
        
        # Headers
        headers2 = customtkinter.CTkFrame(rsx_frame, fg_color="white")
        headers2.pack(fill="x")
        customtkinter.CTkLabel(headers2, text="Phase", font=(FONT_UI[0], 10, "bold"), text_color="black", width=50).pack(side="left", padx=2)
        customtkinter.CTkLabel(headers2, text="TMin(C)", font=(FONT_UI[0], 10, "bold"), text_color="black", width=70).pack(side="left", padx=2)
        customtkinter.CTkLabel(headers2, text="TMax(C)", font=(FONT_UI[0], 10, "bold"), text_color="black", width=70).pack(side="left", padx=2)
        customtkinter.CTkLabel(headers2, text="Speed", font=(FONT_UI[0], 10, "bold"), text_color="black", width=70).pack(side="left", padx=2)
        
        for i in range(5):
            row = customtkinter.CTkFrame(rsx_frame, fg_color="white")
            row.pack(fill="x", pady=2)
            customtkinter.CTkLabel(row, text=f"p{i}", text_color="black", width=50, font=(FONT_UI[0], 10)).pack(side="left", padx=2)
            e1 = customtkinter.CTkEntry(row, width=70, height=28, border_color="#cccccc", font=(FONT_UI[0], 10))
            e1.pack(side="left", padx=2)
            e1.insert(0, str(int(self.rsx_data[i][0])))
            e2 = customtkinter.CTkEntry(row, width=70, height=28, border_color="#cccccc", font=(FONT_UI[0], 10))
            e2.pack(side="left", padx=2)
            e2.insert(0, str(int(self.rsx_data[i][1])))
            e3 = customtkinter.CTkEntry(row, width=70, height=28, border_color="#cccccc", font=(FONT_UI[0], 10))
            e3.pack(side="left", padx=2)
            e3.insert(0, str(self.rsx_data[i][2]))
            self.rsx_entries.append((e1, e2, e3))
        
        # T-Shutdown
        tshut_row2 = customtkinter.CTkFrame(rsx_frame, fg_color="white")
        tshut_row2.pack(fill="x", pady=5)
        customtkinter.CTkLabel(tshut_row2, text="T-Shutdown:", font=(FONT_UI[0], 10, "bold"), text_color="black").pack(side="left", padx=2)
        self.rsx_tshut_entry = customtkinter.CTkEntry(tshut_row2, width=70, height=28, border_color="#cccccc", font=(FONT_UI[0], 10))
        self.rsx_tshut_entry.pack(side="left", padx=2)
        self.rsx_tshut_entry.insert(0, str(self.rsx_tshutdown))
        
        # Add some bottom padding to ensure scrolling works
        customtkinter.CTkLabel(scroll_frame, text="", height=20).pack()
        
        # Output - light theme, MUCH SMALLER
        output_frame = customtkinter.CTkFrame(f, corner_radius=10, fg_color="#f0f0f0", border_width=2, border_color="#cccccc")
        output_frame.grid(row=3, column=0, padx=20, pady=(10, 20), sticky="ew")
        customtkinter.CTkLabel(output_frame, text="Output Log:", font=(FONT_UI[0], 11, "bold"), 
                             text_color="black").pack(anchor="w", padx=10, pady=(8, 3))
        self.output_fan = customtkinter.CTkTextbox(output_frame, font=(FONT_UI[0], 9), corner_radius=10, 
                                                   fg_color="white", text_color="black", border_width=1, 
                                                   border_color="#cccccc", height=50)
        self.output_fan.pack(fill="both", expand=True, padx=10, pady=(0, 8))
    
    def _fan_load(self):
        """Load fan table from console - 5 PHASES"""
        ps3 = self._get_ps3_connection()
        if not ps3: return
        self.output_fan.insert("end", "\n=== Loading Fan Tables (5 phases) ===\n")
        self.output_fan.see("end")
        try:
            for cpu_id, name, entries, data_list in [(0, "CELL", self.cell_entries, self.cell_data), (1, "RSX", self.rsx_entries, self.rsx_data)]:
                self.output_fan.insert("end", f"\nReading {name}...\n")
                for i in range(5):
                    ret = ps3.command(f"fantbl getini {cpu_id} p{i}", wait=0.3)
                    if ret[0] != 0xFFFFFFFF:
                        output = self._format_command_output(ret, self.sc_type_combobox.get())
                        parts = [p for p in output.split() if '.' in p or p.startswith('0x')]
                        if len(parts) >= 3:
                            tmin, tmax = int(float(parts[0])), int(float(parts[1]))
                            speed = int(parts[2], 16) if parts[2].startswith('0x') else int(parts[2])
                            data_list[i] = [tmin, tmax, speed]
                            entries[i][0].delete(0, 'end'); entries[i][0].insert(0, str(tmin))
                            entries[i][1].delete(0, 'end'); entries[i][1].insert(0, str(tmax))
                            entries[i][2].delete(0, 'end'); entries[i][2].insert(0, str(speed))
            self.output_fan.insert("end", "\nLoad complete!\n")
            self._update_graph()
            messagebox.showinfo("Success", "Fan tables loaded!")
        except Exception as e:
            self.output_fan.insert("end", f"\nError: {e}\n")
    
    def _fan_save(self):
        """Save fan table to console - 5 PHASES"""
        ps3 = self._get_ps3_connection()
        if not ps3: return
        if not messagebox.askyesno("Confirm", "Write new fan tables to console (5 phases)?\n\nIncorrect values can damage hardware!"):
            return
        self.output_fan.insert("end", "\n=== Saving Fan Tables (5 phases) ===\n")
        try:
            for cpu_id, name, entries in [(0, "CELL", self.cell_entries), (1, "RSX", self.rsx_entries)]:
                self.output_fan.insert("end", f"\nWriting {name}...\n")
                for i in range(5):
                    tmin = int(float(entries[i][0].get()))
                    tmax = int(float(entries[i][1].get()))
                    speed = int(entries[i][2].get())
                    cmd = f"fantbl setini {cpu_id} p{i} {tmin}.00 {tmax}.00 0x{speed:02x}"
                    self.output_fan.insert("end", f"  {cmd}\n")
                    self.output_fan.see("end")
                    ret = ps3.command(cmd, wait=0.3)
                    if ret[0] == 0xFFFFFFFF:
                        messagebox.showerror("Error", f"Failed at {name} p{i}")
                        return
                tshut = int(self.cell_tshut_entry.get()) if cpu_id == 0 else int(self.rsx_tshut_entry.get())
                ps3.command(f"tshutdown setini {cpu_id} {tshut}", wait=0.3)
            self.output_fan.insert("end", "\nSave complete!\n")
            messagebox.showwarning("Fix Checksum", "IMPORTANT: Fix EEPROM checksum now!\n\nGo to Advanced Patching tab and run:\n'Checksum Correction (Auto-detect & Fix)'")
        except Exception as e:
            self.output_fan.insert("end", f"\nError: {e}\n")
    
    def _fan_preset(self):
        """Load preset - 5 PHASES with INTEGERS"""
        presets = {
            "Stock": {
                "cell": [[0, 70, 51], [65, 75, 90], [72, 80, 128], [75, 85, 200], [80, 90, 255]], 
                "rsx": [[0, 78, 51], [70, 82, 90], [75, 87, 128], [80, 90, 200], [85, 95, 255]]
            },
            "Quiet": {
                "cell": [[0, 70, 45], [65, 75, 70], [72, 80, 110], [75, 85, 180], [80, 90, 255]], 
                "rsx": [[0, 78, 45], [70, 82, 70], [75, 87, 110], [80, 90, 180], [85, 95, 255]]
            },
            "Performance": {
                "cell": [[0, 65, 60], [60, 70, 100], [68, 75, 150], [72, 80, 220], [78, 85, 255]], 
                "rsx": [[0, 75, 60], [65, 80, 100], [72, 85, 150], [78, 88, 220], [83, 92, 255]]
            }
        }
        win = customtkinter.CTkToplevel(self.root)
        win.title("Load Preset")
        win.geometry("350x220")
        win.transient(self.root)
        win.grab_set()
        customtkinter.CTkLabel(win, text="Select Preset", font=(FONT_UI[0], 14, "bold")).pack(pady=20)
        var = customtkinter.StringVar(value="Stock")
        for name in presets.keys():
            customtkinter.CTkRadioButton(win, text=name, variable=var, value=name).pack(pady=5, padx=20, anchor="w")
        def apply():
            preset = presets[var.get()]
            for i in range(5):
                for j, val in enumerate(preset["cell"][i]):
                    self.cell_entries[i][j].delete(0, 'end')
                    self.cell_entries[i][j].insert(0, str(int(val)))
                    self.cell_data[i][j] = int(val)
                for j, val in enumerate(preset["rsx"][i]):
                    self.rsx_entries[i][j].delete(0, 'end')
                    self.rsx_entries[i][j].insert(0, str(int(val)))
                    self.rsx_data[i][j] = int(val)
            self._update_graph()
            win.destroy()
            messagebox.showinfo("Loaded", f"Preset '{var.get()}' loaded!")
        customtkinter.CTkButton(win, text="Apply", command=apply, fg_color="gray50", hover_color="gray40").pack(pady=20)
    
    def _fan_reset(self):
        """Reset to stock"""
        if messagebox.askyesno("Reset", "Reset to stock values?"):
            self._fan_preset()  # Just trigger preset with Stock selected
    
    def _update_graph(self):
        """Update the fan curve graph - LIGHT THEME"""
        if not self.has_graph:
            return
        
        import numpy as np
        
        self.ax.clear()
        
        # Light background
        self.ax.set_facecolor('white')
        self.fig.patch.set_facecolor('white')
        
        # Extract TMax and Speed for plotting (convert speed 0-255 to 0-100%)
        cell_temps = [p[1] for p in self.cell_data]
        cell_speeds = [p[2] * 100 / 255 for p in self.cell_data]
        rsx_temps = [p[1] for p in self.rsx_data]
        rsx_speeds = [p[2] * 100 / 255 for p in self.rsx_data]
        
        # Plot curves with visible markers - bright colors for light background
        self.ax.plot(cell_temps, cell_speeds, 'o-', color='#cc0000', linewidth=3, markersize=12, 
                    markeredgecolor='black', markeredgewidth=1.5, label='CELL (CPU)', zorder=3)
        self.ax.plot(rsx_temps, rsx_speeds, 's-', color='#0066cc', linewidth=3, markersize=12, 
                    markeredgecolor='black', markeredgewidth=1.5, label='RSX (GPU)', zorder=3)
        
        # Styling with black text
        self.ax.set_xlabel('Temperature (C)', color='black', fontsize=12, fontweight='bold')
        self.ax.set_ylabel('Fan Speed (%)', color='black', fontsize=12, fontweight='bold')
        self.ax.set_title('PS3 Fan Curve', color='black', fontsize=13, fontweight='bold', pad=12)
        self.ax.set_xlim(0, 100)
        self.ax.set_ylim(0, 110)
        
        # Grid styling - light gray for white background
        self.ax.grid(True, alpha=0.5, color='#cccccc', linestyle='-', linewidth=1, zorder=1)
        
        # Tick styling - black for light theme
        self.ax.tick_params(axis='both', colors='black', labelsize=10, width=1.5, length=6)
        for spine in self.ax.spines.values():
            spine.set_color('black')
            spine.set_linewidth(1.5)
        
        # Legend styling
        legend = self.ax.legend(loc='upper left', facecolor='white', edgecolor='black', 
                               fontsize=10, labelcolor='black', framealpha=0.9)
        legend.get_frame().set_linewidth(1.5)
        
        self.fig.tight_layout()
        
        # Force canvas to draw
        try:
            self.canvas.draw_idle()
            self.canvas.flush_events()
        except:
            self.canvas.draw()
    
    def _graph_press(self, event):
        """Handle mouse press on graph"""
        if not event.inaxes:
            return
        
        # Find closest point
        min_dist = 999
        for i, p in enumerate(self.cell_data):
            temp, speed_pct = p[1], p[2] * 100 / 255
            dist = ((event.xdata - temp)**2 + (event.ydata - speed_pct)**2)**0.5
            if dist < min_dist and dist < 8:
                min_dist = dist
                self.drag_point = i
                self.drag_curve = 'cell'
        
        for i, p in enumerate(self.rsx_data):
            temp, speed_pct = p[1], p[2] * 100 / 255
            dist = ((event.xdata - temp)**2 + (event.ydata - speed_pct)**2)**0.5
            if dist < min_dist and dist < 8:
                min_dist = dist
                self.drag_point = i
                self.drag_curve = 'rsx'
        
        if self.drag_point is not None:
            self.dragging = True
    
    def _graph_move(self, event):
        """Handle mouse move (drag point)"""
        if not self.dragging or not event.inaxes:
            return
        
        new_temp = int(max(0, min(100, event.xdata)))  # Round to integer
        new_speed_pct = max(0, min(100, event.ydata))
        new_speed = int(new_speed_pct * 255 / 100)
        
        i = self.drag_point
        entries = self.cell_entries if self.drag_curve == 'cell' else self.rsx_entries
        data = self.cell_data if self.drag_curve == 'cell' else self.rsx_data
        
        # Update data and entries
        data[i][1] = new_temp
        data[i][2] = new_speed
        entries[i][1].delete(0, 'end')
        entries[i][1].insert(0, str(new_temp))
        entries[i][2].delete(0, 'end')
        entries[i][2].insert(0, str(new_speed))
        
        self._update_graph()
    
    def _graph_release(self, event):
        """Handle mouse release"""
        self.dragging = False
        self.drag_point = None
        self.drag_curve = None


def main():
    customtkinter.set_appearance_mode("Dark")
    customtkinter.set_default_color_theme("blue")

    root = customtkinter.CTk()
    root.geometry("950x800")
    app = PS3SysconGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
