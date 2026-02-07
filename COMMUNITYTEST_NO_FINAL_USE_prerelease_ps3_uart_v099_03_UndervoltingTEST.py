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


# --- PS3UART Klasse (Backend) - UNCHANGED ---
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
            # For CXRF/Internal mode, read until prompt or timeout
            if hasattr(self, 'type') and self.type == 'CXRF':
                # Read more aggressively for internal mode
                import time
                start = time.time()
                buffer = b''
                while time.time() - start < 2.0:  # 2 second timeout
                    waiting = self.ser.inWaiting()
                    if waiting > 0:
                        chunk = self.ser.read(waiting)
                        buffer += chunk
                        # Check if we got the prompt
                        if b'[mullion]$' in buffer or b'SC_READY' in buffer:
                            break
                    time.sleep(0.05)  # Small delay between reads
                return buffer if buffer else self.ser.read(self.ser.inWaiting())
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
        
        # Restart detection for CXR->CXRF workflow
        self.just_restarted_cxrf = (len(sys.argv) > 1 and sys.argv[1] == '--cxrf-restart')
        
        self._build_root_layout()
        
        # Show checksum reminder after CXRF restart
        if self.just_restarted_cxrf:
            self.root.after(1000, self._show_checksum_reminder)
    
    def _show_checksum_reminder(self):
        """Show checksum reminder popup"""
        result = messagebox.askyesno(
            "Checksum Correction Required",
            "If your console beeped 3 times after restart,\n"
            "you MUST fix the checksum now!\n\n"
            "Click YES to go to Checksum Correction."
        )
        if result:
            self.tab_view.set("Advanced Patching")

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
        self.tab_view.add("Undervolt")
        self.tab_view.add("Fan Settings (FAT)")
        
        self.frame_advanced = self.tab_view.tab("Advanced Patching")
        self.frame_quick = self.tab_view.tab("Quick Commands")
        self.frame_manual = self.tab_view.tab("Manual Commands")
        self.frame_undervolt = self.tab_view.tab("Undervolt")
        self.frame_fan = self.tab_view.tab("Fan Settings (FAT)")

        self._build_advanced_tab()
        self._build_quick_tab()
        self._build_manual_tab()
        self._build_undervolt_tab()
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
        # Auto-select CXRF after restart
        if hasattr(self, 'just_restarted_cxrf') and self.just_restarted_cxrf:
            self.sc_type_combobox.set("CXRF")
        else:
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
        self._update_checksum_button_state()
        # Update CXR to CXRF button
        if self.is_authenticated:
            if choice == "CXR":
                self.cxr_button.configure(state="normal")
            else:
                self.cxr_button.configure(state="disabled")
    
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
        self.cxr_button = customtkinter.CTkButton(f, text="CXR to CXRF Patcher (Mullion Only)", command=self._run_cxr_patcher, font=btn_font, height=50, fg_color="gray50", hover_color="gray40", state="disabled")
        self.cxr_button.grid(row=3, column=0, padx=10, pady=5, sticky="ew")

        self.checksum_button = customtkinter.CTkButton(f, text="Checksum Correction (Auto-detect & Fix)", command=self._run_checksum_correction, font=btn_font, height=50, fg_color="gray50", hover_color="gray40", state="disabled")
        self.checksum_button.grid(row=3, column=1, padx=10, pady=5, sticky="ew")
        self._update_checksum_button_state()
        
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
    
    def _update_checksum_button_state(self):
        """Enable/disable checksum button based on SC Type and AUTH"""
        sc_type = self.sc_type_combobox.get()
        # Only enable if authenticated AND CXRF mode
        if sc_type == "CXRF" and self.is_authenticated:
            self.checksum_button.configure(state="normal")
        else:
            self.checksum_button.configure(state="disabled")
    
    def _update_all_buttons_after_auth(self):
        """Enable buttons after successful authentication"""
        # CXR to CXRF patcher only works in CXR mode
        sc_type = self.sc_type_combobox.get()
        if sc_type == "CXR":
            self.cxr_button.configure(state="normal")
        else:
            self.cxr_button.configure(state="disabled")
        # Update checksum button based on mode
        self._update_checksum_button_state()
        # RSX buttons are handled by _update_rsx_button_state

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
        f.grid_rowconfigure(4, weight=1)

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
  Ã¢â‚¬Â¢ EEP GET <addr> <len> - Read EEPROM
  Ã¢â‚¬Â¢ EEP SET <addr> <len> <data> - Write EEPROM
  Ã¢â‚¬Â¢ ERRLOG GET 00 - Get error log (00-1F)

Internal Mode:
  Ã¢â‚¬Â¢ r <addr> - Read from EEPROM address
  Ã¢â‚¬Â¢ w <addr> <data> - Write to EEPROM address
  Ã¢â‚¬Â¢ errlog - Get error log
  Ã¢â‚¬Â¢ clearerrlog - Clear error log
  Ã¢â‚¬Â¢ fantbl - Fan table commands
  Ã¢â‚¬Â¢ patchvereep - Get patched version"""

        customtkinter.CTkLabel(help_frame, text=help_text, font=("Consolas", 9), justify="left").pack(padx=15, pady=10, anchor="w")

        # Output
        customtkinter.CTkLabel(f, text="Output Log:", font=(FONT_UI[0], 12, "bold")).grid(row=3, column=0, padx=10, pady=(10, 5), sticky="w")
        self.output_manual = customtkinter.CTkTextbox(f, font=FONT_MONO, corner_radius=10, text_color=FG_OUTPUT_DARK_BG)
        self.output_manual.grid(row=4, column=0, padx=10, pady=(0, 10), sticky="nsew")

    # --- HELPER METHODS ---
    def _get_ps3_connection(self):
        """Get PS3UART instance with current settings"""
        port = self.port_combobox.get()
        sc_type = self.sc_type_combobox.get()
        sandbox = self.sandbox_mode.get()
        
        if not sandbox and (not port or not sc_type):
            messagebox.showerror("Error", "Please select serial port and SC type.")
            return None
        
        if sc_type in ("CXR","SW"):
            serial_speed = "57600"  # CXR and SW are 57600
        else:
            serial_speed = "115200"  # CXRF uses 115200
        
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
        Diese Methode ist der SchlÃƒÂ¼ssel zur korrekten Output-Darstellung!
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
Ã¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€Â

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

Ã¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€ÂÃ¢â€Â
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
            self._log_to_output("Running Authentication...\n")
            if hasattr(self, 'output_quick') and self.output_quick:
                self.output_quick.insert("end", "Running Authentication...\n")
                self.output_quick.see("end")
            
            result = ps3.auth()
            
            self._log_to_output(result + "\n")
            if hasattr(self, 'output_quick') and self.output_quick:
                self.output_quick.insert("end", result + "\n")
                self.output_quick.see("end")
            
            if "successful" in result:
                self.is_authenticated = True
                self.auth_status_label.configure(text="Status: AUTHENTICATED", text_color=FG_SUCCESS)
                self._update_rsx_button_state()
                self._update_all_buttons_after_auth()
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
            self._log_to_output("ERROR: AUTH required before any RSX patching!\n")
            messagebox.showerror("Authentication Required", "You must authenticate before RSX patching to prevent bricking!")
            return False
        return True
    
    def _log_to_output(self, text, widget=None):
        """Helper to log text and auto-scroll"""
        if widget is None:
            widget = self.output_advanced
        widget.insert("end", text)
        widget.see("end")
        widget.update_idletasks()  # Force UI update
    
    def _run_cxr_patcher(self):
        """CXR to CXRF patcher - mit korrekter Output-Formatierung"""
        ps3 = self._get_ps3_connection()
        if not ps3:
            return
        
        self._log_to_output("\n=== CXR to CXRF Patcher (Mullion Only) ===\n")
        
        try:
            # Step 1: Check current value
            self.output_advanced.insert("end", "Step 1: Checking current value...\n")
            self._log_to_output("Command: EEP GET 3961 01\n")
            
            ret = ps3.command("EEP GET 3961 01", wait=1)
            
            if ret[0] == 0xFFFFFFFF:
                messagebox.showerror("Error", f"Command failed: {ret[1][0]}")
                return
            
            # Korrekte Formatierung wie im alten GUI
            response = ' '.join(str(x) for x in ret[1])
            self._log_to_output(f"Response: {response}\n")
            
            if self.sandbox_mode.get() or "FF" in response.upper():
                self._log_to_output("Ã¢Å“â€œ Current value is FF - proceeding with patch\n")
                
                # Step 2: Patch
                self.output_advanced.insert("end", "\nStep 2: Patching to 00...\n")
                self._log_to_output("Command: EEP SET 3961 01 00\n")
                
                ret = ps3.command("EEP SET 3961 01 00", wait=1)
                
                if ret[0] == 0xFFFFFFFF:
                    messagebox.showerror("Error", f"Patch failed: {ret[1][0]}")
                    return
                
                self._log_to_output("Ã¢Å“â€œ Patch command sent\n")
                time.sleep(0.5)
                
                # Step 3: Verify
                self.output_advanced.insert("end", "\nStep 3: Verifying patch...\n")
                self._log_to_output("Command: EEP GET 3961 01\n")
                
                ret = ps3.command("EEP GET 3961 01", wait=1)
                response = ' '.join(str(x) for x in ret[1])
                self._log_to_output(f"Response: {response}\n")
                
                if self.sandbox_mode.get() or "00" in response:
                    self._log_to_output("Ã¢Å“â€œ Patch verified successfully!\n\n")
                    
                    messagebox.showinfo("Patch Successful!", 
                        "CXR to CXRF patch completed successfully!\n\nValue changed from FF to 00.")
                    
                    messagebox.showwarning("Shutdown Required", 
                        "Please shut down your console at the power switch.\n\nPress OK when done.")
                    
                    restart = messagebox.askyesno("Connect DIAG Wire", 
                        "Connect DIAG to ground now.\n\n"
                        "Program will restart in CXRF mode.\n\nClick YES to restart.")
                    
                    if restart:
                        # Close serial connection
                        if hasattr(ps3, 'ser') and ps3.ser:
                            try:
                                ps3.ser.close()
                            except:
                                pass
                        
                        # Restart application
                        import os
                        os.execl(sys.executable, sys.executable, __file__, '--cxrf-restart')
                    else:
                        messagebox.showinfo("Manual Steps",
                            "Please do manually:\n1. Change SC Type to CXRF\n2. Run Checksum Correction")
                    
                    self._log_to_output("=== CXR to CXRF Patch Complete ===\n\n")
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
        
        self._log_to_output("\n=== Checksum Correction ===\n")
        
        try:
            self._log_to_output("Running: eepcsum\n")
            
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
                self._log_to_output(f"{line}\n")
            
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
                            
                            self.output_advanced.insert("end", f"\nÃ¢Å“â€œ Found correction needed:\n")
                            self.output_advanced.insert("end", f"  Address: 0x{address_clean}\n")
                            self._log_to_output(f"  Value: 0x{value_clean}\n")
                            
                            if len(value_clean) == 4:
                                byte1 = value_clean[2:4]
                                byte2 = value_clean[0:2]
                                command = f"w {address_clean} {byte1} {byte2}"
                                
                                self._log_to_output(f"  Command: {command}\n")
                                
                                confirm = messagebox.askyesno("Checksum Correction", 
                                                             f"Apply correction?\n\n"
                                                             f"Address: 0x{address_clean}\n"
                                                             f"Value: 0x{value_clean}\n"
                                                             f"Command: {command}\n\n"
                                                             f"Apply this fix?")
                                
                                if confirm:
                                    ret = ps3.command(command, wait=1)
                                    
                                    if ret[0] != 0xFFFFFFFF:
                                        self._log_to_output("Ã¢Å“â€œ Correction applied!\n")
                                        messagebox.showinfo("Success", "Checksum correction applied successfully!")
                                    else:
                                        self.output_advanced.insert("end", f"Failed: {ret[1]}\n")
                                        messagebox.showerror("Error", f"Correction failed: {ret[1][0]}")
                                else:
                                    self.output_advanced.insert("end", "Ã¢Å“â€” Correction cancelled by user\n")
            
            if not corrections_found:
                if self.sandbox_mode.get():
                    self.output_advanced.insert("end", "\n[SANDBOX] Simulating - no real corrections needed\n")
                else:
                    self.output_advanced.insert("end", "\nÃ¢Å“â€œ Checksum is OK - no corrections needed\n")
                messagebox.showinfo("Checksum OK", "No checksum corrections needed!")
            
            self._log_to_output("\n=== Checksum Correction Complete ===\n\n")
            
        except Exception as e:
            error_msg = f"Error during checksum correction: {str(e)}"
            self.output_advanced.insert("end", f"\nERROR: {error_msg}\n")
            messagebox.showerror("Error", error_msg)

    def _run_rsx_checksum_correction(self):
        """RSX Swap Checksum Correction - Speziell fÃƒÂ¼r Adressen 32FE und 34FE mit Endian-Swapping"""
        ps3 = self._get_ps3_connection()
        if not ps3:
            return
        
        self._log_to_output("\n=== RSX Swap Checksum Correction (32FE/34FE) ===\n")
        
        # Die beiden RSX-spezifischen Adressen
        rsx_addresses = ["32FE", "34FE"]
        
        try:
            for address in rsx_addresses:
                self._log_to_output(f"\nChecking address 0x{address}...\n")
                
                # Lese die aktuellen 2 Bytes an der Adresse
                command = f"r {address}"
                self._log_to_output(f"Command: {command}\n")
                
                ret = ps3.command(command, wait=1)
                
                if ret[0] == 0xFFFFFFFF:
                    self.output_advanced.insert("end", f"Ã¢Å“â€” Failed to read address {address}: {ret[1][0]}\n")
                    continue
                
                # Parse die Response
                output = self._format_command_output(ret, self.sc_type_combobox.get())
                self._log_to_output(f"Response: {output}\n")
                
                # Extrahiere die Hex-Werte aus der Response
                # Format ist typischerweise: "00000000 XX YY" oder ÃƒÂ¤hnlich
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
                    self._log_to_output(f"  Swapped value (Little Endian): 0x{swapped_value}\n")
                    
                    # Frage den User ob er swappen mÃƒÂ¶chte
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
                        # Schreibe die geswappten Bytes zurÃƒÂ¼ck
                        write_command = f"w {address} {swapped_byte1} {swapped_byte2}"
                        self._log_to_output(f"  Writing: {write_command}\n")
                        
                        ret = ps3.command(write_command, wait=1)
                        
                        if ret[0] != 0xFFFFFFFF:
                            self._log_to_output(f"Ã¢Å“â€œ Swap applied successfully for 0x{address}!\n")
                            
                            # Verify
                            self._log_to_output(f"  Verifying...\n")
                            
                            ret_verify = ps3.command(f"r {address}", wait=1)
                            output_verify = self._format_command_output(ret_verify, self.sc_type_combobox.get())
                            self._log_to_output(f"  Verification: {output_verify}\n")
                        else:
                            self._log_to_output(f"Ã¢Å“â€” Failed to write: {ret[1]}\n")
                    else:
                        self._log_to_output(f"Ã¢Å“â€” Swap cancelled by user for 0x{address}\n")
                else:
                    self._log_to_output(f"Ã¢Å“â€” Could not parse response for address {address}\n")
            
            self._log_to_output("\n=== RSX Swap Checksum Correction Complete ===\n\n")
            messagebox.showinfo("Complete", "RSX Swap Checksum Correction process completed!")
            
        except Exception as e:
            error_msg = f"Error during RSX checksum correction: {str(e)}"
            self._log_to_output(f"\nERROR: {error_msg}\n")
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
        
        self._log_to_output(f"\n=== Starting {patch_name} ===\n")
        
        try:
            for i, cmd in enumerate(commands, 1):
                self._log_to_output(f"[{i}/{len(commands)}] Executing: {cmd}\n")
                
                ret = ps3.command(cmd, wait=1)
                
                if ret[0] == 0xFFFFFFFF:
                    error_msg = f"Command failed: {ret[1][0]}"
                    self._log_to_output(f"ERROR: {error_msg}\n")
                    messagebox.showerror("Patch Error", error_msg)
                    return
                
                # Korrekte Output-Formatierung
                output = self._format_command_output(ret, self.sc_type_combobox.get())
                self._log_to_output(f"Ã¢Å“â€œ Response: {output}\n")
                
                time.sleep(0.3)
            
            self._log_to_output(f"\n=== {patch_name} completed successfully! ===\n\n")
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
            
            # DIES IST DER SCHLÃƒÅ“SSEL: Verwende die korrekte Formatierung wie im alten GUI
            output = self._format_command_output(ret, self.sc_type_combobox.get())
            
            self.output_manual.insert("end", output + "\n")
            self.output_manual.see("end")
            
            self.command_entry.delete(0, "end")
            
        except Exception as e:
            self.output_manual.insert("end", f"Error: {str(e)}\n")
            self.output_manual.see("end")

    # === UNDERVOLT TAB ===
    def _build_undervolt_tab(self):
        """Undervolt Tab with Auto Presets and Manual Sliders"""
        f = self.frame_undervolt
        f.grid_columnconfigure(0, weight=1)
        f.grid_rowconfigure(3, weight=1)
        
        # Title
        title_label = customtkinter.CTkLabel(f, text="Undervolt Presets", font=(FONT_UI[0], 18, "bold"))
        title_label.grid(row=0, column=0, padx=20, pady=(20, 5), sticky="w")
        
        # Segmented Button + Info in one row
        top_row = customtkinter.CTkFrame(f, fg_color="transparent")
        top_row.grid(row=1, column=0, padx=20, pady=(0, 10), sticky="ew")
        
        self.uv_mode_segment = customtkinter.CTkSegmentedButton(
            top_row,
            values=["Auto Presets", "Manual Sliders"],
            command=self._switch_uv_mode,
            font=(FONT_UI[0], 10),
            height=28
        )
        self.uv_mode_segment.pack(side="left")
        self.uv_mode_segment.set("Auto Presets")
        
        # Info text next to it
        customtkinter.CTkLabel(
            top_row,
            text="Auto: community-tested • Manual: 0.8375V-1.6V (0.0125V steps)",
            font=(FONT_UI[0], 9),
            text_color="gray60"
        ).pack(side="left", padx=(15, 0))
        
        # Container for switchable content
        self.uv_content_frame = customtkinter.CTkFrame(f, corner_radius=10, fg_color="#2b2b2b")
        self.uv_content_frame.grid(row=2, column=0, padx=20, pady=10, sticky="nsew")
        
        # Build voltage lookup table
        self._build_voltage_table()
        
        # Build both modes (but only show one at a time)
        self._build_auto_mode()
        self._build_manual_mode()
        
        # Show auto mode by default
        self._switch_uv_mode("Auto Presets")
        
        # Output Log
        output_frame = customtkinter.CTkFrame(f, corner_radius=10, fg_color="#2b2b2b")
        output_frame.grid(row=3, column=0, padx=20, pady=(10, 20), sticky="ew")
        
        customtkinter.CTkLabel(
            output_frame,
            text="Output Log:",
            font=(FONT_UI[0], 11, "bold")
        ).pack(anchor="w", padx=10, pady=(8, 3))
        
        self.output_undervolt = customtkinter.CTkTextbox(
            output_frame,
            font=FONT_MONO,
            corner_radius=10,
            fg_color="#1e1e1e",
            text_color=FG_OUTPUT_DARK_BG,
            height=120
        )
        self.output_undervolt.pack(fill="both", expand=True, padx=10, pady=(0, 8))
    
    def _build_voltage_table(self):
        """Build voltage to HEX lookup table from the VID table"""
        self.voltage_to_hex = {
            1.6000: "2A", 1.5875: "0B", 1.5750: "2B", 1.5625: "0C", 1.5500: "2C",
            1.5375: "0D", 1.5250: "2D", 1.5125: "0E", 1.5000: "2E", 1.4875: "0F",
            1.4750: "2F", 1.4625: "10", 1.4500: "30", 1.4375: "11", 1.4250: "31",
            1.4125: "12", 1.4000: "32", 1.3875: "13", 1.3750: "33", 1.3625: "14",
            1.3500: "34", 1.3375: "15", 1.3250: "35", 1.3125: "16", 1.3000: "36",
            1.2875: "17", 1.2750: "37", 1.2625: "18", 1.2500: "38", 1.2375: "19",
            1.2250: "39", 1.2125: "1A", 1.2000: "3A", 1.1875: "1B", 1.1750: "3B",
            1.1625: "1C", 1.1500: "3C", 1.1375: "1D", 1.1250: "3D", 1.1125: "1E",
            1.1000: "3E", 1.0875: "00", 1.0750: "20", 1.0625: "01", 1.0500: "21",
            1.0375: "02", 1.0250: "22", 1.0125: "03", 1.0000: "23", 0.9875: "04",
            0.9750: "24", 0.9625: "05", 0.9500: "25", 0.9375: "06", 0.9250: "26",
            0.9125: "07", 0.9000: "27", 0.8875: "08", 0.8750: "28", 0.8625: "09",
            0.8500: "29", 0.8375: "0A"
        }
        
        # Reverse lookup for slider
        self.hex_to_voltage = {v: k for k, v in self.voltage_to_hex.items()}
    
    def _build_auto_mode(self):
        """Build Auto Presets mode (original layout)"""
        self.auto_frame = customtkinter.CTkFrame(self.uv_content_frame, fg_color="transparent")
        
        self.auto_frame.grid_columnconfigure(0, weight=1, uniform="cols")
        self.auto_frame.grid_columnconfigure(1, weight=1, uniform="cols")
        self.auto_frame.grid_rowconfigure(0, weight=0)
        self.auto_frame.grid_rowconfigure(1, weight=0)
        
        # === LEFT: CELL ===
        cell_frame = customtkinter.CTkFrame(self.auto_frame, corner_radius=10, fg_color="#1e1e1e")
        cell_frame.grid(row=0, column=0, padx=(10, 5), pady=(10, 5), sticky="nsew")
        
        customtkinter.CTkLabel(cell_frame, text="CELL (CPU)", font=(FONT_UI[0], 14, "bold"), text_color="#cc0000").pack(pady=(15, 5))
        
        self.cell_type_var = customtkinter.StringVar(value="90nm")
        cell_radio_frame = customtkinter.CTkFrame(cell_frame, fg_color="transparent")
        cell_radio_frame.pack(pady=(5, 10))
        
        customtkinter.CTkRadioButton(cell_radio_frame, text="90nm", variable=self.cell_type_var, value="90nm", font=(FONT_UI[0], 10)).pack(anchor="w", padx=30, pady=3)
        customtkinter.CTkRadioButton(cell_radio_frame, text="65nm", variable=self.cell_type_var, value="65nm", font=(FONT_UI[0], 10)).pack(anchor="w", padx=30, pady=3)
        customtkinter.CTkRadioButton(cell_radio_frame, text="45nm", variable=self.cell_type_var, value="45nm", font=(FONT_UI[0], 10)).pack(anchor="w", padx=30, pady=3)
        
        info_frame_cell = customtkinter.CTkFrame(cell_frame, fg_color="#2b2b2b", corner_radius=8)
        info_frame_cell.pack(fill="x", padx=15, pady=(5, 15))
        customtkinter.CTkLabel(info_frame_cell, text="• Lower voltage  • Reduce heat  • Extend life", font=("Consolas", 8), justify="left", text_color="gray80").pack(anchor="w", padx=8, pady=6)
        
        # === RIGHT: RSX ===
        rsx_frame = customtkinter.CTkFrame(self.auto_frame, corner_radius=10, fg_color="#1e1e1e")
        rsx_frame.grid(row=0, column=1, padx=(5, 10), pady=(10, 5), sticky="nsew")
        
        customtkinter.CTkLabel(rsx_frame, text="RSX (GPU)", font=(FONT_UI[0], 14, "bold"), text_color="#0066cc").pack(pady=(15, 5))
        
        self.rsx_type_var = customtkinter.StringVar(value="90nm")
        rsx_radio_frame = customtkinter.CTkFrame(rsx_frame, fg_color="transparent")
        rsx_radio_frame.pack(pady=(5, 10))
        
        customtkinter.CTkRadioButton(rsx_radio_frame, text="90nm", variable=self.rsx_type_var, value="90nm", font=(FONT_UI[0], 10)).pack(anchor="w", padx=30, pady=3)
        customtkinter.CTkRadioButton(rsx_radio_frame, text="65nm", variable=self.rsx_type_var, value="65nm", font=(FONT_UI[0], 10)).pack(anchor="w", padx=30, pady=3)
        customtkinter.CTkRadioButton(rsx_radio_frame, text="40nm", variable=self.rsx_type_var, value="40nm", font=(FONT_UI[0], 10)).pack(anchor="w", padx=30, pady=3)
        
        info_frame_rsx = customtkinter.CTkFrame(rsx_frame, fg_color="#2b2b2b", corner_radius=8)
        info_frame_rsx.pack(fill="x", padx=15, pady=(5, 15))
        customtkinter.CTkLabel(info_frame_rsx, text="• Chip-specific  • Lower GPU temp  • Test w/ games", font=("Consolas", 8), justify="left", text_color="gray80").pack(anchor="w", padx=8, pady=6)
        
        # Buttons
        self.cell_uv_button_auto = customtkinter.CTkButton(self.auto_frame, text="Apply CELL", command=self._apply_cell_undervolt, font=(FONT_UI[0], 12, "bold"), height=50, fg_color="#cc0000", hover_color="#990000")
        self.cell_uv_button_auto.grid(row=1, column=0, padx=(10, 5), pady=(0, 10), sticky="ew")
        
        self.rsx_uv_button_auto = customtkinter.CTkButton(self.auto_frame, text="Apply RSX", command=self._apply_rsx_undervolt, font=(FONT_UI[0], 12, "bold"), height=50, fg_color="#0066cc", hover_color="#004499")
        self.rsx_uv_button_auto.grid(row=1, column=1, padx=(5, 10), pady=(0, 10), sticky="ew")
        
        # Reverse checkbox
        reverse_frame = customtkinter.CTkFrame(self.auto_frame, fg_color="transparent")
        reverse_frame.grid(row=2, column=0, columnspan=2, padx=10, pady=(0, 10))
        
        self.reverse_to_stock_var = customtkinter.BooleanVar(value=False)
        self.reverse_checkbox = customtkinter.CTkCheckBox(reverse_frame, text="Reverse to Stock", variable=self.reverse_to_stock_var, font=(FONT_UI[0], 10), text_color="#ffaa00", fg_color="#ffaa00", hover_color="#cc8800")
        self.reverse_checkbox.pack(pady=5)
    
    def _build_manual_mode(self):
        """Build Manual Sliders mode"""
        self.manual_frame = customtkinter.CTkFrame(self.uv_content_frame, fg_color="transparent")
        self.manual_frame.grid_columnconfigure(0, weight=1)
        
        # CELL Slider - COMPACT
        cell_slider_frame = customtkinter.CTkFrame(self.manual_frame, corner_radius=10, fg_color="#1e1e1e")
        cell_slider_frame.pack(fill="x", padx=20, pady=(15, 8))
        
        customtkinter.CTkLabel(cell_slider_frame, text="CELL (CPU) Voltage", font=(FONT_UI[0], 12, "bold"), text_color="#cc0000").pack(pady=(12, 8))
        
        self.cell_voltage_var = customtkinter.DoubleVar(value=1.1375)
        self.cell_slider = customtkinter.CTkSlider(
            cell_slider_frame,
            from_=0.8375,
            to=1.6000,
            number_of_steps=61,
            variable=self.cell_voltage_var,
            command=self._update_cell_voltage,
            width=500,
            height=16
        )
        self.cell_slider.pack(pady=8)
        
        self.cell_voltage_label = customtkinter.CTkLabel(
            cell_slider_frame,
            text="1.1375V (0x1D)",
            font=("Consolas", 14, "bold"),
            text_color="#00ff00"
        )
        self.cell_voltage_label.pack(pady=(0, 12))
        
        # RSX Slider - COMPACT
        rsx_slider_frame = customtkinter.CTkFrame(self.manual_frame, corner_radius=10, fg_color="#1e1e1e")
        rsx_slider_frame.pack(fill="x", padx=20, pady=8)
        
        customtkinter.CTkLabel(rsx_slider_frame, text="RSX (GPU) Voltage", font=(FONT_UI[0], 12, "bold"), text_color="#0066cc").pack(pady=(12, 8))
        
        self.rsx_voltage_var = customtkinter.DoubleVar(value=1.1875)
        self.rsx_slider = customtkinter.CTkSlider(
            rsx_slider_frame,
            from_=0.8375,
            to=1.6000,
            number_of_steps=61,
            variable=self.rsx_voltage_var,
            command=self._update_rsx_voltage,
            width=500,
            height=16
        )
        self.rsx_slider.pack(pady=8)
        
        self.rsx_voltage_label = customtkinter.CTkLabel(
            rsx_slider_frame,
            text="1.1875V (0x1B)",
            font=("Consolas", 14, "bold"),
            text_color="#00ff00"
        )
        self.rsx_voltage_label.pack(pady=(0, 12))
        
        # Apply Buttons - COMPACT
        btn_frame = customtkinter.CTkFrame(self.manual_frame, fg_color="transparent")
        btn_frame.pack(fill="x", padx=20, pady=(8, 15))
        btn_frame.grid_columnconfigure((0,1), weight=1)
        
        self.cell_uv_button_manual = customtkinter.CTkButton(btn_frame, text="Apply CELL", command=self._apply_cell_manual, font=(FONT_UI[0], 12, "bold"), height=45, fg_color="#cc0000", hover_color="#990000")
        self.cell_uv_button_manual.grid(row=0, column=0, padx=5, sticky="ew")
        
        self.rsx_uv_button_manual = customtkinter.CTkButton(btn_frame, text="Apply RSX", command=self._apply_rsx_manual, font=(FONT_UI[0], 12, "bold"), height=45, fg_color="#0066cc", hover_color="#004499")
        self.rsx_uv_button_manual.grid(row=0, column=1, padx=5, sticky="ew")
    
    def _switch_uv_mode(self, mode):
        """Switch between Auto and Manual modes"""
        if mode == "Auto Presets":
            self.manual_frame.pack_forget()
            self.auto_frame.pack(fill="both", expand=True, padx=10, pady=10)
        else:  # Manual Sliders
            self.auto_frame.pack_forget()
            self.manual_frame.pack(fill="both", expand=True, padx=10, pady=10)
    
    def _update_cell_voltage(self, value):
        """Update CELL voltage display"""
        voltage = round(float(value), 4)
        hex_val = self.voltage_to_hex.get(voltage, "??")
        self.cell_voltage_label.configure(text=f"{voltage:.4f}V (0x{hex_val})")
    
    def _update_rsx_voltage(self, value):
        """Update RSX voltage display"""
        voltage = round(float(value), 4)
        hex_val = self.voltage_to_hex.get(voltage, "??")
        self.rsx_voltage_label.configure(text=f"{voltage:.4f}V (0x{hex_val})")
    
    def _apply_cell_manual(self):
        """Apply manual CELL voltage"""
        ps3 = self._get_ps3_connection()
        if not ps3:
            return
        
        voltage = round(self.cell_voltage_var.get(), 4)
        hex_val = self.voltage_to_hex.get(voltage, None)
        
        if not hex_val:
            messagebox.showerror("Error", f"Invalid voltage: {voltage}V")
            return
        
        confirm = messagebox.askyesno(
            "Confirm CELL Manual Voltage",
            f"WARNING: Undervolting can cause instability or damage!\n\n"
            f"Apply CELL voltage: {voltage}V (0x{hex_val})\n\n"
            "Test thoroughly after applying!\n\n"
            "Continue at your own risk?"
        )
        
        if not confirm:
            return
        
        try:
            self.output_undervolt.insert("end", f"\n=== Applying CELL Manual Voltage ===\n")
            self.output_undervolt.insert("end", f"Voltage: {voltage}V\n")
            self.output_undervolt.insert("end", f"Command: w 50 {hex_val}\n")
            self.output_undervolt.see("end")
            
            ret = ps3.command(f"w 50 {hex_val}", wait=1)
            
            if ret[0] != 0xFFFFFFFF:
                output = self._format_command_output(ret, self.sc_type_combobox.get())
                self.output_undervolt.insert("end", f"Response: {output}\n")
                self.output_undervolt.insert("end", f"\n✓ CELL voltage applied!\n")
                messagebox.showinfo("Success", f"CELL voltage set to {voltage}V!")
            else:
                error_msg = f"Command failed: {ret[1][0] if ret[1] else 'Unknown'}"
                self.output_undervolt.insert("end", f"ERROR: {error_msg}\n")
                messagebox.showerror("Error", error_msg)
        except Exception as e:
            self.output_undervolt.insert("end", f"\nERROR: {str(e)}\n")
            messagebox.showerror("Error", str(e))
    
    def _apply_rsx_manual(self):
        """Apply manual RSX voltage"""
        ps3 = self._get_ps3_connection()
        if not ps3:
            return
        
        voltage = round(self.rsx_voltage_var.get(), 4)
        hex_val = self.voltage_to_hex.get(voltage, None)
        
        if not hex_val:
            messagebox.showerror("Error", f"Invalid voltage: {voltage}V")
            return
        
        confirm = messagebox.askyesno(
            "Confirm RSX Manual Voltage",
            f"WARNING: Undervolting can cause instability or damage!\n\n"
            f"Apply RSX voltage: {voltage}V (0x{hex_val})\n\n"
            "Test with demanding games!\n\n"
            "Continue at your own risk?"
        )
        
        if not confirm:
            return
        
        try:
            self.output_undervolt.insert("end", f"\n=== Applying RSX Manual Voltage ===\n")
            self.output_undervolt.insert("end", f"Voltage: {voltage}V\n")
            self.output_undervolt.insert("end", f"Command: w 51 {hex_val}\n")
            self.output_undervolt.see("end")
            
            ret = ps3.command(f"w 51 {hex_val}", wait=1)
            
            if ret[0] != 0xFFFFFFFF:
                output = self._format_command_output(ret, self.sc_type_combobox.get())
                self.output_undervolt.insert("end", f"Response: {output}\n")
                self.output_undervolt.insert("end", f"\n✓ RSX voltage applied!\n")
                messagebox.showinfo("Success", f"RSX voltage set to {voltage}V!")
            else:
                error_msg = f"Command failed: {ret[1][0] if ret[1] else 'Unknown'}"
                self.output_undervolt.insert("end", f"ERROR: {error_msg}\n")
                messagebox.showerror("Error", error_msg)
        except Exception as e:
            self.output_undervolt.insert("end", f"\nERROR: {str(e)}\n")
            messagebox.showerror("Error", str(e))
        """Undervolt Tab with CELL and RSX presets"""
        f = self.frame_undervolt
        f.grid_columnconfigure(0, weight=1)
        f.grid_rowconfigure(2, weight=1)
        
        # Title
        title_label = customtkinter.CTkLabel(f, text="Undervolt Presets", font=(FONT_UI[0], 18, "bold"))
        title_label.grid(row=0, column=0, padx=20, pady=(20, 5), sticky="w")
        
        # Info text about community values
        info_label = customtkinter.CTkLabel(
            f,
            text="These presets use community-tested stable undervolt values.",
            font=(FONT_UI[0], 11),
            text_color="gray70"
        )
        info_label.grid(row=1, column=0, padx=20, pady=(0, 5), sticky="w")
        
        # Warning - NO EMOJI
        warning_label = customtkinter.CTkLabel(
            f, 
            text="WARNING: Undervolting can cause instability or damage! Use at your own risk. Test thoroughly!",
            text_color=FG_ERROR,
            font=(FONT_UI[0], 11, "bold"),
            wraplength=900
        )
        warning_label.grid(row=2, column=0, padx=20, pady=(0, 10), sticky="ew")
        
        # Main container
        main_frame = customtkinter.CTkFrame(f, corner_radius=10, fg_color="#2b2b2b")
        main_frame.grid(row=3, column=0, padx=20, pady=10, sticky="nsew")
        main_frame.grid_columnconfigure(0, weight=1, uniform="cols")  # Equal width
        main_frame.grid_columnconfigure(1, weight=1, uniform="cols")  # Equal width
        main_frame.grid_rowconfigure(0, weight=0)
        main_frame.grid_rowconfigure(1, weight=0)
        
        # === LEFT SIDE: CELL Undervolt ===
        cell_frame = customtkinter.CTkFrame(main_frame, corner_radius=10, fg_color="#1e1e1e")
        cell_frame.grid(row=0, column=0, padx=(10, 5), pady=(10, 5), sticky="nsew")
        
        customtkinter.CTkLabel(
            cell_frame, 
            text="CELL (CPU) Undervolt",
            font=(FONT_UI[0], 16, "bold"),
            text_color="#cc0000"
        ).pack(pady=(20, 10))
        
        customtkinter.CTkLabel(
            cell_frame,
            text="Select your CELL chip type:",
            font=(FONT_UI[0], 11, "bold")
        ).pack(pady=(0, 10))
        
        # CELL Type selection
        self.cell_type_var = customtkinter.StringVar(value="90nm")
        
        cell_radio_frame = customtkinter.CTkFrame(cell_frame, fg_color="transparent")
        cell_radio_frame.pack(pady=(0, 10))
        
        customtkinter.CTkRadioButton(
            cell_radio_frame,
            text="90nm CELL",
            variable=self.cell_type_var,
            value="90nm",
            font=(FONT_UI[0], 11)
        ).pack(anchor="w", padx=40, pady=5)
        
        customtkinter.CTkRadioButton(
            cell_radio_frame,
            text="65nm CELL",
            variable=self.cell_type_var,
            value="65nm",
            font=(FONT_UI[0], 11)
        ).pack(anchor="w", padx=40, pady=5)
        
        customtkinter.CTkRadioButton(
            cell_radio_frame,
            text="45nm CELL",
            variable=self.cell_type_var,
            value="45nm",
            font=(FONT_UI[0], 11)
        ).pack(anchor="w", padx=40, pady=5)
        
        # Info inside box
        info_frame_cell = customtkinter.CTkFrame(cell_frame, fg_color="#2b2b2b", corner_radius=8)
        info_frame_cell.pack(fill="x", padx=20, pady=(10, 20))
        
        customtkinter.CTkLabel(
            info_frame_cell,
            text="• Lowers CELL voltage\n• Reduces heat output\n• May extend lifespan",
            font=("Consolas", 9),
            justify="left",
            text_color="gray80"
        ).pack(anchor="w", padx=10, pady=10)
        
        # === RIGHT SIDE: RSX Undervolt ===
        rsx_frame = customtkinter.CTkFrame(main_frame, corner_radius=10, fg_color="#1e1e1e")
        rsx_frame.grid(row=0, column=1, padx=(5, 10), pady=(10, 5), sticky="nsew")
        
        customtkinter.CTkLabel(
            rsx_frame,
            text="RSX (GPU) Undervolt",
            font=(FONT_UI[0], 16, "bold"),
            text_color="#0066cc"
        ).pack(pady=(20, 10))
        
        customtkinter.CTkLabel(
            rsx_frame,
            text="Select your RSX chip type:",
            font=(FONT_UI[0], 11, "bold")
        ).pack(pady=(0, 10))
        
        # RSX Type selection
        self.rsx_type_var = customtkinter.StringVar(value="90nm")
        
        rsx_radio_frame = customtkinter.CTkFrame(rsx_frame, fg_color="transparent")
        rsx_radio_frame.pack(pady=(0, 10))
        
        customtkinter.CTkRadioButton(
            rsx_radio_frame,
            text="90nm RSX (CECHA/CECHB)",
            variable=self.rsx_type_var,
            value="90nm",
            font=(FONT_UI[0], 11)
        ).pack(anchor="w", padx=40, pady=5)
        
        customtkinter.CTkRadioButton(
            rsx_radio_frame,
            text="65nm RSX (CECHC/CECHE/CECHG)",
            variable=self.rsx_type_var,
            value="65nm",
            font=(FONT_UI[0], 11)
        ).pack(anchor="w", padx=40, pady=5)
        
        customtkinter.CTkRadioButton(
            rsx_radio_frame,
            text="40nm RSX (CECHH/CECHJ/CECHK)",
            variable=self.rsx_type_var,
            value="40nm",
            font=(FONT_UI[0], 11)
        ).pack(anchor="w", padx=40, pady=5)
        
        # Info inside box
        info_frame_rsx = customtkinter.CTkFrame(rsx_frame, fg_color="#2b2b2b", corner_radius=8)
        info_frame_rsx.pack(fill="x", padx=20, pady=(10, 20))
        
        customtkinter.CTkLabel(
            info_frame_rsx,
            text="• Optimized per chip size\n• Reduces GPU temps\n• Test with demanding games",
            font=("Consolas", 9),
            justify="left",
            text_color="gray80"
        ).pack(anchor="w", padx=10, pady=10)
        
        # === BUTTONS - Each in its own column, perfectly aligned ===
        # CELL Button - RED - in column 0
        self.cell_uv_button = customtkinter.CTkButton(
            main_frame,
            text="Apply CELL Undervolt",
            command=self._apply_cell_undervolt,
            font=(FONT_UI[0], 14, "bold"),
            height=60,
            fg_color="#cc0000",
            hover_color="#990000"
        )
        self.cell_uv_button.grid(row=1, column=0, padx=(10, 5), pady=(0, 10), sticky="ew")
        
        # RSX Button - BLUE - in column 1
        self.rsx_uv_button = customtkinter.CTkButton(
            main_frame,
            text="Apply RSX Undervolt",
            command=self._apply_rsx_undervolt,
            font=(FONT_UI[0], 14, "bold"),
            height=60,
            fg_color="#0066cc",
            hover_color="#004499"
        )
        self.rsx_uv_button.grid(row=1, column=1, padx=(5, 10), pady=(0, 10), sticky="ew")
        
        # === REVERSE TO STOCK CHECKBOX ===
        reverse_frame = customtkinter.CTkFrame(main_frame, fg_color="transparent")
        reverse_frame.grid(row=2, column=0, columnspan=2, padx=10, pady=(0, 10))
        
        self.reverse_to_stock_var = customtkinter.BooleanVar(value=False)
        
        self.reverse_checkbox = customtkinter.CTkCheckBox(
            reverse_frame,
            text="Reverse to Stock (loads original voltage values)",
            variable=self.reverse_to_stock_var,
            font=(FONT_UI[0], 11, "bold"),
            text_color="#ffaa00",
            fg_color="#ffaa00",
            hover_color="#cc8800"
        )
        self.reverse_checkbox.pack(pady=5)
        
        # Output Log
        output_frame = customtkinter.CTkFrame(f, corner_radius=10, fg_color="#2b2b2b")
        output_frame.grid(row=3, column=0, padx=20, pady=(10, 20), sticky="ew")
        
        customtkinter.CTkLabel(
            output_frame,
            text="Output Log:",
            font=(FONT_UI[0], 11, "bold")
        ).pack(anchor="w", padx=10, pady=(8, 3))
        
        self.output_undervolt = customtkinter.CTkTextbox(
            output_frame,
            font=FONT_MONO,
            corner_radius=10,
            fg_color="#1e1e1e",
            text_color=FG_OUTPUT_DARK_BG,
            height=50
        )
        self.output_undervolt.pack(fill="both", expand=True, padx=10, pady=(0, 8))
    
    def _apply_cell_undervolt(self):
        """Apply CELL undervolt preset"""
        ps3 = self._get_ps3_connection()
        if not ps3:
            return
        
        cell_type = self.cell_type_var.get()
        reverse_mode = self.reverse_to_stock_var.get()
        
        mode_text = "REVERSE TO STOCK" if reverse_mode else "UNDERVOLT"
        
        # Confirmation dialog with warning
        confirm = messagebox.askyesno(
            f"Confirm CELL {cell_type} {mode_text}",
            f"WARNING: Undervolting can cause instability or damage!\n\n"
            f"This will apply CELL {mode_text.lower()} for {cell_type} chip.\n"
            f"Mode: {'Restore stock voltages' if reverse_mode else 'Apply undervolt'}\n\n"
            "Make sure to:\n"
            "• Have good cooling\n"
            "• Test thoroughly after\n"
            "• Monitor for crashes\n\n"
            "Continue at your own risk?"
        )
        
        if not confirm:
            return
        
        self.output_undervolt.insert("end", f"\n=== Applying CELL {cell_type} {mode_text} ===\n")
        self.output_undervolt.see("end")
        
        try:
            # CELL commands based on chip type and mode
            if reverse_mode:
                # Stock voltage commands
                if cell_type == "90nm":
                    commands = ["w 50 39"]  # Stock 90nm: 1.25V
                    voltage = "1.25V"
                    chip_info = "90nm CELL (Stock)"
                elif cell_type == "65nm":
                    commands = ["w 50 3E"]  # Stock 65nm: 1.1V
                    voltage = "1.1V"
                    chip_info = "65nm CELL (Stock)"
                else:  # 45nm
                    commands = ["w 50 25"]  # Stock 45nm: 0.95V
                    voltage = "0.95V"
                    chip_info = "45nm CELL (Stock)"
            else:
                # Undervolt commands
                if cell_type == "90nm":
                    commands = ["w 50 1D"]  # UV 90nm: 1.1375V
                    voltage = "1.1375V"
                    chip_info = "90nm CELL (Undervolt)"
                elif cell_type == "65nm":
                    commands = ["w 50 3E"]  # UV 65nm: 1.1V (same as stock!)
                    voltage = "1.1V"
                    chip_info = "65nm CELL (Undervolt)"
                else:  # 45nm
                    commands = ["w 50 07"]  # UV 45nm: 0.9125V
                    voltage = "0.9125V"
                    chip_info = "45nm CELL (Undervolt)"
            
            self.output_undervolt.insert("end", f"Target: {chip_info}\n")
            self.output_undervolt.insert("end", f"Mode: {mode_text}\n")
            self.output_undervolt.insert("end", f"Voltage: {voltage}\n")
            self.output_undervolt.insert("end", f"Command: {commands[0]}\n")
            self.output_undervolt.see("end")
            
            # Execute command
            ret = ps3.command(commands[0], wait=1)
            
            if ret[0] != 0xFFFFFFFF:
                output = self._format_command_output(ret, self.sc_type_combobox.get())
                self.output_undervolt.insert("end", f"Response: {output}\n")
                self.output_undervolt.insert("end", f"\n✓ CELL {mode_text} applied successfully!\n")
                self.output_undervolt.see("end")
                
                messagebox.showinfo(
                    "Success",
                    f"CELL {cell_type} {mode_text.lower()} applied!\n\n"
                    f"Voltage: {voltage}\n\n"
                    "Please test thoroughly!"
                )
            else:
                error_msg = f"Command failed: {ret[1][0] if ret[1] else 'Unknown error'}"
                self.output_undervolt.insert("end", f"ERROR: {error_msg}\n")
                messagebox.showerror("Error", error_msg)
            
        except Exception as e:
            error_msg = f"Error during CELL operation: {str(e)}"
            self.output_undervolt.insert("end", f"\nERROR: {error_msg}\n")
            self.output_undervolt.see("end")
            messagebox.showerror("Error", error_msg)
    
    def _apply_rsx_undervolt(self):
        """Apply RSX undervolt based on selected chip type"""
        ps3 = self._get_ps3_connection()
        if not ps3:
            return
        
        rsx_type = self.rsx_type_var.get()
        reverse_mode = self.reverse_to_stock_var.get()
        
        mode_text = "REVERSE TO STOCK" if reverse_mode else "UNDERVOLT"
        
        # Confirmation dialog with warning
        confirm = messagebox.askyesno(
            f"Confirm RSX {rsx_type} {mode_text}",
            f"WARNING: Undervolting can cause instability or damage!\n\n"
            f"This will apply RSX {mode_text.lower()} for {rsx_type} chip.\n"
            f"Mode: {'Restore stock voltages' if reverse_mode else 'Apply undervolt'}\n\n"
            "Make sure to:\n"
            "• Have good cooling\n"
            "• Test with demanding games\n"
            "• Monitor for artifacts/crashes\n\n"
            "Continue at your own risk?"
        )
        
        if not confirm:
            return
        
        self.output_undervolt.insert("end", f"\n=== Applying RSX {rsx_type} {mode_text} ===\n")
        self.output_undervolt.see("end")
        
        try:
            # RSX commands based on chip type and mode
            if reverse_mode:
                # Stock voltage commands
                if rsx_type == "90nm":
                    commands = ["w 51 36"]  # Stock 90nm: 1.30V
                    voltage = "1.30V"
                    chip_info = "90nm RSX (Stock)"
                elif rsx_type == "65nm":
                    commands = ["w 51 3E"]  # Stock 65nm: 1.1V
                    voltage = "1.1V"
                    chip_info = "65nm RSX (Stock)"
                else:  # 40nm
                    commands = ["w 51 25"]  # Stock 40nm: 0.95V
                    voltage = "0.95V"
                    chip_info = "40nm RSX (Stock)"
            else:
                # Undervolt commands
                if rsx_type == "90nm":
                    commands = ["w 51 1B"]  # UV 90nm: 1.1875V
                    voltage = "1.1875V"
                    chip_info = "90nm RSX (Undervolt)"
                elif rsx_type == "65nm":
                    commands = ["w 51 00"]  # UV 65nm: 1.0875V
                    voltage = "1.0875V"
                    chip_info = "65nm RSX (Undervolt)"
                else:  # 40nm
                    commands = ["w 51 07"]  # UV 40nm: 0.9125V
                    voltage = "0.9125V"
                    chip_info = "40nm RSX (Undervolt)"
            
            self.output_undervolt.insert("end", f"Target: {chip_info}\n")
            self.output_undervolt.insert("end", f"Mode: {mode_text}\n")
            self.output_undervolt.insert("end", f"Voltage: {voltage}\n")
            self.output_undervolt.insert("end", f"Command: {commands[0]}\n")
            self.output_undervolt.see("end")
            
            # Execute command
            ret = ps3.command(commands[0], wait=1)
            
            if ret[0] != 0xFFFFFFFF:
                output = self._format_command_output(ret, self.sc_type_combobox.get())
                self.output_undervolt.insert("end", f"Response: {output}\n")
                self.output_undervolt.insert("end", f"\n✓ RSX {mode_text} applied successfully!\n")
                self.output_undervolt.see("end")
                
                messagebox.showinfo(
                    "Success",
                    f"RSX {rsx_type} {mode_text.lower()} applied!\n\n"
                    f"Voltage: {voltage}\n\n"
                    "Please test thoroughly with demanding games!"
                )
            else:
                error_msg = f"Command failed: {ret[1][0] if ret[1] else 'Unknown error'}"
                self.output_undervolt.insert("end", f"ERROR: {error_msg}\n")
                messagebox.showerror("Error", error_msg)
            
        except Exception as e:
            error_msg = f"Error during RSX operation: {str(e)}"
            self.output_undervolt.insert("end", f"\nERROR: {error_msg}\n")
            self.output_undervolt.see("end")
            messagebox.showerror("Error", error_msg)

    # === FAN SETTINGS TAB - 10 PHASES - 2 COLUMN LAYOUT ===
    def _build_fan_tab(self):
        """Fan Settings Tab - 10 Phases - Graph LEFT, Tables RIGHT"""
        f = self.frame_fan
        f.grid_columnconfigure(0, weight=1)
        f.grid_rowconfigure(2, weight=1)
        
        # Title
        title = customtkinter.CTkLabel(f, text="Fan Curve Editor for FAT PS3 (COK-001/002) - 10 Phases", 
                                       font=(FONT_UI[0], 16, "bold"), text_color="white")
        title.grid(row=0, column=0, padx=20, pady=(20, 5), sticky="w")
        
        warning = customtkinter.CTkLabel(f, text="WARNING: For CXRF Mullion Syscons on FAT consoles only! Modify with caution.", 
                                        text_color="#ff3333", font=(FONT_UI[0], 10))
        warning.grid(row=1, column=0, padx=20, pady=(0, 10), sticky="w")
        
        # Main container
        main_frame = customtkinter.CTkFrame(f, corner_radius=10, fg_color="#2b2b2b")
        main_frame.grid(row=2, column=0, padx=20, pady=10, sticky="nsew")
        main_frame.grid_columnconfigure(0, weight=1)  # Left column (graph)
        main_frame.grid_columnconfigure(1, weight=0)  # Right column (tables) - fixed width
        main_frame.grid_rowconfigure(1, weight=1)
        
        # Control buttons (spans both columns)
        btn_frame = customtkinter.CTkFrame(main_frame, fg_color="transparent")
        btn_frame.grid(row=0, column=0, columnspan=2, padx=10, pady=10, sticky="ew")
        btn_frame.grid_columnconfigure((0,1,2,3), weight=1)
        
        customtkinter.CTkButton(btn_frame, text="Load from Console", command=self._fan_load, height=40, 
                              fg_color="#0078d4", hover_color="#005a9e").grid(row=0, column=0, padx=5, sticky="ew")
        customtkinter.CTkButton(btn_frame, text="Save to Console", command=self._fan_save, height=40, 
                              fg_color="#0078d4", hover_color="#005a9e").grid(row=0, column=1, padx=5, sticky="ew")
        customtkinter.CTkButton(btn_frame, text="Load Preset", command=self._fan_preset, height=40, 
                              fg_color="#0078d4", hover_color="#005a9e").grid(row=0, column=2, padx=5, sticky="ew")
        customtkinter.CTkButton(btn_frame, text="Reset to Stock", command=self._fan_reset, height=40, 
                              fg_color="#0078d4", hover_color="#005a9e").grid(row=0, column=3, padx=5, sticky="ew")
        
        # LEFT SIDE: Graph Frame
        graph_frame = customtkinter.CTkFrame(main_frame, corner_radius=10, fg_color="#1e1e1e")
        graph_frame.grid(row=1, column=0, padx=(10, 5), pady=10, sticky="nsew")
        
        # Initialize data - 10 PHASES
        self.cell_data = [
            [0, 46, 77], [46, 55, 77], [53, 61, 77], [61, 65, 89], [63, 67, 102],
            [65, 69, 128], [67, 70, 153], [69, 72, 173], [75, 80, 255], [73, 85, 255]
        ]
        self.rsx_data = [
            [0, 40, 77], [40, 50, 89], [50, 55, 102], [54, 58, 117], [56, 61, 128],
            [60, 65, 153], [63, 69, 208], [68, 72, 255], [72, 75, 255], [75, 80, 255]
        ]
        self.cell_tshutdown = 85
        self.rsx_tshutdown = 80
        self.cell_entries = []
        self.rsx_entries = []
        
        # Create matplotlib graph
        self.has_graph = False
        try:
            import matplotlib
            matplotlib.use('TkAgg')
            from matplotlib.figure import Figure
            from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
            
            # Graph takes full left side
            self.fig = Figure(figsize=(7, 6), facecolor='#1e1e1e', dpi=90)
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
            
            self.has_graph = True
            self.root.after(100, self._update_graph)
            
        except Exception as e:
            customtkinter.CTkLabel(graph_frame, text=f"Matplotlib not available\n{str(e)}\n\nInstall: pip install matplotlib", 
                                 font=(FONT_UI[0], 11), text_color="#cc0000").pack(expand=True, pady=50)
        
        # RIGHT SIDE: Tables (scrollable) - FIXED WIDTH
        tables_scroll = customtkinter.CTkScrollableFrame(main_frame, width=320, fg_color="#2b2b2b")
        tables_scroll.grid(row=1, column=1, padx=(5, 10), pady=10, sticky="nsew")
        
        # CELL Table - 10 PHASES - COMPACT
        customtkinter.CTkLabel(tables_scroll, text="CELL (CPU)", 
                             font=(FONT_UI[0], 12, "bold"), text_color="#cc0000").pack(pady=(5,3))
        
        cell_container = customtkinter.CTkFrame(tables_scroll, fg_color="#1e1e1e")
        cell_container.pack(fill="x", padx=5, pady=5)
        
        # Headers - very compact
        headers = customtkinter.CTkFrame(cell_container, fg_color="transparent")
        headers.pack(fill="x", padx=3, pady=2)
        customtkinter.CTkLabel(headers, text="P", font=(FONT_UI[0], 8, "bold"), width=25).pack(side="left", padx=1)
        customtkinter.CTkLabel(headers, text="TMin", font=(FONT_UI[0], 8, "bold"), width=55).pack(side="left", padx=1)
        customtkinter.CTkLabel(headers, text="TMax", font=(FONT_UI[0], 8, "bold"), width=55).pack(side="left", padx=1)
        customtkinter.CTkLabel(headers, text="Spd", font=(FONT_UI[0], 8, "bold"), width=55).pack(side="left", padx=1)
        
        # 10 Phasen - super compact
        for i in range(10):
            row = customtkinter.CTkFrame(cell_container, fg_color="transparent")
            row.pack(fill="x", padx=3, pady=1)
            customtkinter.CTkLabel(row, text=f"{i}", width=25, font=(FONT_UI[0], 8)).pack(side="left", padx=1)
            e1 = customtkinter.CTkEntry(row, width=55, height=22, font=(FONT_UI[0], 8))
            e1.pack(side="left", padx=1)
            e1.insert(0, str(int(self.cell_data[i][0])))
            e2 = customtkinter.CTkEntry(row, width=55, height=22, font=(FONT_UI[0], 8))
            e2.pack(side="left", padx=1)
            e2.insert(0, str(int(self.cell_data[i][1])))
            e3 = customtkinter.CTkEntry(row, width=55, height=22, font=(FONT_UI[0], 8))
            e3.pack(side="left", padx=1)
            e3.insert(0, str(self.cell_data[i][2]))
            self.cell_entries.append((e1, e2, e3))
        
        # T-Shutdown
        tshut_row = customtkinter.CTkFrame(cell_container, fg_color="transparent")
        tshut_row.pack(fill="x", padx=3, pady=3)
        customtkinter.CTkLabel(tshut_row, text="T-Shutdown:", font=(FONT_UI[0], 8, "bold")).pack(side="left", padx=2)
        self.cell_tshut_entry = customtkinter.CTkEntry(tshut_row, width=50, height=22, font=(FONT_UI[0], 8))
        self.cell_tshut_entry.pack(side="left", padx=2)
        self.cell_tshut_entry.insert(0, str(self.cell_tshutdown))
        
        # Separator
        customtkinter.CTkFrame(tables_scroll, height=2, fg_color="#555555").pack(fill="x", pady=8)
        
        # RSX Table - 10 PHASES - COMPACT
        customtkinter.CTkLabel(tables_scroll, text="RSX (GPU)", 
                             font=(FONT_UI[0], 12, "bold"), text_color="#0066cc").pack(pady=(3,3))
        
        rsx_container = customtkinter.CTkFrame(tables_scroll, fg_color="#1e1e1e")
        rsx_container.pack(fill="x", padx=5, pady=5)
        
        # Headers - very compact
        headers2 = customtkinter.CTkFrame(rsx_container, fg_color="transparent")
        headers2.pack(fill="x", padx=3, pady=2)
        customtkinter.CTkLabel(headers2, text="P", font=(FONT_UI[0], 8, "bold"), width=25).pack(side="left", padx=1)
        customtkinter.CTkLabel(headers2, text="TMin", font=(FONT_UI[0], 8, "bold"), width=55).pack(side="left", padx=1)
        customtkinter.CTkLabel(headers2, text="TMax", font=(FONT_UI[0], 8, "bold"), width=55).pack(side="left", padx=1)
        customtkinter.CTkLabel(headers2, text="Spd", font=(FONT_UI[0], 8, "bold"), width=55).pack(side="left", padx=1)
        
        # 10 Phasen - super compact
        for i in range(10):
            row = customtkinter.CTkFrame(rsx_container, fg_color="transparent")
            row.pack(fill="x", padx=3, pady=1)
            customtkinter.CTkLabel(row, text=f"{i}", width=25, font=(FONT_UI[0], 8)).pack(side="left", padx=1)
            e1 = customtkinter.CTkEntry(row, width=55, height=22, font=(FONT_UI[0], 8))
            e1.pack(side="left", padx=1)
            e1.insert(0, str(int(self.rsx_data[i][0])))
            e2 = customtkinter.CTkEntry(row, width=55, height=22, font=(FONT_UI[0], 8))
            e2.pack(side="left", padx=1)
            e2.insert(0, str(int(self.rsx_data[i][1])))
            e3 = customtkinter.CTkEntry(row, width=55, height=22, font=(FONT_UI[0], 8))
            e3.pack(side="left", padx=1)
            e3.insert(0, str(self.rsx_data[i][2]))
            self.rsx_entries.append((e1, e2, e3))
        
        # T-Shutdown
        tshut_row2 = customtkinter.CTkFrame(rsx_container, fg_color="transparent")
        tshut_row2.pack(fill="x", padx=3, pady=3)
        customtkinter.CTkLabel(tshut_row2, text="T-Shutdown:", font=(FONT_UI[0], 8, "bold")).pack(side="left", padx=2)
        self.rsx_tshut_entry = customtkinter.CTkEntry(tshut_row2, width=50, height=22, font=(FONT_UI[0], 8))
        self.rsx_tshut_entry.pack(side="left", padx=2)
        self.rsx_tshut_entry.insert(0, str(self.rsx_tshutdown))
        
        # Spacer
        customtkinter.CTkLabel(tables_scroll, text="", height=10).pack()
        
        # Output Log - below everything
        output_frame = customtkinter.CTkFrame(f, corner_radius=10, fg_color="#2b2b2b")
        output_frame.grid(row=3, column=0, padx=20, pady=(10, 20), sticky="ew")
        customtkinter.CTkLabel(output_frame, text="Output Log:", font=(FONT_UI[0], 10, "bold")).pack(anchor="w", padx=10, pady=(5, 2))
        self.output_fan = customtkinter.CTkTextbox(output_frame, font=(FONT_UI[0], 9), corner_radius=10, 
                                                   fg_color="#1e1e1e", height=80)
        self.output_fan.pack(fill="both", padx=10, pady=(0, 5))
    
    def _fan_load(self):
        """Load fan table from console - 10 PHASES - CORRECTED PARSING"""
        ps3 = self._get_ps3_connection()
        if not ps3: 
            return
        
        self.output_fan.insert("end", "\n=== Loading Fan Tables (10 phases) ===\n")
        self.output_fan.see("end")
        
        try:
            for cpu_id, name, entries, data_list in [(0, "CELL", self.cell_entries, self.cell_data), 
                                                     (1, "RSX", self.rsx_entries, self.rsx_data)]:
                self.output_fan.insert("end", f"\nReading {name}...\n")
                self.output_fan.see("end")
                
                # Call fantbl getini WITHOUT phase number to get all 10 phases
                ret = ps3.command(f"fantbl getini {cpu_id}", wait=0.5)
                
                if ret[0] != 0xFFFFFFFF:
                    # Parse the full output
                    output = self._format_command_output(ret, self.sc_type_combobox.get())
                    self.output_fan.insert("end", f"Raw output:\n{output}\n")
                    
                    # Parse each phase line: "P0: TempD:0.0(0x0000) - TempU:46.0(0x2e00) duty:30%(0x4d)"
                    lines = output.split('\n')
                    phase_count = 0
                    
                    for line in lines:
                        # Match pattern: P{n}: TempD:{temp} - TempU:{temp} duty:{percent}%
                        match = re.search(r'P(\d+):\s+TempD:([0-9.]+).*TempU:([0-9.]+).*duty:(\d+)%', line)
                        if match:
                            phase_num = int(match.group(1))
                            tempd = int(float(match.group(2)))  # TMin
                            tempu = int(float(match.group(3)))  # TMax
                            duty_percent = int(match.group(4))
                            
                            # Convert percent to 0-255
                            speed = int(duty_percent * 255 / 100)
                            
                            if phase_num < 10:  # Only use first 10 phases
                                data_list[phase_num] = [tempd, tempu, speed]
                                entries[phase_num][0].delete(0, 'end')
                                entries[phase_num][0].insert(0, str(tempd))
                                entries[phase_num][1].delete(0, 'end')
                                entries[phase_num][1].insert(0, str(tempu))
                                entries[phase_num][2].delete(0, 'end')
                                entries[phase_num][2].insert(0, str(speed))
                                phase_count += 1
                    
                    self.output_fan.insert("end", f"Loaded {phase_count} phases for {name}\n")
                else:
                    self.output_fan.insert("end", f"ERROR: Failed to read {name} fan table\n")
            
            self.output_fan.insert("end", "\n✓ Load complete!\n")
            self._update_graph()
            messagebox.showinfo("Success", "Fan tables loaded from console!")
            
        except Exception as e:
            error_msg = f"Error loading fan tables: {str(e)}"
            self.output_fan.insert("end", f"\nERROR: {error_msg}\n")
            messagebox.showerror("Error", error_msg)
    
    def _fan_save(self):
        """Save fan table to console - 10 PHASES"""
        ps3 = self._get_ps3_connection()
        if not ps3: 
            return
        
        if not messagebox.askyesno("Confirm", "Write new fan tables to console (10 phases)?\n\nIncorrect values can damage hardware!"):
            return
        
        self.output_fan.insert("end", "\n=== Saving Fan Tables (10 phases) ===\n")
        self.output_fan.see("end")
        
        try:
            for cpu_id, name, entries in [(0, "CELL", self.cell_entries), (1, "RSX", self.rsx_entries)]:
                self.output_fan.insert("end", f"\nWriting {name}...\n")
                self.output_fan.see("end")
                
                for i in range(10):
                    tmin = int(float(entries[i][0].get()))
                    tmax = int(float(entries[i][1].get()))
                    speed = int(entries[i][2].get())
                    cmd = f"fantbl setini {cpu_id} p{i} {tmin}.00 {tmax}.00 0x{speed:02x}"
                    self.output_fan.insert("end", f"  {cmd}\n")
                    self.output_fan.see("end")
                    ret = ps3.command(cmd, wait=0.3)
                    if ret[0] == 0xFFFFFFFF:
                        messagebox.showerror("Error", f"Failed at {name} P{i}")
                        return
                
                # Set T-Shutdown
                tshut = int(self.cell_tshut_entry.get()) if cpu_id == 0 else int(self.rsx_tshut_entry.get())
                ps3.command(f"tshutdown setini {cpu_id} {tshut}", wait=0.3)
            
            self.output_fan.insert("end", "\n✓ Save complete!\n")
            messagebox.showwarning("Fix Checksum", "IMPORTANT: Fix EEPROM checksum now!\n\nGo to Advanced Patching tab and run:\n'Checksum Correction (Auto-detect & Fix)'")
            
        except Exception as e:
            error_msg = f"Error saving fan tables: {str(e)}"
            self.output_fan.insert("end", f"\nERROR: {error_msg}\n")
            messagebox.showerror("Error", error_msg)
    
    def _fan_preset(self):
        """Load preset - 10 PHASES"""
        presets = {
            "Stock": {
                "cell": [[0, 46, 77], [46, 55, 77], [53, 61, 77], [61, 65, 89], [63, 67, 102],
                        [65, 69, 128], [67, 70, 153], [69, 72, 173], [75, 80, 255], [73, 85, 255]], 
                "rsx": [[0, 40, 77], [40, 50, 89], [50, 55, 102], [54, 58, 117], [56, 61, 128],
                       [60, 65, 153], [63, 69, 208], [68, 72, 255], [72, 75, 255], [75, 80, 255]]
            },
            "Quiet": {
                "cell": [[0, 46, 64], [46, 55, 64], [53, 61, 64], [61, 65, 77], [63, 67, 89],
                        [65, 69, 102], [67, 70, 128], [69, 72, 153], [75, 80, 230], [73, 85, 255]], 
                "rsx": [[0, 40, 64], [40, 50, 77], [50, 55, 89], [54, 58, 102], [56, 61, 115],
                       [60, 65, 140], [63, 69, 180], [68, 72, 230], [72, 75, 255], [75, 80, 255]]
            },
            "Performance": {
                "cell": [[0, 40, 89], [40, 50, 102], [50, 58, 115], [58, 62, 128], [60, 65, 153],
                        [63, 68, 180], [65, 70, 204], [68, 73, 230], [70, 78, 255], [75, 85, 255]], 
                "rsx": [[0, 38, 89], [38, 48, 102], [48, 53, 115], [52, 56, 128], [54, 59, 153],
                       [58, 63, 180], [61, 67, 208], [65, 70, 230], [68, 73, 255], [72, 78, 255]]
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
            for i in range(10):
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
            # Load stock preset
            preset = {
                "cell": [[0, 46, 77], [46, 55, 77], [53, 61, 77], [61, 65, 89], [63, 67, 102],
                        [65, 69, 128], [67, 70, 153], [69, 72, 173], [75, 80, 255], [73, 85, 255]], 
                "rsx": [[0, 40, 77], [40, 50, 89], [50, 55, 102], [54, 58, 117], [56, 61, 128],
                       [60, 65, 153], [63, 69, 208], [68, 72, 255], [72, 75, 255], [75, 80, 255]]
            }
            for i in range(10):
                for j, val in enumerate(preset["cell"][i]):
                    self.cell_entries[i][j].delete(0, 'end')
                    self.cell_entries[i][j].insert(0, str(int(val)))
                    self.cell_data[i][j] = int(val)
                for j, val in enumerate(preset["rsx"][i]):
                    self.rsx_entries[i][j].delete(0, 'end')
                    self.rsx_entries[i][j].insert(0, str(int(val)))
                    self.rsx_data[i][j] = int(val)
            self._update_graph()
            messagebox.showinfo("Reset", "Values reset to stock!")
    
    def _update_graph(self):
        """Update the fan curve graph - 10 PHASES"""
        if not self.has_graph:
            return
        
        import numpy as np
        
        self.ax.clear()
        
        # Dark background
        self.ax.set_facecolor('#1e1e1e')
        self.fig.patch.set_facecolor('#1e1e1e')
        
        # Extract TMax and Speed for plotting (convert speed 0-255 to 0-100%)
        cell_temps = [p[1] for p in self.cell_data]
        cell_speeds = [p[2] * 100 / 255 for p in self.cell_data]
        rsx_temps = [p[1] for p in self.rsx_data]
        rsx_speeds = [p[2] * 100 / 255 for p in self.rsx_data]
        
        # Plot curves with markers
        self.ax.plot(cell_temps, cell_speeds, 'o-', color='#cc0000', linewidth=2.5, markersize=8, 
                    label='CELL (CPU)', zorder=3)
        self.ax.plot(rsx_temps, rsx_speeds, 's-', color='#0066cc', linewidth=2.5, markersize=8, 
                    label='RSX (GPU)', zorder=3)
        
        # Styling
        self.ax.set_xlabel('Temperature (°C)', color='white', fontsize=11, fontweight='bold')
        self.ax.set_ylabel('Fan Speed (%)', color='white', fontsize=11, fontweight='bold')
        self.ax.set_title('PS3 Fan Curve - 10 Phases', color='white', fontsize=12, fontweight='bold')
        self.ax.set_xlim(0, 100)
        self.ax.set_ylim(0, 110)
        
        # Grid
        self.ax.grid(True, alpha=0.3, color='#555555', linestyle='-', linewidth=0.8)
        
        # Tick styling
        self.ax.tick_params(axis='both', colors='white', labelsize=9)
        for spine in self.ax.spines.values():
            spine.set_color('white')
        
        # Legend
        self.ax.legend(loc='upper left', facecolor='#2b2b2b', edgecolor='white', 
                      fontsize=9, labelcolor='white')
        
        self.fig.tight_layout()
        
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
    root.geometry("1000x900")
    app = PS3SysconGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
