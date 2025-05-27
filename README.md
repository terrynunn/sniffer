# Simple Packet Sniffer

This tool is a basic packet sniffer with a simple graphical user interface built using Python and Tkinter. It allows you to capture and view Ethernet frame information from your network interface.

## Features
- Captures live network packets.
- Displays Ethernet frame details:
    - Source MAC Address
    - Destination MAC Address
    - EtherType (Protocol)
- Simple UI with "Start" and "Stop" buttons to control capture.
- Basic error reporting in the UI.

## Usage
1. **Prerequisites:** Ensure you have Python 3 installed. Tkinter is usually included with standard Python installations.
2. **Open Terminal:** Open your terminal or command prompt.
3. **Navigate to Directory:** Change to the directory where `sniffer.py` and other project files are located.
4. **Run the Sniffer:** Execute the script using Python 3. You will likely need administrator/root privileges:
   ```bash
   sudo python3 sniffer.py
   ```
   On Windows, you might need to run your terminal as Administrator and then execute `python sniffer.py`.

## Permissions
- **Administrator/Root Privileges Required:** This tool requires administrator or root privileges to run.
- **Reason:** Packet sniffing involves capturing all network traffic that reaches your network interface. This requires access to raw sockets, which is a privileged operation restricted to administrators for security reasons.
- **If Not Run with Privileges:** If you attempt to run the sniffer without the necessary permissions, it will likely fail to open the raw socket, and an error message (e.g., "Permission denied") will be displayed in the UI's text area.

## User Interface
- **Packet Display Area:** A text area where details of captured packets are shown.
- **Start Button:** Click this button to begin capturing packets.
- **Stop Button:** Click this button to stop the ongoing packet capture.
