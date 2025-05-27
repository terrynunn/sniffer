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

## Setup and Usage

### 1. Prerequisites
- **Python 3:** Ensure you have Python 3 installed.
- **Tkinter:** This project relies on Tkinter for its user interface.
    - On many systems (like Windows and macOS with standard Python installs), Tkinter is included by default.
    - On some Linux distributions (especially minimal installs or WSL), you might need to install it manually. For Debian/Ubuntu-based systems, use:
      ```bash
      sudo apt-get update
      sudo apt-get install python3-tk
      ```
    - You can check if Tkinter is available by trying to import it in Python: `python3 -m tkinter`

### 2. Setting up a Virtual Environment (Recommended)
It's good practice to run Python projects in a virtual environment.
1.  **Create a virtual environment:**
    Open your terminal, navigate to the project directory, and run:
    ```bash
    python3 -m venv venv
    ```
    This will create a `venv` folder in your project directory.
2.  **Activate the virtual environment:**
    - On macOS and Linux:
      ```bash
      source venv/bin/activate
      ```
    - On Windows (Git Bash or similar):
      ```bash
      source venv/Scripts/activate
      ```
    - On Windows (Command Prompt):
      ```bash
      .\venv\Scripts\activate.bat
      ```
    Your terminal prompt should change to indicate that the virtual environment is active.

### 3. Installing Dependencies
- This project primarily uses built-in Python libraries.
- The `requirements.txt` file is included as a placeholder and to note system-level dependencies like Tkinter. If other pip-installable packages were required in the future, you would install them using:
  ```bash
  pip install -r requirements.txt
  ```
  For now, ensuring `python3-tk` (or your system's equivalent) is installed is the main step.

### 4. Running the Sniffer
1.  **Navigate to Directory:** Ensure your terminal is in the project directory where `sniffer.py` is located.
2.  **Execute the script:** You will need administrator/root privileges:
    ```bash
    sudo python3 sniffer.py
    ```
    If you are using a virtual environment, make sure it's activated, then run the `sudo` command. `sudo` will use the system's Python by default, so ensure the system Python also has access to `tkinter` if `sudo` doesn't inherit the virtual environment's context perfectly for GUI applications. Alternatively, configure `sudo` to preserve the environment if possible, or run as root directly if appropriate for your security context. For development, running your terminal session as root initially (if permissible) can simplify this.

## Permissions
- **Administrator/Root Privileges Required:** This tool requires administrator or root privileges.
- **Reason:** Packet sniffing needs access to raw sockets, a privileged operation.
- **If Not Run with Privileges:** An error message (e.g., "Permission denied") will appear in the UI.

## User Interface
- **Packet Display Area:** Shows details of captured packets.
- **Start Button:** Begins packet capture.
- **Stop Button:** Halts packet capture.
