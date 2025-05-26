import socket
import tkinter as tk
from tkinter import scrolledtext
from nettypes import EthernetFrame
import threading

# Global event to signal the sniffing thread to stop
stop_sniffing_event = threading.Event()
sniffer_thread = None # To keep track of the sniffing thread

# Function to update the text area from any thread
def update_text_area(message):
    text_area.config(state='normal')
    text_area.insert(tk.END, message)
    text_area.see(tk.END) # Scroll to the end
    text_area.config(state='disabled')

# Modified main function for packet sniffing
def packet_sniffer_worker(ui_text_area, stop_event):
    conn = None
    error_occurred_in_worker = False
    try:
        # This requires root privileges
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        root.after_idle(update_text_area, "Sniffing started...\n")
        while not stop_event.is_set():
            try:
                raw_data, addr = conn.recvfrom(65536) # Increased buffer size slightly
                ethernet_frame = EthernetFrame(raw_data)
                frame_info = str(ethernet_frame)
                # Schedule UI update on the main thread
                root.after_idle(update_text_area, frame_info + "\n\n")
            except Exception as loop_e: # Catch errors within the loop
                error_msg = f"Error during packet processing: {loop_e}\n"
                root.after_idle(update_text_area, error_msg)
                # Optionally, decide if the loop should continue or break on certain errors
                # For now, it continues trying to read next packet.
    except PermissionError:
        error_msg = "Permission Denied: Root privileges are required to create raw sockets.\nPlease run the script as root (e.g., using sudo).\n"
        root.after_idle(update_text_area, error_msg)
        error_occurred_in_worker = True
    except Exception as e:
        # Catch other potential errors during sniffing setup or critical failures
        error_msg = f"An unexpected error occurred: {e}\n"
        root.after_idle(update_text_area, error_msg)
        error_occurred_in_worker = True
    finally:
        if conn:
            conn.close()
        
        stop_message = "Sniffing stopped.\n"
        if error_occurred_in_worker:
            stop_message = "Sniffing stopped due to an error.\n"
        elif not stop_event.is_set():
             # If loop exited without stop_event being set and no error, it's unexpected.
             stop_message = "Sniffing stopped unexpectedly.\n"

        root.after_idle(update_text_area, stop_message)
        # Ensure buttons are reset correctly even if sniffing stops due to error
        root.after_idle(reset_button_states_after_stop)

def start_sniffing():
    global sniffer_thread
    if sniffer_thread and sniffer_thread.is_alive():
        # Prevent starting multiple threads if one is already running (shouldn't happen with button states)
        return

    stop_sniffing_event.clear()
    start_button.config(state='disabled')
    stop_button.config(state='normal')
    
    # Clear previous content in text_area before starting new sniffing
    text_area.config(state='normal')
    text_area.delete('1.0', tk.END)
    text_area.config(state='disabled')

    sniffer_thread = threading.Thread(target=packet_sniffer_worker, args=(text_area, stop_sniffing_event))
    sniffer_thread.daemon = True # Allows main program to exit even if thread is running
    sniffer_thread.start()

def stop_sniffing():
    stop_sniffing_event.set()
    # Button states will be updated by the worker thread's finally block or reset_button_states_after_stop

def reset_button_states_after_stop():
    start_button.config(state='normal')
    stop_button.config(state='disabled')

# Create the main window
root = tk.Tk()
root.title("Packet Sniffer")

# Add a Text widget
text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, state='disabled')
text_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

# Add Start and Stop buttons
start_button = tk.Button(root, text="Start", command=start_sniffing)
start_button.pack(side=tk.LEFT, padx=(10, 5), pady=(0, 10))

stop_button = tk.Button(root, text="Stop", command=stop_sniffing, state='disabled')
stop_button.pack(side=tk.LEFT, padx=(5, 10), pady=(0, 10))

if __name__ == '__main__':
    root.mainloop()
