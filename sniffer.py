import socket
import tkinter as tk
from tkinter import scrolledtext
from nettypes import EthernetFrame
import threading
import queue # Import the queue module

# Global event to signal the sniffing thread to stop
stop_sniffing_event = threading.Event()
sniffer_thread = None # To keep track of the sniffing thread
packet_queue = queue.Queue() # Global queue for packet data

# Function to update the text area from any thread (for status messages)
def update_text_area(message):
    text_area.config(state='normal')
    text_area.insert(tk.END, message)
    text_area.see(tk.END) # Scroll to the end
    text_area.config(state='disabled')

# Modified main function for packet sniffing
def packet_sniffer_worker(ui_text_area, stop_event, data_queue): # Added data_queue parameter
    conn = None
    error_occurred_in_worker = False
    try:
        # This requires root privileges
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        # Status update remains direct UI update
        root.after_idle(update_text_area, "Sniffing started...\n")
        while not stop_event.is_set():
            try:
                raw_data, addr = conn.recvfrom(65536) # Increased buffer size slightly
                ethernet_frame = EthernetFrame(raw_data)
                frame_info = str(ethernet_frame)
                # Put packet data string into the queue
                data_queue.put(frame_info + "\n\n")
            except Exception as loop_e: # Catch errors within the loop
                error_msg = f"Error during packet processing: {loop_e}\n"
                # Put error message related to packet processing into the queue
                data_queue.put(error_msg)
                # For now, it continues trying to read next packet.
    except PermissionError:
        error_msg = "Permission Denied: Root privileges are required to create raw sockets.\nPlease run the script as root (e.g., using sudo).\n"
        # Critical error, update UI directly
        root.after_idle(update_text_area, error_msg)
        error_occurred_in_worker = True
    except Exception as e:
        # Catch other potential errors during sniffing setup or critical failures
        error_msg = f"An unexpected error occurred: {e}\n"
        # Critical error, update UI directly
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
        
        # Final status update remains direct UI update
        root.after_idle(update_text_area, stop_message)
        # Ensure buttons are reset correctly even if sniffing stops due to error
        root.after_idle(reset_button_states_after_stop)

def start_sniffing():
    global sniffer_thread
    if sniffer_thread and sniffer_thread.is_alive():
        return

    stop_sniffing_event.clear()
    start_button.config(state='disabled')
    stop_button.config(state='normal')
    
    text_area.config(state='normal')
    text_area.delete('1.0', tk.END)
    text_area.config(state='disabled')

    # Pass the global packet_queue to the worker thread
    sniffer_thread = threading.Thread(target=packet_sniffer_worker, args=(text_area, stop_sniffing_event, packet_queue))
    sniffer_thread.daemon = True 
    sniffer_thread.start()
    # Start the queue processing loop
    process_packet_queue()

def stop_sniffing():
    stop_sniffing_event.set()
    
    # Clear any remaining items from the packet_queue
    # This prevents old packets from appearing if sniffing is restarted
    while not packet_queue.empty():
        try:
            packet_queue.get_nowait()
        except queue.Empty:
            # This should ideally not be reached if .empty() is reliable,
            # but good for robustness.
            break
        except Exception: 
            # Catch any other unexpected error during queue clearing
            # Optionally log this, but for now, just break to avoid an infinite loop.
            break
    
    # Button states will be updated by the worker thread's finally block 
    # or reset_button_states_after_stop which is called from the worker's finally.
    # The process_packet_queue will also stop rescheduling itself because stop_sniffing_event is set.

def reset_button_states_after_stop():
    start_button.config(state='normal')
    stop_button.config(state='disabled')

# Function to process messages from the packet_queue and update UI
def process_packet_queue():
    try:
        while True: # Process all messages currently in the queue
            message = packet_queue.get_nowait()
            update_text_area(message) # update_text_area handles enabling/disabling text_area
    except queue.Empty:
        pass # Queue is empty, no more messages for now

    # If sniffing is still active, schedule this function to run again
    if not stop_sniffing_event.is_set():
        root.after(100, process_packet_queue) # Check queue every 100ms

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
