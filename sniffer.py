import time
from scapy.all import sniff, IP, TCP, IPv6
import re
import os

# Define the path to the folder where you want to save the plot images
output_folder = "c:/Users/97258/OneDrive - Ariel University/year 2/semester b/Communication networks/פרוייקט סיום"

# Define global variables to store message information
message_groups = {}  # Dictionary to hold groups of messages
message_counter = 0  # Counter to keep track of messages

# Function to check if packets belong to the same group
def are_packets_in_same_group_first(packet1, packet2):
    # Define threshold values for time and size similarity (you can adjust these as needed)
    time_threshold = 0.2 # seconds
    size_threshold = 16  # bytes

    # Check if packets have the same size and close transmission times
    return (
        abs(packet1[2] - packet2[2]) <= time_threshold
        and abs(len(packet1) - len(packet2)) <= size_threshold
        
    )


# Function to process captured packets
def process_packet(packet):
    global message_counter, message_groups

    if IPv6 in packet:
        # IPv6 packet processing
        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst
        # Replace the target_ipv6 with the IPv6 address you want to filter on
        target_ipv6 = "2a03:2880:f242:c8:face:b00c:0:167"

        group_identifier = f"{src_ip}_{dst_ip}"
        timestamp = time.time()
        size = len(packet)
    else:
        # IPv4 packet processing
        if packet.haslayer(TCP) and packet.haslayer(IP):
            # Extract the source IP, destination IP, timestamp, and size
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            timestamp = time.time()
            size = len(packet)

    # Create a unique identifier for the message group
    group_identifier = f"{src_ip}--{dst_ip}"

    # Check if this is a new group or an existing one
    if group_identifier not in message_groups:
        message_groups[group_identifier] = []

    # Check if the current packet belongs to the same group as the previous one
    if (
        len(message_groups[group_identifier]) > 0
        and are_packets_in_same_group_first
        (
            message_groups[group_identifier][-1], (message_counter, size, timestamp)
        )
    ):
        # Add the current packet to the same group
        message_groups[group_identifier][-1][0] += 1
    else:
        # Create a new group for the current packet
        message_groups[group_identifier].append([1, size, timestamp])

    # Increment the message counter
    message_counter += 1

# Start sniffing
try:
    # Sniff the network for a limited number of packets (modify count as needed)
    sniff(filter="tcp port 443 or tcp port 80", prn=process_packet, timeout=20)

    # Open the file in append mode
    with open("c:/Users/97258/OneDrive - Ariel University/year 2/semester b/Communication networks/פרוייקט סיום/output-massages1.txt", "a") as file:
        # Process and plot the data for each message group
        for group_identifier, messages in message_groups.items():
            if group_identifier == "2a02:6680:2105:aa78:5d79:df94:5095:14ea--2a03:2880:f242:1c2:face:b00c:0:167" or group_identifier=="2a03:2880:f242:1c2:face:b00c:0:167--2a02:6680:2105:aa78:5d79:df94:5095:14ea":
            
                # Remove colons from group identifier to create a valid filename
                sanitized_group_identifier = re.sub(r'[:]', '_', group_identifier)

                # Extract information for plotting
                message_ids = [msg[0] for msg in messages]
                message_sizes = [msg[1] for msg in messages]
                timestamps = [msg[2] for msg in messages]

                # Append data to the file
                file.write(f"Group Identifier: {group_identifier}\n")
                for msg_id, msg_size, timestamp in zip(message_ids, message_sizes, timestamps):
                    file.write(f"Message ID: {msg_id}, Size: {msg_size} bytes, Timestamp: {timestamp}\n")

                # Now you can use any plotting library (e.g., matplotlib) to visualize the data
                # Here's a basic example using matplotlib:
                import matplotlib.pyplot as plt
                        
                # Plot inter-message delays as a column chart
                plt.figure(figsize=(10, 5))
                plt.bar(timestamps, message_sizes, width=0.1, align='center', color='blue', edgecolor='black')
                plt.xlabel("Timestamp")
                plt.ylabel("Message Size (bytes)")
                plt.title(f"Message Sizes over Time for Group: {group_identifier}")
                plt.grid(axis='y', linestyle='--', alpha=0.7)
                plt.xticks(rotation=45)  # Rotate x-axis labels for better readability
                plot_filename = os.path.join(output_folder, f"{sanitized_group_identifier}_Channel1.png")
                plt.savefig(plot_filename)
                plt.show()


except KeyboardInterrupt:
    print("Sniffing stopped.")
