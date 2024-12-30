import sys
import subprocess
import importlib.util
import time
from collections import defaultdict
import os
import threading

# Function to install missing packages
def install_packages(packages):
    for package in packages:
        if importlib.util.find_spec(package) is None:
            print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Installing missing package: {package}")
            try:
                subprocess.check_call(
                    [sys.executable, "-m", "pip", "install", package],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            except subprocess.CalledProcessError as e:
                print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Failed to install {package}: {e}")
                sys.exit(1)

# List of required packages
required_packages = ['psutil', 'pyshark', 'colorama']
install_packages(required_packages)

import psutil
import pyshark
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Configuration
MONITOR_INTERVAL = 1  # seconds for each monitoring interval
DATA_RATE_THRESHOLD = 100  # bytes per second to consider as significant traffic

# Define list of known game-related process names
GAME_PROCESS_NAMES = [
    'cod.exe',  # Call of Duty
    'FortniteClient-Win64-Shipping.exe',  # Fortnite
    'VALORANT.exe',  # Valorant
    'RainbowSix.exe',  # Rainbow Six Siege
    # Add more game-related process names as needed
]

# Colored print functions
def print_success(message):
    print(f"{Fore.GREEN}{message}{Style.RESET_ALL}")

def print_info(message):
    print(f"{Fore.CYAN}{message}{Style.RESET_ALL}")

def print_warning(message):
    print(f"{Fore.YELLOW}{message}{Style.RESET_ALL}")

def print_error(message):
    print(f"{Fore.RED}{message}{Style.RESET_ALL}")

def clear_console():
    """Clear the console based on the operating system."""
    os.system('cls' if os.name == 'nt' else 'clear')

def get_top_cpu_processes(n=5):
    """Retrieve top n .exe processes by CPU usage using multi-threading."""
    processes = []
    exe_procs = []

    # Collect all .exe processes
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            name = proc.info['name']
            if name and name.lower().endswith('.exe'):
                exe_procs.append(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # Function to initialize CPU percent for a process
    def init_cpu(proc):
        try:
            proc.cpu_percent(interval=None)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    # Initialize CPU percent using threads
    threads = []
    for proc in exe_procs:
        thread = threading.Thread(target=init_cpu, args=(proc,))
        thread.start()
        threads.append(thread)

    # Wait for all threads to finish initialization
    for thread in threads:
        thread.join()

    # Sleep to allow CPU percent calculation
    time.sleep(MONITOR_INTERVAL)

    # Collect CPU usage
    cpu_usages = []
    for proc in exe_procs:
        try:
            cpu = proc.cpu_percent(interval=None)
            if cpu is None:
                cpu = 0.0
            cpu_usages.append((proc.info['name'], cpu))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # Get number of CPU cores
    num_cores = psutil.cpu_count()

    # Normalize CPU usage based on number of cores
    cpu_usages = [(name, cpu / num_cores) for name, cpu in cpu_usages]

    # Sort by CPU usage descending and get top n
    processes = sorted(cpu_usages, key=lambda x: x[1], reverse=True)[:n]
    return processes

def list_top_processes():
    """List top CPU consuming .exe processes."""
    top_cpu = get_top_cpu_processes(5)
    
    if not top_cpu:
        print_warning("No CPU data available.")
        return []
    
    print_success("\n░▒▓█ C͎h͎o͎o͎s͎e͎ ͎Y͎o͎u͎r͎ ͎C͎u͎r͎r͎e͎n͎t͎ ͎G͎a͎m͎e͎ █▓▒░")
    print("")
    print(f"{'No.':<5}{'Process Name':<40}{'CPU Usage (%)':>15}")
    print("-" * 60)
    for idx, (name, cpu) in enumerate(top_cpu, 1):
        print(f"{idx:<5}{name:<40}{cpu:>15.1f}")
    
    return top_cpu

def get_user_selection(max_number):
    """Prompt the user to select a process by entering a number."""
    while True:
        try:
            selection = int(input(f"\nSelect a process to monitor (1-{max_number}): ").strip())
            if 1 <= selection <= max_number:
                return selection
            else:
                print_warning(f"Please enter a number between 1 and {max_number}.")
        except ValueError:
            print_warning("Invalid input. Please enter a numeric value.")

def auto_select_game_process():
    """Automatically select a game-related process if any are running."""
    game_procs = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            name = proc.info['name']
            if name and name.lower() in [game.lower() for game in GAME_PROCESS_NAMES]:
                game_procs.append(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return game_procs

def auto_select_network_interface():
    """Auto-select the network interface with the highest total traffic."""
    interfaces = psutil.net_io_counters(pernic=True)
    if not interfaces:
        print_error("No network interfaces found.")
        sys.exit(1)
    interface_traffic = {}
    for iface, counters in interfaces.items():
        total = counters.bytes_sent + counters.bytes_recv
        interface_traffic[iface] = total
    # Select interface with highest traffic
    selected_interface = max(interface_traffic, key=interface_traffic.get)
    return selected_interface

def get_process_pids(process_name):
    """Get all PIDs for the given process name."""
    pids = []
    for proc in psutil.process_iter(['name']):
        try:
            if proc.info['name'] and proc.info['name'].lower() == process_name.lower():
                pids.append(proc.pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return pids

def get_udp_ports(pid):
    """Get all local UDP ports for the given PID."""
    ports = set()
    try:
        proc = psutil.Process(pid)
        for conn in proc.net_connections(kind='udp'):
            if conn.laddr:
                ports.add(conn.laddr.port)
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        print_warning(f"Cannot access UDP ports for PID {pid}: {e}")
    return ports

def monitor_udp_traffic(pid_ports, interface_name, duration):
    """Monitor UDP traffic and calculate data rates per remote connection."""
    capture_filter = "udp"
    try:
        capture = pyshark.LiveCapture(interface=interface_name, bpf_filter=capture_filter, only_summaries=False)
    except pyshark.capture.capture.TSharkCrashException:
        print_error("Failed to start packet capture. Ensure TShark is installed and accessible.")
        sys.exit(1)
    except pyshark.capture.capture.UnknownInterfaceException:
        print_error(f"Interface '{interface_name}' does not exist.")
        sys.exit(1)
    except Exception as e:
        print_error(f"Error starting packet capture: {e}")
        sys.exit(1)

    traffic_data = defaultdict(int)
    start_time = time.time()

    try:
        for packet in capture.sniff_continuously():
            try:
                if 'UDP' in packet:
                    src_port = int(packet.udp.srcport)
                    dst_port = int(packet.udp.dstport)

                    # Check if either src_port or dst_port is in pid_ports
                    if src_port in pid_ports:
                        remote_ip = packet.ip.dst
                        remote_port = dst_port
                        traffic_data[(remote_ip, remote_port)] += len(packet)
                    elif dst_port in pid_ports:
                        remote_ip = packet.ip.src
                        remote_port = src_port
                        traffic_data[(remote_ip, remote_port)] += len(packet)
            except AttributeError:
                continue  # Ignore non-IP packets or missing attributes
            except Exception as e:
                print_warning(f"Packet processing error: {e}")
                continue

            if time.time() - start_time > duration:
                break
    except KeyboardInterrupt:
        # Immediate termination upon Ctrl+C
        print("\n[WARNING] Script terminated by user.")
        sys.exit(0)
    except Exception as e:
        print_error(f"Unexpected error during packet capture: {e}")
        sys.exit(1)
    finally:
        capture.close()

    return traffic_data

def main():
    # Clear the console at the start
    clear_console()

    # Attempt to auto-select game-related processes
    game_processes = auto_select_game_process()

    if game_processes:
        # If game-related processes are found, proceed without user selection
        selected_process = game_processes[0]  # Select the first found game process
        process_name = selected_process.info['name']
        cpu_usage = selected_process.cpu_percent(interval=None) / psutil.cpu_count()
        
        # Initialize CPU percent for the selected process
        try:
            selected_process.cpu_percent(interval=None)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            print_error(f"Cannot access CPU usage for '{process_name}'.")
            sys.exit(1)
        
        # Sleep to allow CPU percent calculation
        time.sleep(MONITOR_INTERVAL)
        
        # Get updated CPU usage
        try:
            cpu_usage = selected_process.cpu_percent(interval=None) / psutil.cpu_count()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            cpu_usage = 0.0

        # Clear the console after selection to ensure clean output
        clear_console()

        print_success(f"Capturing '{process_name}'...")
        print_info("Monitoring... Press Ctrl+C to terminate.\n")

        # Get PIDs of the selected process
        pids = get_process_pids(process_name)
        if not pids:
            print_error(f"No running process found with name '{process_name}'. Ensure the application is running.")
            input("Press Enter to exit...")
            sys.exit(1)

        # Aggregate all UDP ports from all PIDs
        all_ports = set()
        for pid in pids:
            ports = get_udp_ports(pid)
            all_ports.update(ports)

        if not all_ports:
            print_warning(f"No UDP ports found for '{process_name}'. Ensure the application is actively communicating.")
            input("Press Enter to exit...")
            sys.exit(1)

        # Auto-select network interface
        selected_interface = auto_select_network_interface()

    else:
        # If no game-related processes are found, proceed with manual selection
        # List top CPU consuming .exe processes
        processes = list_top_processes()
        if not processes:
            print_error("No .exe processes found. Exiting.")
            input("Press Enter to exit...")
            sys.exit(1)

        # Allow user to select a process
        selection = get_user_selection(len(processes))
        selected_process = processes[selection - 1]
        process_name, cpu_usage = selected_process

        # Clear the console after selection to ensure clean output
        clear_console()

        print_success(f"Capturing '{process_name}'...")
        print_info("Monitoring... Press Ctrl+C to terminate.\n")

        # Get PIDs of the selected process
        pids = get_process_pids(process_name)
        if not pids:
            print_error(f"No running process found with name '{process_name}'. Ensure the application is running.")
            input("Press Enter to exit...")
            sys.exit(1)

        # Aggregate all UDP ports from all PIDs
        all_ports = set()
        for pid in pids:
            ports = get_udp_ports(pid)
            all_ports.update(ports)

        if not all_ports:
            print_warning(f"No UDP ports found for '{process_name}'. Ensure the application is actively communicating.")
            input("Press Enter to exit...")
            sys.exit(1)

        # Auto-select network interface
        selected_interface = auto_select_network_interface()

    # Initialize a set to keep track of already identified connections
    identified_connections = set()

    try:
        while True:
            # Monitor UDP traffic for the specified interval
            traffic_data = monitor_udp_traffic(all_ports, selected_interface, MONITOR_INTERVAL)

            # Calculate data rates for each connection
            significant_connections = {}
            for conn, byte_count in traffic_data.items():
                data_rate = byte_count / MONITOR_INTERVAL  # bytes per second
                if data_rate >= DATA_RATE_THRESHOLD:
                    significant_connections[conn] = data_rate

            # Iterate over significant connections and report new ones
            for (ip, port), rate in significant_connections.items():
                if (ip, port) not in identified_connections:
                    if port == 44998:
                        # Highlight specific port in red with special message
                        print(f"{Fore.RED}=== Moving Server Detected! ==={Style.RESET_ALL}")
                        print(f"{Fore.RED}{'IP Address':<15}: {ip}{Style.RESET_ALL}")
                        print(f"{Fore.RED}{'Port':<15}: {port}{Style.RESET_ALL}\n")
                        print(f"{Fore.RED}========================{Style.RESET_ALL}")
                        print(f"{Fore.RED}IP:PORT Format{Style.RESET_ALL}")
                        print(f"{Fore.RED}{ip}:{port}{Style.RESET_ALL}")
                        print(f"{Fore.RED}========================{Style.RESET_ALL}")
                        print(f"{Fore.RED}{'Data Rate (B/s)':<15}: {rate:.2f}{Style.RESET_ALL}")
                        print(f"{Fore.RED}=======================\n{Style.RESET_ALL}")
                    else:
                        # Regular server detection
                        print_success("=== Active Game Server Identified ===")
                        print(f"{'IP Address':<15}: {ip}")
                        print(f"{'Port':<15}: {port}\n")
                        print("=====================================")
                        print("IP:PORT Format")
                        print(f"{ip}:{port}")
                        print("=====================================")
                        print(f"{'Data Rate (B/s)':<15}: {rate:.2f}")
                        print("=====================================\n")
                    # Add to the set of identified connections
                    identified_connections.add((ip, port))
    except KeyboardInterrupt:
        # Graceful termination upon user interrupt
        print("\n[WARNING] Monitoring terminated by user.")
        sys.exit(0)
    except Exception as e:
        print_error(f"An unexpected error occurred: {e}")
        input("Press Enter to exit...")
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        # Ensures immediate termination upon Ctrl+C
        print("\n[WARNING] Script terminated by user.")
        sys.exit(0)
    except Exception as e:
        print_error(f"An unexpected error occurred: {e}")
        input("Press Enter to exit...")
        sys.exit(1)
