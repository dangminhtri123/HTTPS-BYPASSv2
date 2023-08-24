import subprocess
import time
from termcolor import colored

def main():
    command = "node c.js https://taxisontay24h.com 60 64 8 PROXYVIP.txt"
    request_interval = 70
    vietnam_timezone_offset = 7 * 3600

    while True:
        current_time_utc = time.time()
        current_time_vietnam = current_time_utc + vietnam_timezone_offset
        formatted_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(current_time_vietnam))
        
        print(colored(f"| {formatted_time} | {command} |", "green"))
        subprocess.run(["bash", "-c", command], shell=False)
        time.sleep(request_interval)

if __name__ == "__main__":
    main()
