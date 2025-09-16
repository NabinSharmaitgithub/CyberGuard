import requests
import threading
from tqdm import tqdm

def map_site(target_url, wordlist, extensions, timeout=5, threads=10):
    found_urls = []
    
    if not target_url.endswith('/'):
        target_url += '/'

    def check_url(url):
        try:
            response = requests.get(url, timeout=timeout)
            if response.status_code != 404:
                found_urls.append(url)
        except requests.RequestException:
            pass

    urls_to_check = []
    for word in wordlist:
        for ext in extensions:
            urls_to_check.append(f"{target_url}{word}{ext}")

    with tqdm(total=len(urls_to_check), desc="Mapping site") as pbar:
        for i in range(0, len(urls_to_check), threads):
            batch = urls_to_check[i:i+threads]
            thread_list = []
            for url in batch:
                thread = threading.Thread(target=check_url, args=(url,))
                thread_list.append(thread)
                thread.start()
            
            for thread in thread_list:
                thread.join()
            
            pbar.update(len(batch))

    return found_urls
