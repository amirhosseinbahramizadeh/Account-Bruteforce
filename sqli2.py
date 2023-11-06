from googlesearch import search
import requests
import re

def check_sqli_vulnerability(url):
    vulnerable_patterns = ['id=', 'page=', 'username=', 'password=', 'search=', 'action=', 'location=', 'comment=', 'tags=']
    for pattern in vulnerable_patterns:
        if pattern in url:
            return True
    return False

def get_urls(dorks, num_results=10):
    urls = []
    for dork in dorks:
        try:
            for j in search(dork, num_results=num_results):
                urls.append(j)
        except Exception as e:
            print(e)
    return urls

def read_dorks_from_file(file_name):
    with open(file_name, 'r') as f:
        dorks = f.readlines()
    return [dork.strip() for dork in dorks]

def write_urls_to_file(urls, file_name):
    with open(file_name, 'w') as f:
        for url in urls:
            f.write("%s\n" % url)

if __name__ == "__main__":
    dorks = read_dorks_from_file('dorks.txt')
    urls = get_urls(dorks)
    vulnerable_urls = []
    for url in urls:
        if check_sqli_vulnerability(url):
            vulnerable_urls.append(url)
    write_urls_to_file(vulnerable_urls, 'vulnerable_urls.txt')
