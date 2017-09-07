import multiprocessing
import time
import subprocess
from dns_test_url_list import list_of_urls
# import os


port = "10053"
address = "@127.0.0.1"


def command(url):
    process = subprocess.Popen(["dig", "+tcp", address, "-p", port, url, "+short"],
                               stdout=subprocess.PIPE,
                               shell=True)
    (output, error) = process.communicate()
    print("output for " + str(url) + " : " + str(output))

if __name__ == '__main__':
    for x in range(1, 10):
        pool = multiprocessing.Pool(6)
        pool.map(command, list_of_urls)
        time.sleep(1)
