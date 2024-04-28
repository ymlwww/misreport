####
#crawler:script to get pcap file from MAWI website
import requests
import os
from bs4 import BeautifulSoup
url="https://mawi.wide.ad.jp/mawi/ditl/ditl2018/"
strhtml = requests.get(url)
soup = BeautifulSoup(strhtml.text,'lxml')
anchordata = soup.select("a")
linklist = []
for anchor in anchordata:
	linklist.append(url+anchor['href'][:-4]+"pcap.gz")
for item in linklist:
        os.system("wget "+item)
