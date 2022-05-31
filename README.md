# DVFetcher_python
Simple fetcher for python package's dependencies and their CVE'S for as registered in pypi.org
for recursive search use -r 
for package use -p 
for version use -v
for a list of packages use -l 
examples: 
[+] recursive search on a list : python DVFetcher -r -l="pandas 0.22.0,numpy" 
[+] information about 1 package: python DVFetcher -p="pandas" -v="0.22.0"
