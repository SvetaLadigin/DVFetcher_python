# DVFetcher_python
Simple fetcher for python package's dependencies and their CVE'S for as registered in pypi.org <br />
for locally installed packeges use -local <br />
for recursive search use -r <br />
for package use -p <br />
for version use -v <br />
for a list of packages use -l <br /><br />
examples: <br />
[+] for locally installed packages: python DVFetcher.py -local <br />
[+] recursive search on a list : python DVFetcher -r -l="pandas 0.22.0,numpy" <br />
[+] information about 1 package: python DVFetcher -p="pandas" -v="0.22.0" <br />
<br /><br />
Output: results.csv <br />
col 1: name <br />
col 2: version <br />
col 3: dependencies <br />
col 4: CVE'S <br />
col 5: error, if there was an error fetching the information from pypi the field value equals to 1 otherwise, 0 <br />
