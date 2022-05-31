import requests
import json


def get_package_req(package_name, *version):

    # https://pypi.org/pypi/pandas/0.22.0/json
    base_url = "https://pypi.org/pypi/"
    version_toreturn = None
    print(version)
    if version[0]:
        version_toreturn = version[0]
        package_desc = (package_name,version_toreturn,"json")
    else:
        package_desc = (package_name, "json")
    print(package_desc)
    url_pack = "/".join(package_desc)
    url = base_url+url_pack
    package_req = requests.get(url)
    #print(package_req.text)
    json_pack = json.loads(package_req.text)
    print(json_pack)
    print("---------package name-----------")
    print(package_name)
    if version:
        print(version_toreturn)
    print("---------dependencies-----------")
    dependencies = json_pack['info']['requires_dist']
    print(dependencies)
    print("---------vulnerabilities-----------")
    vulnerabilities = json_pack['vulnerabilities']
    print(vulnerabilities)

    return {"name": package_name,"version":version_toreturn,"dependencies":dependencies, "vulnerabilities": vulnerabilities}

def send_req_parssed(pack_string):
    tmp_pac = pack_string.split(" ")
    package_name = tmp_pac[0]
    if len(tmp_pac)>1:
        version = tmp_pac[1]
        return get_package_req(str(package_name), str(version))
    else:
        return get_package_req(package_name)


def get_info_for_list_of_packages(packages):
    return_data = {}
    if packages:
        if type(packages) == type("x"):
            return_data[packages] = send_req_parssed(packages)
            return return_data

        for package in packages:
            return_data[package] = send_req_parssed(package)

    return return_data
