import get_requirements
import sys
import argparse



def parse_packages_from_pypi(list_of_packages):
    new_list = []
    chars_to_remove = ">=()<,"
    if list_of_packages:
        for package in list_of_packages:
            p = package
            for char in chars_to_remove:
                p = p.replace(char,"")
            p_needed_arg = p.split(";")
            p_needed = p_needed_arg[0]
            new_list.append(p_needed)
    return new_list


def parse_recursivly_on_one_package(package_name, *version):
    if version:
        json_data = get_requirements.get_package_req(package_name,version[0])
    else:
        json_data = get_requirements.get_package_req(package_name)
    list_of_packages = json_data["dependencies"]
    parrsed_list_of_packages = parse_packages_from_pypi(list_of_packages)
    info_list = get_requirements.get_info_for_list_of_packages(parrsed_list_of_packages)
    print(info_list)
    return info_list


if __name__ == '__main__':
    # get_requirements.get_package_req("pandas")
    # list_of_package = ['python-dateutil (>=2.8.1)', 'pytz (>=2020.1)', 'numpy (>=1.18.5) ; platform_machine != "aarch64" and platform_machine != "arm64" and python_version < "3.10"', 'numpy (>=1.19.2) ; platform_machine == "aarch64" and python_version < "3.10"', 'numpy (>=1.20.0) ; platform_machine == "arm64" and python_version < "3.10"', 'numpy (>=1.21.0) ; python_version >= "3.10"', "hypothesis (>=5.5.3) ; extra == 'test'", "pytest (>=6.0) ; extra == 'test'", "pytest-xdist (>=1.31) ; extra == 'test'"]
    # new_list_list_of_package = parse_packages_from_pypi(list_of_package)
    # info_list = get_requirements.get_info_for_list_of_packages(new_list_list_of_package)
    # print(info_list)
    parser = argparse.ArgumentParser(description="Simple fetcher for python package's dependencies and their CVE'S for as registered in pypi.org\n"
              "for recursive search use -r\n"
              "for package use -p\n"
              "for version use -v\n"
              "for a list of packages use -l\n"
              "examples: [+] recursive search on a list :  python DVFetcher -r -l=\"pandas 0.22.0,numpy\"\n"
              "information about 1 package: [+] python DVFetcher -p=\"pandas\" -v=\"0.22.0\"")

    parser.add_argument('-p', type=str, default=None,
                        help='Package name')
    parser.add_argument('-v', type=str, default=None,
                        help='Version')
    parser.add_argument('-r', action='store_true', default=False,
                        help='Recursive search')
    parser.add_argument('-l', type=str, default=None,
                        help='List of packages')

    args = parser.parse_args()

    result_file = open("results.csv", "w", buffering=1)


    if args.r:
        version = None
        if args.v:
            version = args.v
        if args.r:
            if args.p:
                package_name = args.p
                if version:
                    parent_package_data = get_requirements.get_package_req(package_name, version)
                    data = parse_recursivly_on_one_package(package_name, version)
                elif version is None:
                    parent_package_data = get_requirements.get_package_req(package_name)
                    data = parse_recursivly_on_one_package(package_name)

                result_file.write(
                    "{},{},{},{}\n".format(parent_package_data["name"], parent_package_data["version"],
                                           parent_package_data["dependencies"],
                                           parent_package_data["vulnerabilities"]))
                for d in data:
                    d_json = data[d]
                    print("---data----")
                    print(data)
                    result_file.write("{},{},{},{}\n".format(d_json["name"], d_json["version"],d_json["dependencies"], d_json["vulnerabilities"]))
            elif args.l:
                packages = args.l
                list_of_packages = packages.split(",")
                print(list_of_packages)
                for package in list_of_packages:
                    p = package.split(" ")
                    package_name = p[0]
                    version = None
                    if len(p)>1:
                        version = p[1]
                    if version:
                        parent_package_data = get_requirements.get_package_req(package_name, version)
                        data = parse_recursivly_on_one_package(package_name, version)
                    elif version is None:
                        parent_package_data = get_requirements.get_package_req(package_name)
                        data = parse_recursivly_on_one_package(package_name)

                    result_file.write(
                        "{},{},{},{}\n".format(parent_package_data["name"], parent_package_data["version"], parent_package_data["dependencies"],
                                               parent_package_data["vulnerabilities"]))
                    for d in data:
                        d_json = data[d]
                        result_file.write(
                            "{},{},{},{}\n".format(d_json["name"], d_json["version"], d_json["dependencies"], d_json["vulnerabilities"]))
    else:
        version = None
        if args.v:
            version = args.v
        if args.p:
            package_name = args.p
            d = get_requirements.get_package_req(package_name, version)
            result_file.write(
                "{},{},{},{}\n".format(d["name"], d["version"], d["dependencies"], d["vulnerabilities"]))
        elif args.l:
            packages = args.l
            list_of_packages = packages.split(",")
            print(list_of_packages)
            data = get_requirements.get_info_for_list_of_packages(list_of_packages)
            print("data-----------")
            print(data)
            #print(data)
            for d in data:
                # print(data[d])
                # if not data[d]["version"]:
                #     print("not")
                result_file.write(
                    "{},{},{},{}\n".format(data[d]["name"], data[d]["version"], data[d]["dependencies"], data[d]["vulnerabilities"]))

    result_file.close()








    #
    # recursive = input("Recursive? (y/n)")
    # if recursive == "y":
    #     package_name_and_version = input("package name and version [name] [version] :")
    #     package = package_name_and_version.split(" ")
    #     data = parse_recursivly_on_one_package(package[0],package[1])
    #     f = open("output.txt", "w")
    #     f.writelines(data)

