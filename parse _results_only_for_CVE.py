f = open("results.csv","r")
parsed_file = open("parssed.csv","w")
lines = f.readlines()
for line in lines:
    if "CVE" in line:
        parse = line.split(",")
        print(parse[0],parse[1])
        for p in parse:
            if "CVE" in p:
                print(p)
                parsed_file.write("{},{},{}\n".format(parse[0],parse[1],p))
