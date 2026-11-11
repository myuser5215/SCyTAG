import sys
import os
import csv
import json
from os import listdir
from os.path import isfile, join

NVDPATH = "nvd_json_files"
DEFAULT_VALUE = "Undefined"
Unknown = "Unknown"
DEBUG = False

def printDebug(debugMessage):
    if DEBUG:
        print(debugMessage)

# Replace '.' and '-' with '_', since MulVAL doesn't like dots in names and constants
# If edge name starts with number, add '_' at the beginning, since MulVAL doesn't like names starting with nums
def fixName(name):
    fixedName = name.replace('.', '_').replace('-', '_')
    if fixedName[0].isdigit():
        fixedName = '_' + fixedName

    return fixedName

# Reads the list of binaries from the input file
# The input file structure: binary_name, binary_version
def readBinariesList(binFile):
    if not os.path.isfile(binFile):  # File does not exist
        print("File {} does not exist".format(binFile))
        raise Exception()

    tsvinf = open(binFile, 'r')
    tsvin = csv.reader(tsvinf, delimiter=',')
    binaries = []
    for row in tsvin:
        if len(row) <= 1:  # Jump over empty lines
            continue
        binaries.append((row[0].strip(), row[1].strip()))

    tsvinf.close()
    return binaries

# Go over all the CVE JSON files and search for CVEs related to one of the binaries in the input file
def findVulnerableBinaries(binaries):
    # Build the list of NVD CVE files to process
    nvdFiles = [file for file in listdir(NVDPATH) if isfile(join(NVDPATH, file))]
    printDebug(nvdFiles)

    vulBinaries = []
    for file in nvdFiles:
        jsonFile = open(join(NVDPATH, file), encoding='utf-8')
        try:
            cve_json_object = json.load(jsonFile)
        except ValueError:
            print("Could not load {} file.".format(file))
            continue
        for cve_item in cve_json_object['CVE_Items']:
            if 'baseMetricV2' not in cve_item['impact']:
                continue
            # get CVE-ID
            cve_id = cve_item['cve']['CVE_data_meta']['ID']
            vuln_soft = DEFAULT_VALUE
            vuln_soft_ver = DEFAULT_VALUE
            # get severity level
            severity = cve_item['impact']['baseMetricV2']['severity']
            # get access vector
            accessVector = cve_item['impact']['baseMetricV2']['cvssV2']['accessVector']
            # Get CIA impact
            availability_loss = cve_item['impact']['baseMetricV2']['cvssV2']['availabilityImpact']
            data_loss = cve_item['impact']['baseMetricV2']['cvssV2']['confidentialityImpact']
            integrity_loss = cve_item['impact']['baseMetricV2']['cvssV2']['integrityImpact']
            ciaImpact = ""
            if availability_loss != "NONE":
                ciaImpact += "availability_loss,"
            elif data_loss != "NONE":
                ciaImpact += "data_loss,"
            elif integrity_loss != "NONE":
                ciaImpact += "data_modification,"

            if ciaImpact == "":
                ciaImpact = Unknown
            else:
                ciaImpact = ciaImpact[:-1]  # Remove last comma

            # get vulnerable software
            node_list = cve_item['configurations']['nodes']
            for node in node_list:
                if 'cpe_match' in node:
                    cpe_list = node['cpe_match']
                    for cpe_item in cpe_list:
                        cpe_item = cpe_item['cpe23Uri']
                        vuln_soft = cpe_item.split(":")[4]
                        vuln_soft_ver = cpe_item.split(":")[5]
                        break
                break
            if not softwareAndVersionInList((vuln_soft.strip(), vuln_soft_ver.strip()), binaries):
                continue

            printDebug("CVE-ID: {}, Severity: {}, Access: {}, CIA Impact: {}, Vulnerable Software: {}".format(
                cve_id, severity, accessVector, ciaImpact, vuln_soft))
            vulBinaries.append((cve_id, severity, accessVector, ciaImpact, vuln_soft))

        jsonFile.close()

    return vulBinaries

# Check if the tuple (binary, version) is in the binaries list
def softwareAndVersionInList(binTuple, binaries):
    found = False
    for binary in binaries:
        # Check if the same binary name and binary version
        if binary[0] == binTuple[0] and (binTuple[1] == '*' or binary[1] == binTuple[1]):
            found = True
            break

    return found

# Create MulVAL predicates for the vulnerable binaries
def createPredicatesForVulBinaries(vulBinaries, filePathToCreate):
    fileStream = open(filePathToCreate, "a")
    for binary in vulBinaries:
        print(binary)
        cveId = binary[0]
        severity = binary[1]
        accessVector = binary[2]
        ciaImpact = binary[3]
        vulnSoft = fixName(binary[4])

        predicate = f"vulExists('{cveId}', {vulnSoft}, '{accessVector}', '{ciaImpact}', '{severity}').\n"
        fileStream.write(predicate)

    fileStream.close()

# Go over all the CVE JSON files and search for binaries (ignoring version) from the input file.
# A binary that appears in of the CVE JSON files is an open-source software
def findOpenSourceBinaries(binaries):
    # Build the list of NVD CVE files to process
    nvdFiles = [file for file in listdir(NVDPATH) if isfile(join(NVDPATH, file))]
    printDebug(nvdFiles)

    openSourceBinaries = []
    for file in nvdFiles:
        jsonFile = open(join(NVDPATH, file), encoding='utf-8')
        try:
            cve_json_object = json.load(jsonFile)
        except ValueError:
            print("Could not load {} file.".format(file))
            continue
        for cve_item in cve_json_object['CVE_Items']:
            vuln_soft = DEFAULT_VALUE
            # get vulnerable software
            node_list = cve_item['configurations']['nodes']
            for node in node_list:
                if 'cpe_match' in node:
                    cpe_list = node['cpe_match']
                    for cpe_item in cpe_list:
                        cpe_item = cpe_item['cpe23Uri']
                        vuln_soft = cpe_item.split(":")[4].strip()
                        break
                break
            if not softwareInList(vuln_soft, binaries):
                continue
            if vuln_soft in openSourceBinaries:
                continue

            printDebug("Software found: {}".format(vuln_soft))
            openSourceBinaries.append(vuln_soft)

        jsonFile.close()

    return openSourceBinaries

# Check if the binary is in the binaries list
def softwareInList(sw, binaries):
    found = False
    for binary in binaries:
        # Check if the same binary name
        if binary[0] == sw:
            found = True
            break

    return found

# Create MulVAL predicates for the vulnerable binaries
def createPredicatesForOpenSourceBinaries(openSourceBinaries, filePathToCreate):
    fileStream = open(filePathToCreate, "a")
    for binary in openSourceBinaries:
        print(binary)
        openSourceSoft = fixName(binary)

        predicate = f"bugHyp({openSourceSoft}, 'LOCAL', '{DEFAULT_VALUE}').\n"
        fileStream.write(predicate)
    fileStream.close()

def main():
    inputFile = "BinariesList.csv"  # The list of binaries and their versions
    vulBinFile = "vulBin.p"  # The file to create with list of predicated for vulnerable binaries
    if len(sys.argv) > 1:
        inputFile = sys.argv[1]
    if len(sys.argv) > 2:
        vulBinFile = sys.argv[2]

    print("The file to read: " + inputFile)
    binaries = readBinariesList(inputFile)
    for binary in binaries:
        printDebug("Binary name: {}, version: {}".format(binary[0], binary[1]))
    vulBinaries = findVulnerableBinaries(binaries)
    createPredicatesForVulBinaries(vulBinaries, vulBinFile)
    print("The file {} was updated/created with vulnerable binaries.".format(vulBinFile))


if __name__ == "__main__":
    main()
