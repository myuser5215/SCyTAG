import os
from os.path import isfile
import re
import sys
from dotenv import load_dotenv
DEBUG = True
EMPTY_SET = (0, 0)

class IrHeadAndBody:
    def __init__(self, irHead, bodyPredicates):
        self.irHead = irHead
        self.bodyPredicates = bodyPredicates


def printDebug(debugMessage):
    if DEBUG:
        print(debugMessage)

# Find IRs' required conditions (facts) that are not represented in the fact file and are not IRs themselves
def findMissingPredicates(factFileName, irFileName):
    factNames = findUniqueFactNames(factFileName)
    printDebug(f"Fact file: {factFileName}, its fact names:")
    for factName in factNames:
        printDebug(factName)

    irsHeadsAndBodies, irNames = findIrsHeadsAndBodies(irFileName)
    if irsHeadsAndBodies is None:
        return
    printDebug(f"IR file: {irFileName}, its IRs and their Heads and Bodies:")
    for irHeadAndBody in irsHeadsAndBodies:
        printDebug(f"IR head: {irHeadAndBody.irHead}, its body predicates:")
        for predicate in irHeadAndBody.bodyPredicates:
            printDebug(predicate)
    printDebug("IR unique names:")
    for irName in irNames:
        printDebug(irName)

    # Go through IRs' body predicates and find those that don't appear in fact names and IR names
    missingPredicates = []
    for irHeadAndBody in irsHeadsAndBodies:
        for predicate in irHeadAndBody.bodyPredicates:
            predicateHead = predicate[0:predicate.find("(")]
            if predicateHead not in factNames and predicateHead not in irNames:
                missingPredicates.append(predicate)
                printDebug(f"The IR {irHeadAndBody.irHead} misses the {predicate} condition")

    return missingPredicates

# Read the given fact file and extract unique fact names
def findUniqueFactNames(factFileName):
    if not isfile(factFileName):  # File does not exist
        print(f"File {factFileName} does not exist")
        return []

    irFile = open(factFileName, 'r')
    fileLines = irFile.readlines()
    irFile.close()

    factNames = []
    for line in fileLines:
        if line.startswith("/*") or len(line) < 5:
            continue
        factName = line[0:line.find("(")]
        if factName not in factNames:
            factNames.append(factName)

    return factNames

# Read the given IR file and extract IRs' heads and body predicates
def findIrsHeadsAndBodies(irFileName):
    if not isfile(irFileName):  # File does not exist
        print(f"File {irFileName} does not exist")
        return None

    irFile = open(irFileName, 'r')
    fileLines = irFile.readlines()
    irFile.close()

    irHeadAndBody = IrHeadAndBody('', [])
    irsHeadsAndBodies = []
    irNames = []
    irSection = False
    irBody = False
    for line in fileLines:
        if "interaction_rule(" in line:
            irSection = True  # IR section starts here
            continue
        if "rule_desc(" in line:
            irsHeadsAndBodies.append(irHeadAndBody)
            irHeadAndBody = IrHeadAndBody('', [])
            irSection = False  # IR section ends here
            irBody = False
            continue
        if not irSection:
            continue
        if not irBody:
            irHead = line[line.find(" (")+2:line.find(":-")]
            irHeadAndBody.irHead = irHead.rstrip()
            irName = irHead[0:irHead.find("(")]
            if irName not in irNames:
                irNames.append(irName)
            irBody = True
            continue
        bodyPredicate = line[0:line.find("),")+1]
        # Check if the string ends with "))" and remove the last ")"
        if bodyPredicate.endswith("))"):
            bodyPredicate = bodyPredicate[:-1]  # Remove the last character
        irHeadAndBody.bodyPredicates.append(bodyPredicate.lstrip())

    return irsHeadsAndBodies, irNames

# Make facts from given predicates
def predicatesToFacts(predicates):
    missingFacts = []
    for predicate in predicates:
        # Split predicate to head and parameters, using regular expressions
        match = re.match(r"(\w+)\((.*)\)", predicate)
        if match:
            head = match.group(1)  # Extract the head
            parameters = [param.strip() for param in match.group(2).split(',')]  # Extract parameters and strip spaces
            fact = f"{head}("
            for param in parameters:
                if not (param.startswith('_') or param[0].islower() or param.startswith('\'') or param.startswith('\"')):
                    fact += '_'  # Add underscore for variable params
                fact += f"{param}, "
            fact = fact[0:-2]  # Remove last ", "
            missingFacts.append(fact+").")

    return missingFacts

def main():
    # Load environment variables from .env file
    load_dotenv()
    missingFactsFileName = os.getenv('MISSING_FACTS_FILE_PATH')
    
    if not missingFactsFileName:
        print("Error: MISSING_FACTS_FILE_PATH not found in .env file")
        return
    if len(sys.argv) > 1:
        factFileName = sys.argv[1]
    if len(sys.argv) > 2:
        irFileName = sys.argv[2]
    missingPredicates = findMissingPredicates(factFileName, irFileName)
    if len(missingPredicates) == 0:
        print("There are no missing facts")
    else:
        missingFacts = predicatesToFacts(missingPredicates)
        with open(missingFactsFileName, 'w', encoding='utf-8', newline='') as outfile:
            for missingFact in missingFacts:
                outfile.write(missingFact + "\n")


if __name__ == "__main__":
    main()
