from bisect import bisect
from symLogging import LogDebug, LogError

class SymbolInfo:
  def __init__(self, addressMap):
    self.sortedAddresses = sorted(addressMap.keys())
    self.sortedSymbols = [addressMap[address] for address in self.sortedAddresses]
    self.entryCount = len(self.sortedAddresses)

  # TODO: Add checks for address < funcEnd ?
  def Lookup(self, address):
    nearest = bisect(self.sortedAddresses, address) - 1
    if nearest < 0:
      return None
    return self.sortedSymbols[nearest]

  def GetEntryCount(self):
    return self.entryCount

def ParseSymbolFile(symFile):
  try:
    symbolMap = {}
    publicCount = 0
    funcCount = 0
    for lineNum, line in enumerate(symFile.readlines()):
      if line[0:7] == "PUBLIC ":
        line = line.rstrip()
        fields = line.split(" ")
        if len(fields) < 4:
          LogDebug("Line " + str(lineNum + 1) + " is messed")
          continue
        address = int(fields[1], 16)
        symbolMap[address] = " ".join(fields[3:])
        publicCount += 1
      elif line[0:5] == "FUNC ":
        line = line.rstrip()
        fields = line.split(" ")
        if len(fields) < 5:
          LogDebug("Line " + str(lineNum + 1) + " is messed")
          continue
        address = int(fields[1], 16)
        symbolMap[address] = " ".join(fields[4:])
        funcCount += 1
  except Exception as e:
    LogError("Error parsing SYM file {}: {}".format(symFile, e))
    return None

  logString = "Found " + str(len(symbolMap.keys())) + " unique entries from "
  logString += str(publicCount) + " PUBLIC lines, " + str(funcCount) + " FUNC lines"
  LogDebug(logString)

  return SymbolInfo(symbolMap)

