from logging import LogTrace, LogError, LogMessage
import symFileManager

import re
import json
import urllib2
from bisect import bisect

# Precompiled regex for validating lib names
gLibNameRE = re.compile("[0-9a-zA-Z_+\-\.]*$") # Empty lib name means client couldn't associate frame with any lib
gPdbSigRE = re.compile("{([0-9a-fA-F]{8})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{12})}$")
gPdbSigRE2 = re.compile("[0-9a-fA-F]{32}$")

# Maximum number of times a request can be forwarded to a different server
# for symbolication. Also prevents loops.
MAX_FORWARDED_REQUESTS = 3

class ModuleV2:
  def __init__(self, libName, pdbAge, pdbSig, pdbName):
    self.libName = libName
    self.pdbAge = pdbAge
    self.pdbSig = pdbSig
    self.pdbName = pdbName

def getModuleV2(libName, pdbAge, pdbSig, pdbName):
  if not isinstance(libName, basestring) or not gLibNameRE.match(libName):
    LogTrace("Bad library name: " + str(libName))
    return None

  if isinstance(pdbSig, basestring):
    matches = gPdbSigRE.match(pdbSig)
    if matches:
      pdbSig = "".join(matches.groups()).upper()
    elif gPdbSigRE2.match(pdbSig):
      pdbSig = pdbSig.upper()
    else:
      LogTrace("Bad PDB signature: " + pdbSig)
      return None
  else:
    LogTrace("Bad PDB signature: " + str(pdbSig))
    return None

  if isinstance(pdbAge, basestring):
    pdbAge = int(pdbAge)
  if not isinstance(pdbAge, (int, long)) or int(pdbAge) < 0:
    LogTrace("Bad PDB age: " + str(pdbAge))
    return None
  pdbAge = (hex(pdbAge)[2:]).lower()

  if not isinstance(pdbName, basestring) or not gLibNameRE.match(pdbName):
    LogTrace("Bad PDB name: " + str(pdbName))
    return None
  return ModuleV2(libName, pdbAge, pdbSig, pdbName)

class SymbolicationRequest:
  def __init__(self, symFileManager, rawRequests):
    self.Reset()
    self.symFileManager = symFileManager
    self.stacks = []
    self.memoryMaps = []
    self.ParseRequests(rawRequests)

  def Reset(self):
    self.symFileManager = None
    self.isValidRequest = False
    self.memoryMaps = []
    self.stacks = []
    self.forwardCount = 0

  def ParseRequests(self, rawRequests):
    self.isValidRequest = False
    if not isinstance(rawRequests, dict):
      LogTrace("Request is not a dictionary")
      return
    self.ParseRequestsV2(rawRequests)

  def ParseRequestsV2(self, rawRequests):
    try:
      if "version" not in rawRequests:
        LogTrace("Request is missing 'version' field")
        return
      version = rawRequests["version"]
      if version != 2:
        LogTrace("Invalid version: %s" % version)
        return

      if "forwarded" in rawRequests:
        if not isinstance(rawRequests["forwarded"], (int, long)):
          LogTrace("Invalid 'forwards' field: " + str(rawRequests["forwarded"]))
          return
        self.forwardCount = rawRequests["forwarded"]

      if "memoryMap" not in rawRequests:
        LogTrace("Request is missing 'memoryMap' field")
        return
      memoryMap = rawRequests["memoryMap"]
      if not isinstance(memoryMap, list):
        LogTrace("'memoryMap' field in request is not a list")

      if "stacks" not in rawRequests:
        LogTrace("Request is missing 'stacks' field")
        return
      stacks = rawRequests["stacks"]
      if not isinstance(stacks, list):
        LogTrace("'stacks' field in request is not a list")
        return

      # Check memory map is well-formatted
      cleanMemoryMap = []
      for module in memoryMap:
        if not isinstance(module, list):
          LogTrace("Entry in memory map is not a list: " + str(module))
          return

        if len(module) != 4:
          LogTrace("Entry in memory map is not a 4 item list: " + str(module))
          return

        module = getModuleV2(*module)
        cleanMemoryMap.append(module)

      self.combinedMemoryMap = cleanMemoryMap

      # Check stack is well-formatted
      for stack in stacks:
        if not isinstance(stack, list):
          LogTrace("stack is not a list")
          return
        for entry in stack:
          if not isinstance(entry, list):
            LogTrace("stack entry is not a list")
            return
          if len(entry) != 2:
            LogTrace("stack entry doesn't have exactly 2 elements")
            return

        self.stacks.append(stack)

    except Exception as e:
      LogTrace("Exception while parsing request: " + str(e))
      return

    self.isValidRequest = True

  def ForwardRequest(self, indexes, stack, modules, symbolicatedStack):
    LogTrace("Forwarding " + str(len(stack)) + " PCs for symbolication")

    try:
      url = self.symFileManager.sOptions["remoteSymbolServer"]
      rawModules =  []
      moduleToIndex = {}
      moduleCount = 0
      for m in modules:
        l = [m.libName, m.pdbAge, m.pdbSig, m.pdbName]
        rawModules.append(l)
        moduleToIndex[m] = moduleCount
        moduleCount += 1

      rawStack = []
      for entry in stack:
        moduleIndex = entry[0]
        offset = entry[1]
        module = self.combinedMemoryMap[moduleIndex]
        newIndex = moduleToIndex[module]
        rawStack.append([newIndex, offset])

      requestObj = { "stacks": [rawStack], "memoryMap": rawModules,
	             "forwarded": self.forwardCount + 1, "version": 2 }
      requestJson = json.dumps(requestObj)
      headers = { "Content-Type": "application/json" }
      requestHandle = urllib2.Request(url, requestJson, headers)
      response = urllib2.urlopen(requestHandle)
    except Exception as e:
      LogError("Exception while forwarding request: " + str(e))
      return

    try:
      responseJson = response.read()
    except Exception as e:
      LogError("Exception while reading server response to forwarded request: " + str(e))
      return

    try:
      responseSymbols = json.loads(responseJson)[0]
      if len(responseSymbols) != len(stack):
        LogError(str(len(responseSymbols)) + " symbols in response, " + str(len(stack)) + " PCs in request!")
        return

      for index in range(0, len(stack)):
        symbol = responseSymbols[index]
        originalIndex = indexes[index]
        symbolicatedStack[originalIndex] = symbol
    except Exception as e:
      LogError("Exception while parsing server response to forwarded request: " + str(e))
      return

  def Symbolicate(self, stackNum):
    # Check if we should forward requests when required sym files don't exist
    shouldForwardRequests = False
    if self.symFileManager.sOptions["remoteSymbolServer"] and self.forwardCount < MAX_FORWARDED_REQUESTS:
      shouldForwardRequests = True

    # Symbolicate each PC
    pcIndex = -1
    symbolicatedStack = []
    missingSymFiles = []
    unresolvedIndexes = []
    unresolvedStack = []
    unresolvedModules = []
    stack = self.stacks[stackNum]

    for entry in stack:
      pcIndex += 1
      moduleIndex = entry[0]
      offset = entry[1]
      if moduleIndex == -1:
        symbolicatedStack.append(hex(offset))
        continue
      module = self.combinedMemoryMap[moduleIndex]

      # Don't look for a missing lib multiple times in one request
      if (module.pdbName, module.pdbSig, module.pdbAge) in missingSymFiles:
        if shouldForwardRequests:
          unresolvedIndexes.append(pcIndex)
          unresolvedStack.append(entry)
        symbolicatedStack.append(hex(offset) + " (in " + module.libName + ")")
        continue

      functionName = None
      libSymbolMap = self.symFileManager.GetLibSymbolMap(module.pdbName,
                                                         module.pdbSig,
                                                         module.pdbAge)
      if libSymbolMap:
        functionName = libSymbolMap.Lookup(offset)
      else:
        if shouldForwardRequests:
          unresolvedIndexes.append(pcIndex)
          unresolvedStack.append(entry)
          unresolvedModules.append(module)
        missingSymFiles.append((module.pdbName, module.pdbSig, module.pdbAge))

      if functionName == None:
        functionName = hex(offset)
      symbolicatedStack.append(functionName + " (in " + module.libName + ")")

    # Ask another server for help symbolicating unresolved addresses
    if len(unresolvedStack) > 0:
      self.ForwardRequest(unresolvedIndexes, unresolvedStack, unresolvedModules, symbolicatedStack)

    return symbolicatedStack
