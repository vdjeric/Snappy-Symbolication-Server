from symLogging import LogDebug, LogError, LogMessage

import re
import json
import urllib2

# Precompiled regex for validating lib names
gLibNameRE = re.compile("[0-9a-zA-Z_+\-\.]*$") # Empty lib name means client couldn't associate frame with any lib
gPdbSigRE = re.compile("{([0-9a-fA-F]{8})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{12})}$")
gPdbSigRE2 = re.compile("[0-9a-fA-F]{32}$")

# Maximum number of times a request can be forwarded to a different server
# for symbolication. Also prevents loops.
MAX_FORWARDED_REQUESTS = 3

def getModuleV3(libName, breakpadId):
  if not isinstance(libName, basestring) or not gLibNameRE.match(libName):
    LogDebug("Bad library name: " + str(libName))
    return None

  if not isinstance(breakpadId, basestring):
    LogDebug("Bad breakpad id: " + str(breakpadId))
    return None

  return (libName, breakpadId)

class SymbolicationRequest:
  def __init__(self, symFileManager, rawRequests, remoteIp):
    self.remoteIp = remoteIp
    self.Reset()
    self.symFileManager = symFileManager
    self.stacks = []
    self.combinedMemoryMap = []
    self.knownModules = []
    self.includeKnownModulesInResponse = True
    self.ParseRequests(rawRequests)

  def LogDebug(self, string):
    LogDebug(string, self.remoteIp)

  def LogMessage(self, string):
    LogMessage(string, self.remoteIp)

  def LogError(self, string):
    LogError(string, self.remoteIp)

  def Reset(self):
    self.symFileManager = None
    self.isValidRequest = False
    self.combinedMemoryMap = []
    self.knownModules = []
    self.includeKnownModulesInResponse = True
    self.stacks = []
    self.appName = ""
    self.osName = ""
    self.forwardCount = 0

  def ParseRequests(self, rawRequests):
    self.isValidRequest = False

    try:
      if not isinstance(rawRequests, dict):
        self.LogDebug("Request is not a dictionary")
        return

      if "version" not in rawRequests:
        self.LogDebug("Request is missing 'version' field")
        return
      version = rawRequests["version"]
      if version != 3 and version != 4:
        self.LogDebug("Invalid version: %s" % version)
        return

      if "forwarded" in rawRequests:
        if not isinstance(rawRequests["forwarded"], (int, long)):
          self.LogDebug("Invalid 'forwards' field: " + str(rawRequests["forwarded"]))
          return
        self.forwardCount = rawRequests["forwarded"]

      if "memoryMap" not in rawRequests:
        self.LogDebug("Request is missing 'memoryMap' field")
        return
      memoryMap = rawRequests["memoryMap"]
      if not isinstance(memoryMap, list):
        self.LogDebug("'memoryMap' field in request is not a list")

      if "stacks" not in rawRequests:
        self.LogDebug("Request is missing 'stacks' field")
        return
      stacks = rawRequests["stacks"]
      if not isinstance(stacks, list):
        self.LogDebug("'stacks' field in request is not a list")
        return

      # Check memory map is well-formatted
      cleanMemoryMap = []
      for module in memoryMap:
        if not isinstance(module, list):
          self.LogDebug("Entry in memory map is not a list: " + str(module))
          return

        if len(module) != 2:
          self.LogDebug("Entry in memory map is not a 2 item list: " + str(module))
          return
        module = getModuleV3(*module)

        if module is None:
          return

        cleanMemoryMap.append(module)

      self.combinedMemoryMap = cleanMemoryMap
      self.knownModules = [False] * len(self.combinedMemoryMap)

      if version < 4:
        self.includeKnownModulesInResponse = False

      # Check stack is well-formatted
      for stack in stacks:
        if not isinstance(stack, list):
          self.LogDebug("stack is not a list")
          return
        for entry in stack:
          if not isinstance(entry, list):
            self.LogDebug("stack entry is not a list")
            return
          if len(entry) != 2:
            self.LogDebug("stack entry doesn't have exactly 2 elements")
            return

        self.stacks.append(stack)

    except Exception as e:
      self.LogDebug("Exception while parsing request: " + str(e))
      return

    self.isValidRequest = True

  def ForwardRequest(self, indexes, stack, modules, symbolicatedStack):
    self.LogDebug("Forwarding " + str(len(stack)) + " PCs for symbolication")

    try:
      url = self.symFileManager.sOptions["remoteSymbolServer"]
      rawModules =  []
      moduleToIndex = {}
      newIndexToOldIndex = {}
      for moduleIndex, m in modules:
        l = list(m)
        newModuleIndex = len(rawModules)
        rawModules.append(l)
        moduleToIndex[m] = newModuleIndex
        newIndexToOldIndex[newModuleIndex] = moduleIndex

      rawStack = []
      for entry in stack:
        moduleIndex = entry[0]
        offset = entry[1]
        module = self.combinedMemoryMap[moduleIndex]
        newIndex = moduleToIndex[module]
        rawStack.append([newIndex, offset])

      requestVersion = 4
      while True:
        requestObj = {
          "stacks": [rawStack], "memoryMap": rawModules,
          "forwarded": self.forwardCount + 1, "version": requestVersion
        }
        requestJson = json.dumps(requestObj)
        headers = { "Content-Type": "application/json" }
        requestHandle = urllib2.Request(url, requestJson, headers)
        try:
          response = urllib2.urlopen(requestHandle)
        except Exception as e:
          if requestVersion == 4:
            # Try again with version 3
            requestVersion = 3
            continue
          raise e
        succeededVersion = requestVersion
        break

    except Exception as e:
      self.LogError("Exception while forwarding request: " + str(e))
      return

    try:
      responseJson = json.loads(response.read())
    except Exception as e:
      self.LogError("Exception while reading server response to forwarded request: " + str(e))
      return

    try:
      if succeededVersion == 4:
        responseKnownModules = responseJson['knownModules']
        for newIndex, known in enumerate(responseKnownModules):
          if known and newIndex in newIndexToOldIndex:
            self.knownModules[newIndexToOldIndex[newIndex]] = True

        responseSymbols = responseJson['symbolicatedStacks'][0]
      else:
        responseSymbols = responseJson[0]
      if len(responseSymbols) != len(stack):
        self.LogError(str(len(responseSymbols)) + " symbols in response, " + str(len(stack)) + " PCs in request!")
        return

      for index in range(0, len(stack)):
        symbol = responseSymbols[index]
        originalIndex = indexes[index]
        symbolicatedStack[originalIndex] = symbol
    except Exception as e:
      self.LogError("Exception while parsing server response to forwarded request: " + str(e))
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

    symbols = self.symFileManager.GetLibSymbolMaps(self.combinedMemoryMap)
    for moduleIndex, module in enumerate(self.combinedMemoryMap):
      if module not in symbols:
        missingSymFiles.append(module)
        if shouldForwardRequests:
          unresolvedModules.append((moduleIndex, module))
      else:
        self.knownModules[moduleIndex] = True

    for entry in stack:
      pcIndex += 1
      moduleIndex = entry[0]
      offset = entry[1]
      if moduleIndex == -1:
        symbolicatedStack.append(hex(offset))
        continue
      module = self.combinedMemoryMap[moduleIndex]

      if module in missingSymFiles:
        if shouldForwardRequests:
          unresolvedIndexes.append(pcIndex)
          unresolvedStack.append(entry)
        symbolicatedStack.append(hex(offset) + " (in " + module[0] + ")")
        continue

      functionName = None
      libSymbolMap = symbols[module]
      functionName = libSymbolMap.Lookup(offset)

      if functionName == None:
        functionName = hex(offset)
      symbolicatedStack.append(functionName + " (in " + module[0] + ")")

    # Ask another server for help symbolicating unresolved addresses
    if len(unresolvedStack) > 0:
      self.ForwardRequest(unresolvedIndexes, unresolvedStack, unresolvedModules, symbolicatedStack)

    return symbolicatedStack
