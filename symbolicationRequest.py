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

class ModuleV1(ModuleV2):
  def __init__(self, startAddress, libName, libSize, pdbAge, pdbSig, pdbName):
    ModuleV2.__init__(self, libName, pdbAge, pdbSig, pdbName)
    self.startAddress = startAddress
    self.libSize = libSize

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

def getModuleV1(startAddress, libName, libSize, pdbAge, pdbSig, pdbName):
  if isinstance(startAddress, basestring):
    startAddress = int(startAddress, 16)
  if not isinstance(startAddress, (int, long)) or startAddress < 0:
    LogTrace("Bad start address format: " + str(startAddress))
    return None

  if isinstance(libSize, basestring):
    libSize = int(libSize)
  if not isinstance(libSize, (int, long)) or int(libSize) < 0:
    LogTrace("Bad PDB size: " + str(libSize))
    return None

  v2 = getModuleV2(libName, pdbAge, pdbSig, pdbName)
  if v2 is None:
    return None
  return ModuleV1(startAddress, v2.libName, libSize, v2.pdbAge, v2.pdbSig,
	 v2.pdbName)

class ModuleMap:
  def __init__(self, memoryMap):
    self.sortedModuleAddresses = []
    self.addressToModuleIndex = {}
    self.memoryMap = memoryMap
    moduleIndex = 0
    for module in memoryMap:
      startAddress = module.startAddress
      self.sortedModuleAddresses.append(startAddress)
      self.addressToModuleIndex[startAddress] = moduleIndex
      moduleIndex += 1
    self.sortedModuleAddresses = sorted(self.sortedModuleAddresses)

  def LookupModuleIndex(self, pc):
    index = bisect(self.sortedModuleAddresses, pc) - 1
    if index < 0:
      return -1

    moduleStart = self.sortedModuleAddresses[index]
    moduleIndex = self.addressToModuleIndex[moduleStart]
    module = self.memoryMap[moduleIndex]
    moduleEnd = moduleStart + module.libSize - 1
    if moduleStart <= pc and pc <= moduleEnd:
      return moduleIndex
    return -1

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
    self.moduleMap = None
    self.forwardCount = 0

  def ParseRequests(self, rawRequests):
    self.isValidRequest = False
    if isinstance(rawRequests, dict):
      self.ParseRequestsV2(rawRequests)
      return
    self.ParseRequestsV1(rawRequests)

  def ParseRequestsV2(self, rawRequests):
    try:
      if "version" not in rawRequests:
        LogTrace("Request is missing 'version' field")
        return
      version = rawRequests["version"]
      if version != 2:
        LogTrace("Invalid version: %s" % version)
        return

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

  def ParseRequestsV1(self, rawRequests):
    if not isinstance(rawRequests, list):
      LogTrace("rawRequests is not a list")
      return

    if len(rawRequests) == 0:
      return

    for rawRequest in rawRequests:
      self.isValidRequest = False
      self.ParseRequestV1(rawRequest)
      if not self.isValidRequest:
        return

    firstModuleMap = ModuleMap(self.memoryMaps[0])
    self.combinedMemoryMap = []
    for stackNum in range(len(self.stacks)):
      stack = self.stacks[stackNum]
      oldLength = len(self.combinedMemoryMap)
      self.combinedMemoryMap.extend(self.memoryMaps[stackNum])
      curModuleMap = None
      if stackNum != 0:
        curModuleMap = ModuleMap(self.memoryMaps[stackNum])
      self.memoryMaps[stackNum] = None
      newStack = []
      for pc in stack:
        moduleIndex = self.LookupModuleIndex(pc, curModuleMap, firstModuleMap,
                                             oldLength)
        if moduleIndex == -1:
          LogTrace("Couldn't find module for PC: " + hex(pc))
          newStack.append((moduleIndex, pc))
          continue
        module = self.combinedMemoryMap[moduleIndex]
        newStack.append((moduleIndex, pc - module.startAddress))
      self.stacks[stackNum] = newStack

    for moduleIndex in range(len(self.combinedMemoryMap)):
      old = self.combinedMemoryMap[moduleIndex]
      new = ModuleV2(old.libName, old.pdbAge, old.pdbSig, old.pdbName)
      self.combinedMemoryMap[moduleIndex] = new

  def ParseRequestV1(self, rawRequest):
    try:
      # Parse to confirm valid format before doing any processing
      if not isinstance(rawRequest, dict):
        LogTrace("Request is not a map")
        return
      if "memoryMap" not in rawRequest or "stack" not in rawRequest:
        LogTrace("Request is missing 'memoryMap' or 'stack' fields")
        return
      if not isinstance(rawRequest["memoryMap"], list):
        LogTrace("'memoryMap' field in request is not a list")
      if not isinstance(rawRequest["stack"], list):
        LogTrace("'stack' field in request is not a list")
        return

      # Check stack is well-formatted
      cleanStack = []
      for pc in rawRequest["stack"]:
        if isinstance(pc, basestring):
          pc = int(pc, 16)
        if not isinstance(pc, (int, long)) or pc < 0:
          LogTrace("Invalid stack address: " + hex(pc))
          return
        cleanStack.append(pc)

      # Check memory map is well-formatted
      cleanMemoryMap = []
      for rawModule in rawRequest["memoryMap"]:
        if not isinstance(rawModule, list) or len(rawModule) != 6:
          LogTrace("Entry in memory map is not a 6 item list: %s" % rawModule)
          return
        
        module = getModuleV1(*rawModule)
        if module is None:
          return

        cleanMemoryMap.append(module)

      # Check if this request has been forwarded from another SymbolicationServer
      if "forwarded" in rawRequest:
        if not isinstance(rawRequest["forwarded"], (int, long)):
          LogTrace("Invalid 'forwards' field: " + str(rawRequest["forwarded"]))
          return
        self.forwardCount = rawRequest["forwarded"]

      self.stacks.append(cleanStack)
      self.memoryMaps.append(cleanMemoryMap)

    except Exception as e:
      LogTrace("Exception while parsing request: " + str(e))
      return

    self.isValidRequest = True

  def ForwardRequest(self, indexes, stack, modules, symbolicatedStack):
    LogTrace("Forwarding " + str(len(stack)) + " PCs for symbolication")

    try:
      # find the maximum offset in each module
      maxOffset = {}
      for entry in stack:
        moduleIndex = entry[0]
        offset = entry[1]
        module = self.combinedMemoryMap[moduleIndex]
        newMax = max(maxOffset.get(module, 0), offset)
        maxOffset[module] = newMax

      # create a dummy layout so that we can forward as a v1 request
      addr = 0
      startAddress = {}
      for m in modules:
        libSize = maxOffset[m] + 1
        startAddress[m] = addr
        addr += libSize

      url = self.symFileManager.sOptions["remoteSymbolServer"]
      rawModules =  []
      for m in modules:
        libSize = maxOffset[m] + 1
        start = startAddress[m]
        l = [start, m.libName, libSize, m.pdbAge, m.pdbSig, m.pdbName]
        rawModules.append(l)

      rawStack = []
      for entry in stack:
        moduleIndex = entry[0]
        offset = entry[1]
        module = self.combinedMemoryMap[moduleIndex]
        start = startAddress[module]
        pc = start + offset
        rawStack.append(pc)

      requestObj = [{ "stack": rawStack, "memoryMap": rawModules, "forwarded": self.forwardCount + 1 }]
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
    curModuleMap = None

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

  def LookupModuleIndex(self, pc, curModuleMap, firstModuleMap, diff):
    memoryMapsToConsult = [curModuleMap, firstModuleMap]
    for dataIndex in range(len(memoryMapsToConsult)):
      data = memoryMapsToConsult[dataIndex]
      if data == None:
        continue
      r = data.LookupModuleIndex(pc)
      if r != -1:
        if dataIndex == 0:
          return r + diff
        return r
    return -1
