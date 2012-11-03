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

class Module:
  def __init__(self, startAddress, libName, libSize, pdbAge, pdbSig, pdbName):
    self.libName = libName
    self.pdbAge = pdbAge
    self.pdbSig = pdbSig
    self.pdbName = pdbName
    self.startAddress = startAddress
    self.libSize = libSize

def getModule(startAddress, libName, libSize, pdbAge, pdbSig, pdbName):
  if isinstance(startAddress, basestring):
    startAddress = int(startAddress, 16)
  if not isinstance(startAddress, (int, long)) or startAddress < 0:
    LogTrace("Bad start address format: " + str(startAddress))
    return None

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

  if isinstance(libSize, basestring):
    libSize = int(libSize)
  if not isinstance(libSize, (int, long)) or int(libSize) < 0:
    LogTrace("Bad PDB size: " + str(libSize))
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

  return Module(startAddress, libName, libSize, pdbAge, pdbSig, pdbName)

class ModuleMap:
  def __init__(self, memoryMap):
    self.sortedModuleAddresses = []
    self.addressToModule = {}
    moduleIndex = 0
    for module in memoryMap:
      startAddress = module.startAddress
      self.sortedModuleAddresses.append(startAddress)
      self.addressToModule[startAddress] = module
      moduleIndex += 1
    self.sortedModuleAddresses = sorted(self.sortedModuleAddresses)

  def LookupModule(self, pc):
    index = bisect(self.sortedModuleAddresses, pc) - 1
    if index < 0:
      return None

    moduleStart = self.sortedModuleAddresses[index]
    module = self.addressToModule[moduleStart]
    moduleEnd = moduleStart + module.libSize - 1
    if moduleStart <= pc and pc <= moduleEnd:
      return module
    return None

class SymbolicationRequest:
  def __init__(self, symFileManager, rawRequests):
    self.Reset()
    self.symFileManager = symFileManager
    self.stacks = []
    self.memoryMaps = []
    if len(rawRequests) == 0:
      self.isValidRequest = False
      return
    for rawRequest in rawRequests:
      self.isValidRequest = False
      self.ParseRequest(rawRequest)
      if not self.isValidRequest:
        return
    self.firstModuleMap = ModuleMap(self.memoryMaps[0])

  def Reset(self):
    self.symFileManager = None
    self.isValidRequest = False
    self.memoryMaps = []
    self.stacks = []
    self.moduleMap = None
    self.forwardCount = 0

  def ParseRequest(self, rawRequest):
    global gLibNameRE, gPdbSigRE, gPdbSigRE2
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
        
        module = getModule(*rawModule)
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
      url = self.symFileManager.sOptions["remoteSymbolServer"]
      rawModules =  []
      for m in modules:
        l = [m.startAddress, m.libName, m.libSize, m.pdbAge, m.pdbSig, m.pdbName]
        rawModules.append(l)
      requestObj = [{ "stack": stack, "memoryMap": rawModules, "forwarded": self.forwardCount + 1 }]
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
    if stackNum != 0:
      curModuleMap = ModuleMap(self.memoryMaps[stackNum])

    for pc in stack:
      pcIndex += 1

      module = self.LookupModule(pc, curModuleMap)
      if module == None:
        LogTrace("Couldn't find module for PC: " + hex(pc))
        symbolicatedStack.append(hex(pc))
        continue

      # Don't look for a missing lib multiple times in one request
      if (module.pdbName, module.pdbSig, module.pdbAge) in missingSymFiles:
        if shouldForwardRequests:
          unresolvedIndexes.append(pcIndex)
          unresolvedStack.append(pc)
        symbolicatedStack.append(hex(pc) + " (in " + module.libName + ")")
        continue

      functionName = None
      libSymbolMap = self.symFileManager.GetLibSymbolMap(module.pdbName,
                                                         module.pdbSig,
                                                         module.pdbAge)
      if libSymbolMap:
        functionName = libSymbolMap.Lookup(pc - module.startAddress)
      else:
        if shouldForwardRequests:
          unresolvedIndexes.append(pcIndex)
          unresolvedStack.append(pc)
          unresolvedModules.append(module)
        missingSymFiles.append((module.pdbName, module.pdbSig, module.pdbAge))

      if functionName == None:
        functionName = hex(pc)
      symbolicatedStack.append(functionName + " (in " + module.libName + ")")

    # Ask another server for help symbolicating unresolved addresses
    if len(unresolvedStack) > 0:
      self.ForwardRequest(unresolvedIndexes, unresolvedStack, unresolvedModules, symbolicatedStack)

    return symbolicatedStack

  def LookupModule(self, pc, curModuleMap):
    memoryMapsToConsult = [curModuleMap, self.firstModuleMap]
    for data in memoryMapsToConsult:
      if data == None:
        continue
      r = data.LookupModule(pc)
      if r is not None:
        return r

    return None
