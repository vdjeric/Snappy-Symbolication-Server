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

class SymbolicationRequest:
  def __init__(self, symFileManager, rawRequest):
    self.Reset()
    self.symFileManager = symFileManager
    self.ParseRequest(rawRequest)

  def Reset(self):
    self.symFileManager = None
    self.isValidRequest = False
    self.memoryMap = {}
    self.stackPCs = []
    self.sortedModuleAddresses = []
    self.addressToModule = {}
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
          LogTrace("Invalid stack address: " + str(pc))
          return
        cleanStack.append(pc)

      # Check memory map is well-formatted
      cleanMemoryMap = []
      for module in rawRequest["memoryMap"]:
        if not isinstance(module, list) or len(module) != 6:
          LogTrace("Entry in memory map is not a 6 item list: " + str(module))
          return

        [startAddress, libName, libSize, pdbAge, pdbSig, pdbName] = module

        if isinstance(startAddress, basestring):
          startAddress = int(startAddress, 16)
        if not isinstance(startAddress, (int, long)) or startAddress < 0:
          LogTrace("Bad start address format: " + str(startAddress))
          return

        if not isinstance(libName, basestring) or not gLibNameRE.match(libName):
          LogTrace("Bad library name: " + str(libName))
          return

        if isinstance(pdbSig, basestring):
          matches = gPdbSigRE.match(pdbSig)
          if matches:
            pdbSig = "".join(matches.groups()).upper()
          elif gPdbSigRE2.match(pdbSig):
            pdbSig = pdbSig.upper()
          else:
            LogTrace("Bad PDB signature: " + pdbSig)
            return
        else:
          LogTrace("Bad PDB signature: " + str(pdbSig))
          return

        if isinstance(libSize, basestring):
          libSize = int(libSize)
        if not isinstance(libSize, (int, long)) or int(libSize) < 0:
          LogTrace("Bad PDB size: " + str(libSize))
          return

        if isinstance(pdbAge, basestring):
          pdbAge = int(pdbAge)
        if not isinstance(pdbAge, (int, long)) or int(pdbAge) < 0:
          LogTrace("Bad PDB age: " + str(pdbAge))
          return
        pdbAge = (hex(pdbAge)[2:]).lower()

        if not isinstance(pdbName, basestring) or not gLibNameRE.match(pdbName):
          LogTrace("Bad PDB name: " + str(pdbName))
          return

        cleanMemoryMap.append([startAddress, libName, libSize, pdbAge, pdbSig, pdbName])

      # Check if this request has been forwarded from another SymbolicationServer
      if "forwarded" in rawRequest:
        if not isinstance(rawRequest["forwarded"], (int, long)):
          LogTrace("Invalid 'forwards' field: " + str(rawRequest["forwarded"]))
          return
        self.forwardCount = rawRequest["forwarded"]

      self.stackPCs = cleanStack
      self.memoryMap = cleanMemoryMap

    except Exception as e:
      LogTrace("Exception while parsing request: " + str(e))
      return

    self.isValidRequest = True

  def ForwardRequest(self, indexes, stack, modules, symbolicatedStack):
    LogTrace("Forwarding " + str(len(stack)) + " PCs for symbolication")

    try:
      url = self.symFileManager.sOptions["remoteSymbolServer"]
      requestObj = [{ "stack": stack, "memoryMap": modules, "forwarded": self.forwardCount + 1 }]
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

  def Symbolicate(self, firstRequest):
    self.sortedModuleAddresses = []
    self.moduleAddressToMap = {}

    # Check if we should forward requests when required sym files don't exist
    shouldForwardRequests = False
    if self.symFileManager.sOptions["remoteSymbolServer"] and self.forwardCount < MAX_FORWARDED_REQUESTS:
      shouldForwardRequests = True

    # Build up structures for fast lookup of address -> module
    for module in self.memoryMap:
      startAddress = module[0]
      self.sortedModuleAddresses.append(startAddress)
      self.addressToModule[startAddress] = module

    self.sortedModuleAddresses = sorted(self.sortedModuleAddresses)

    # Symbolicate each PC
    pcIndex = -1
    symbolicatedStack = []
    missingSymFiles = []
    unresolvedIndexes = []
    unresolvedStack = []
    unresolvedModules = []
    for pc in self.stackPCs:
      pcIndex += 1

      module = self.LookupModule(pc, firstRequest)
      if module == None:
        LogTrace("Couldn't find module for PC: " + str(pc))
        symbolicatedStack.append("???")
        continue

      [startAddress, libName, libSize, pdbAge, pdbSig, pdbName] = module


      # Don't look for a missing lib multiple times in one request
      if (pdbName, pdbSig, pdbAge) in missingSymFiles:
        if shouldForwardRequests:
          unresolvedIndexes.append(pcIndex)
          unresolvedStack.append(pc)
        symbolicatedStack.append("??? (in " + libName + ")")
        continue

      functionName = None
      libSymbolMap = self.symFileManager.GetLibSymbolMap(pdbName, pdbSig, pdbAge)
      if libSymbolMap:
        functionName = libSymbolMap.Lookup(pc - startAddress)
      else:
        if shouldForwardRequests:
          unresolvedIndexes.append(pcIndex)
          unresolvedStack.append(pc)
          unresolvedModules.append(module)
        missingSymFiles.append((pdbName, pdbSig, pdbAge))

      if functionName == None:
        functionName = "???"
      symbolicatedStack.append(functionName + " (in " + libName + ")")

    # Ask another server for help symbolicating unresolved addresses
    if len(unresolvedStack) > 0:
      self.ForwardRequest(unresolvedIndexes, unresolvedStack, unresolvedModules, symbolicatedStack)

    return symbolicatedStack

  def LookupModule(self, pc, firstRequest):
    memoryMapsToConsult = [self, firstRequest]
    for data in memoryMapsToConsult:
      if data == None:
        continue
      index = bisect(data.sortedModuleAddresses, pc) - 1
      if index >= 0:
        # It's a hit, sanity check now
        moduleStart = data.sortedModuleAddresses[index]
        module = data.addressToModule[moduleStart]
        moduleEnd = moduleStart + module[2] - 1
        if moduleStart <= pc and pc <= moduleEnd:
          return module
        else:
          #print "Bug or bad request!"
          continue

    return None
