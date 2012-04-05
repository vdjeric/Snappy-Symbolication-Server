from logging import LogTrace, LogError, LogMessage
import symFileManager

import re
from bisect import bisect

# Precompiled regex for validating lib names
gLibNameRE = re.compile("[0-9a-zA-Z_+\-\.]*$") # Empty lib name means client couldn't associate frame with any lib
gPdbSigRE = re.compile("{([0-9a-fA-F]{8})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{12})}$")
gPdbSigRE2 = re.compile("[0-9a-fA-F]{32}$")

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

      self.stackPCs = cleanStack
      self.memoryMap = cleanMemoryMap

    except Exception as e:
      LogTrace("Exception while parsing request: " + str(e))
      return True

    self.isValidRequest = True

  def Symbolicate(self, firstRequest):
    self.sortedModuleAddresses = []
    self.moduleAddressToMap = {}

    # Build up structures for fast lookup of address -> module
    for module in self.memoryMap:
      startAddress = module[0]
      self.sortedModuleAddresses.append(startAddress)
      self.addressToModule[startAddress] = module

    self.sortedModuleAddresses = sorted(self.sortedModuleAddresses)

    # Symbolicate each PC
    symbolicatedStack = []
    missingSymFiles = []
    for pc in self.stackPCs:
      module = self.LookupModule(pc, firstRequest)
      if module == None:
        LogTrace("Couldn't find module for PC: " + str(pc))
        symbolicatedStack.append("???")
        continue

      [startAddress, libName, libSize, pdbAge, pdbSig, pdbName] = module


      if (pdbName, pdbSig, pdbAge) in missingSymFiles:
        # Don't look for a missing lib multiple times in one request
        symbolicatedStack.append("??? (in " + libName + ")")
        continue

      functionName = None
      libSymbolMap = self.symFileManager.GetLibSymbolMap(pdbName, pdbSig, pdbAge)
      if libSymbolMap:
        functionName = libSymbolMap.Lookup(pc - startAddress)
      else:
        missingSymFiles.append((pdbName, pdbSig, pdbAge))

      if functionName == None:
        functionName = "???"
      symbolicatedStack.append(functionName + " (in " + libName + ")")

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
