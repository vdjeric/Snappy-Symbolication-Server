from symLogging import LogTrace, LogError, LogMessage

import os
import re
import threading
import time
from bisect import bisect

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

# Singleton for .SYM file cache management
class SymFileManager:
  # Symbol cache data structures
  sCache = {}
  sCacheCount = 0
  sCacheLock = threading.Lock()
  sMruSymbols = []

  sOptions = {}

  def __init__(self, options):
    self.sOptions = options

  def GetLibSymbolMap(self, libName, breakpadId):
    # Empty lib name means client couldn't associate frame with any lib
    if libName == "":
      return None

    # Check cache first
    libSymbolMap = None
    self.sCacheLock.acquire()
    try:
      if libName in self.sCache and breakpadId in self.sCache[libName]:
        libSymbolMap = self.sCache[libName][breakpadId]
        self.UpdateMruList(libName, breakpadId)
    finally:
      self.sCacheLock.release()

    if libSymbolMap is None:
      LogTrace("Need to fetch PDB file for " + libName + " " + breakpadId)

      # Guess the name of the .sym file on disk
      if libName[-4:] == ".pdb":
        symFileName = re.sub(r"\.[^\.]+$", ".sym", libName)
      else:
        symFileName = libName + ".sym"

      pathSuffix = os.path.join(libName, breakpadId, symFileName)

      # Look in the symbol dirs for this .sym file
      for symbolPath in self.sOptions["symbolPaths"]:
        path = os.path.join(symbolPath, pathSuffix)
        libSymbolMap = self.FetchSymbolsFromFile(path)
        if libSymbolMap:
          break

      if not libSymbolMap:
        LogTrace("No matching sym files, tried " + str(self.sOptions["symbolPaths"]))
        return None

      LogTrace("Storing libSymbolMap under [" + libName + "][" + breakpadId + "]")
      self.sCacheLock.acquire()
      try:
        self.MaybeEvict(libSymbolMap.GetEntryCount())
        if libName not in self.sCache:
          self.sCache[libName] = {}
        self.sCache[libName][breakpadId] = libSymbolMap
        self.sCacheCount += libSymbolMap.GetEntryCount()
        self.UpdateMruList(libName, breakpadId)
        LogTrace(str(self.sCacheCount) + " symbols in cache after fetching symbol file")
      finally:
        self.sCacheLock.release()

    return libSymbolMap

  def FetchSymbolsFromFile(self, path):
    try:
      symFile = open(path, "r")
    except Exception as e:
      LogTrace("Error opening file " + path + ": " + str(e))
      return None

    LogMessage("Parsing SYM file at " + path)

    try:
      symbolMap = {}
      lineNum = 0
      publicCount = 0
      funcCount = 0
      for line in symFile:
        lineNum += 1
        if line[0:7] == "PUBLIC ":
          line = line.rstrip()
          fields = line.split(" ")
          if len(fields) < 4:
            LogTrace("Line " + str(lineNum) + " is messed")
            continue
          address = int(fields[1], 16)
          symbolMap[address] = " ".join(fields[3:])
          publicCount += 1
        elif line[0:5] == "FUNC ":
          line = line.rstrip()
          fields = line.split(" ")
          if len(fields) < 5:
            LogTrace("Line " + str(lineNum) + " is messed")
            continue
          address = int(fields[1], 16)
          symbolMap[address] = " ".join(fields[4:])
          funcCount += 1
    except Exception as e:
      LogError("Error parsing SYM file " + path)
      return None

    logString = "Found " + str(len(symbolMap.keys())) + " unique entries from "
    logString += str(publicCount) + " PUBLIC lines, " + str(funcCount) + " FUNC lines"
    LogTrace(logString)

    return SymbolInfo(symbolMap)

  def PrefetchRecentSymbolFiles(self):
    # TODO: reimplement this
    LogMessage("Finished prefetching recent symbol files")

  def UpdateMruList(self, pdbName, pdbId):
    libId = (pdbName, pdbId)
    if libId in self.sMruSymbols:
      self.sMruSymbols.remove(libId)
    self.sMruSymbols.insert(0, libId)

  def MaybeEvict(self, freeEntriesNeeded):
    maxCacheSize = self.sOptions["maxCacheEntries"]
    LogTrace("Cache occupancy before MaybeEvict: " + str(self.sCacheCount) + "/" + str(maxCacheSize))
    #print "Current MRU: " + str(self.sMruSymbols)
    #print "Maybe evicting to make room for ", freeEntriesNeeded, " new entries"

    if self.sCacheCount == 0 or self.sCacheCount + freeEntriesNeeded <= maxCacheSize:
      # No need to lock mutex here, this doesn't need to be 100%
      #print "Sufficient room for new entries, no need to evict"
      return

    # If adding the new entries would exceed the max cache size,
    # evict so that cache is at 70% capacity after new entries added
    numOldEntriesAfterEvict = max(0, (0.70 * maxCacheSize) - freeEntriesNeeded)
    numToEvict = self.sCacheCount - numOldEntriesAfterEvict

    #print "Evicting: " + str(numToEvict)

    # Evict symbols until evict quota is met, starting with least recently used
    for (pdbName, pdbId) in reversed(self.sMruSymbols):
      if numToEvict <= 0:
        break

      evicteeCount = self.sCache[pdbName][pdbId].GetEntryCount()
      #print "Evicting symbols at " + pdbName + "/" + pdbId + ": " + str(evicteeCount) + " entries"

      del self.sCache[pdbName][pdbId]
      self.sCacheCount -= evicteeCount
      self.sMruSymbols.pop()

      numToEvict -= evicteeCount

    #print "MRU after: " + str(self.sMruSymbols)
    LogTrace("Cache occupancy after MaybeEvict: " + str(self.sCacheCount) + "/" + str(maxCacheSize))

