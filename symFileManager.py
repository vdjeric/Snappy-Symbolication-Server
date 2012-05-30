from logging import LogTrace, LogError, LogMessage

import os
import re
import threading
import time
from bisect import bisect

# Libraries to keep prefetched
PREFETCHED_LIBS = [ "xul.pdb", "firefox.pdb" ]

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
  sCallbackTimer = None

  def __init__(self, options):
    self.sOptions = options

  def GetLibSymbolMap(self, pdbName, pdbSig, pdbAge):
    # Empty lib name means client couldn't associate frame with any lib
    if pdbName == "":
      return None

    pdbId = pdbSig + pdbAge

    # Check cache first
    libSymbolMap = None
    self.sCacheLock.acquire()
    try:
      if pdbName in self.sCache and pdbId in self.sCache[pdbName]:
        libSymbolMap = self.sCache[pdbName][pdbId]
        #print "Found existing PDB entry with " + str(libSymbolMap.entryCount) + " entries"
        self.UpdateMruList(pdbName, pdbId)
    finally:
      self.sCacheLock.release()

    if libSymbolMap is None:
      LogTrace("Need to fetch PDB file for " + pdbName + " " + pdbSig + "-" + pdbAge)

      # Guess the name of the .sym file on disk
      if pdbName[-4:] == ".pdb":
        symFileName = re.sub(r"\.[^\.]+$", ".sym", pdbName)
      else:
        symFileName = pdbName + ".sym"

      pathSuffix = os.sep + pdbName + os.sep + pdbId + os.sep + symFileName
      firefoxPath = self.sOptions['firefoxSymbolsPath'] + pathSuffix
      osPath = self.sOptions['osSymbolsPath'] + pathSuffix

      libSymbolMap = self.FetchSymbolsFromFile(firefoxPath)
      if not libSymbolMap:
        libSymbolMap = self.FetchSymbolsFromFile(osPath)
      if not libSymbolMap:
        LogTrace("No matching sym files, tried " + firefoxPath + " and " + osPath)
        return None

      LogTrace("Storing libSymbolMap under [" + pdbName + "][" + pdbId + "]")
      self.sCacheLock.acquire()
      try:
        self.MaybeEvict(libSymbolMap.GetEntryCount())
        if pdbName not in self.sCache:
          self.sCache[pdbName] = {}
        self.sCache[pdbName][pdbId] = libSymbolMap
        self.sCacheCount += libSymbolMap.GetEntryCount()
        self.UpdateMruList(pdbName, pdbId)
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

  def StopPrefetchTimer(self):
    if self.sCallbackTimer:
      self.sCallbackTimer.cancel()
      self.sCallbackTimer = None

  def PrefetchRecentSymbolFiles(self):
    global PREFETCHED_LIBS

    LogMessage("Prefetching recent symbol files")
    # Schedule next timer callback
    interval = self.sOptions['prefetchInterval'] * 60 * 60
    self.sCallbackTimer = threading.Timer(interval, self.PrefetchRecentSymbolFiles)
    self.sCallbackTimer.start()

    thresholdTime = time.time() - self.sOptions['prefetchThreshold'] * 60 * 60
    symDirsToInspect = {}
    for pdbName in PREFETCHED_LIBS:
      symDirsToInspect[pdbName] = []
      topLibPath = self.sOptions['firefoxSymbolsPath'] + os.sep + pdbName

      try:
        symbolDirs = os.listdir(topLibPath)
        for symbolDir in symbolDirs:
          candidatePath = topLibPath + os.sep + symbolDir
          mtime = os.path.getmtime(candidatePath)
          if mtime > thresholdTime:
            symDirsToInspect[pdbName].append((mtime, candidatePath))
      except Exception as e:
        LogError("Error while pre-fetching: " + str(e))

      LogMessage("Found " + str(len(symDirsToInspect[pdbName])) + " new " + pdbName + " recent dirs")

      # Only prefetch the most recent N entries
      symDirsToInspect[pdbName].sort(reverse=True)
      symDirsToInspect[pdbName] = symDirsToInspect[pdbName][:self.sOptions['prefetchMaxSymbolsPerLib']]

    # Don't fetch symbols already in cache.
    # Ideally, mutex would be held from check to insert in self.sCache,
    # but we don't want to hold the lock during I/O. This won't cause inconsistencies.
    self.sCacheLock.acquire()
    try:
      for pdbName in symDirsToInspect:
        for (mtime, symbolDirPath) in symDirsToInspect[pdbName]:
          pdbId = os.path.basename(symbolDirPath)
          if pdbName in self.sCache and pdbId in self.sCache[pdbName]:
            symDirsToInspect[pdbName].remove((mtime, symbolDirPath))
    finally:
      self.sCacheLock.release()

    # Read all new symbol files in at once
    fetchedSymbols = {}
    fetchedCount = 0
    for pdbName in symDirsToInspect:
      # The corresponding symbol file name ends with .sym
      symFileName = re.sub(r"\.[^\.]+$", ".sym", pdbName)

      for (mtime, symbolDirPath) in symDirsToInspect[pdbName]:
        pdbId = os.path.basename(symbolDirPath)
        symbolFilePath = symbolDirPath + os.sep + symFileName
        symbolInfo = self.FetchSymbolsFromFile(symbolFilePath)
        if symbolInfo:
          # Stop if the prefetched items are bigger than the cache
          if fetchedCount + symbolInfo.GetEntryCount() > self.sOptions["maxCacheEntries"]:
            #print "Can't fit " + pdbName + "/" + pdbId
            break
          fetchedSymbols[(pdbName, pdbId)] = symbolInfo
          fetchedCount += symbolInfo.GetEntryCount()
          #print "fetchedCount = " + str(fetchedCount) + "  after " + pdbName + "/" + pdbId
        else:
          LogError("Couldn't fetch .sym file symbols for " + symbolFilePath)
          continue

    # Insert new symbols into global symbol cache
    self.sCacheLock.acquire()
    try:
      # Make room for the new symbols
      self.MaybeEvict(fetchedCount)

      for (pdbName, pdbId) in fetchedSymbols:
        if pdbName not in self.sCache:
          self.sCache[pdbName] = {}

        if pdbId in self.sCache[pdbName]:
          #print pdbName, "version", pdbId, "already in cache"
          continue

        newSymbolFile = fetchedSymbols[(pdbName, pdbId)]
        self.sCache[pdbName][pdbId] = newSymbolFile
        self.sCacheCount += newSymbolFile.GetEntryCount()
        #print "Cache has " + str(self.sCacheCount) + " entries after inserting prefetched " + pdbName + "/" + pdbId

        # Move new symbols to front of MRU list to give them a chance
        self.UpdateMruList(pdbName, pdbId)

    finally:
      self.sCacheLock.release()

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

