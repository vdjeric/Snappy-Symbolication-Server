from symLogging import LogDebug, LogMessage
from symFetcher import PathFetcher, URLFetcher
from symCache import MemoryCache, DiskCache

# Singleton for .SYM file cache management
class SymFileManager:
  def __init__(self, options):
    self.sOptions = options

    self.fetchPipeline = (PathFetcher(options), URLFetcher(options))
    self.memoryCache = MemoryCache(options)
    self.diskCache = DiskCache(options)
    assert self.memoryCache.MAX_SIZE <= self.diskCache.MAX_SIZE

    self.MRU = self.diskCache.GetCacheEntries()

    if len(self.MRU) > self.diskCache.MAX_SIZE:
      evicted = self.MRU[self.diskCache.MAX_SIZE:]
      self.MRU = self.MRU[:self.diskCache.MAX_SIZE]
      self.diskCache.Evict(evicted)

    self.memoryCache.LoadCacheEntries(self.MRU, self.diskCache)

    LogMessage("MRU loaded with {} entries".format(len(self.MRU)))

  def GetLibSymbolMap(self, lib):
    try:
      index = self.MRU.index(lib)
    except ValueError:
      return self.Fetch(lib)

    if index < self.memoryCache.MAX_SIZE:
      cache = self.memoryCache
    else:
      cache = self.diskCache

    LogDebug("Loading [{}] [{}] from {}".format(lib[0], lib[1], cache.__class__))
    libSymbolMap = cache.Get(lib)

    if libSymbolMap is None:
      libSymbolMap = self.Fetch(lib)

    return libSymbolMap

  def GetLibSymbolMaps(self, libs):
    symbols = {}

    for lib in libs:
      # Empty lib name means client couldn't associate frame with any lib
      if lib[0]:
        symbol = self.GetLibSymbolMap(lib)
        if symbol:
          symbols[lib] = symbol

    newMRU = self.UpdateMRU(symbols)
    self.diskCache.Update(self.MRU, newMRU, symbols)
    self.memoryCache.Update(self.MRU, newMRU, symbols)
    self.MRU = newMRU

    LogDebug("Memory cache size = {}".format(len(self.memoryCache.sCache)))
    LogDebug("Disk cache size = {}".format(len(self.MRU)))

    return symbols

  def Fetch(self, lib):
    for fetcher in self.fetchPipeline:
      libSymbolMap = fetcher.Fetch(lib[0], lib[1])
      if libSymbolMap:
        return libSymbolMap
    else:
      LogDebug("No matching sym files, tried paths: %s and URLs: %s" % \
        (", ".join(self.sOptions["symbolPaths"]), ", ".join(self.sOptions["symbolURLs"])))
      return None

  def UpdateMRU(self, symbols):
    maxSize = self.diskCache.MAX_SIZE
    libs = symbols.keys()[:maxSize]
    libSet = set(libs)
    newMRU = libs + [x for x in self.MRU if x not in libSet]
    return newMRU[:maxSize]

