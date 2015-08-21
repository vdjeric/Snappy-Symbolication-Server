import os
import urllib2
import urlparse
import contextlib
import gzip
from StringIO import StringIO
from symLogging import LogDebug, LogMessage
from symParser import ParseSymbolFile
from symUtil import GetSymbolFileName

class SymbolFetcher(object):
  def __init__(self, options):
    self.sOptions = options

  # Fetch a symbol
  def Fetch(self, libName, breakpadId):
    pass

class PathFetcher(SymbolFetcher):
  def __init__(self, options):
    super(PathFetcher, self).__init__(options)

  def Fetch(self, libName, breakpadId):
    LogDebug("Fetching [{}] [{}] in local paths".format(libName, breakpadId))
    symFileName = GetSymbolFileName(libName)
    pathSuffix = os.path.join(libName, breakpadId, symFileName)
    for symbolPath in self.sOptions["symbolPaths"]:
      path = os.path.join(symbolPath, pathSuffix)
      libSymbolMap = self.FetchSymbolsFromFile(path)
      if libSymbolMap:
        return libSymbolMap
    else:
      return None

  def FetchSymbolsFromFile(self, path):
    try:
      with open(path, "r") as symFile:
        LogMessage("Parsing SYM file at " + path)
        return ParseSymbolFile(symFile)
    except Exception as e:
      LogDebug("Error opening file " + path + ": " + str(e))
      return None

class URLFetcher(SymbolFetcher):
  def __init__(self, options):
    super(URLFetcher, self).__init__(options)

  def Fetch(self, libName, breakpadId):
    LogDebug("Fetching [{}] [{}] in remote URLs".format(libName, breakpadId))
    symFileName = GetSymbolFileName(libName)
    urlSuffix = "/".join([libName, breakpadId, symFileName])
    for symbolURL in self.sOptions["symbolURLs"]:
      url = urlparse.urljoin(symbolURL, urlSuffix)
      libSymbolMap = self.FetchSymbolsFromURL(url)
      if libSymbolMap:
        return libSymbolMap
    else:
      return None

  def FetchSymbolsFromURL(self, url):
    try:
      with contextlib.closing(urllib2.urlopen(url)) as request:
        if request.getcode() != 200:
          return None
        headers = request.info()
        contentEncoding = headers.get("Content-Encoding", "").lower()
        if contentEncoding in ("gzip", "x-gzip", "deflate"):
          data = request.read()
          # We have to put it in a string IO because gzip looks for
          # the "tell()" file object method
          request = StringIO(data)
          try:
            with gzip.GzipFile(fileobj=request) as f:
              request = StringIO(f.read())
          except Exception:
            request = StringIO(data.decode('zlib'))

        LogMessage("Parsing SYM file at " + url)
        return ParseSymbolFile(request)
    except Exception as e:
      LogDebug("Error opening URL " + url + ": " + str(e))
      return None

