from BeautifulSoup import BeautifulSoup
import urllib2,sys
target=sys.argv[1]
def Spider(link):    #our spidering script
   f = urllib2.urlopen(link)
   soup = BeautifulSoup(f.read())
   for link in soup.find_all('a'):
      a=link.get('href')
      if a.startswith('/'):
         a=target+a
      yield a
for i in Spider(target):
   try:
      print i
      for i in Spider(i):
         print i
         for i in Spider(i):
            print i
   except:
      print "Above URL is broken or JavaScript."
      pass
