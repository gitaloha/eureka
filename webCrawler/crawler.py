
import urllib2
import re
import urlparse
import sys
import chardet
type = sys.getfilesystemencoding()

def getLinkList(url):
    """
    download the url page, return a  tuple,including all the hrefs and the text without HTML labels
    """
    
    file = ''
    linklist = []
    try:
        file = urllib2.urlopen(url)
    except urllib2.URLError:
        print(url + " can't be connected")
    else:
        
    html = file.read()
    if not html:
        print "file.read() failed"
        return None
    code = chardet.detect(html)
    if code['encoding']:
        html = html.decode(code['encoding'], 'ignore')
    file.close()
    #get the "href" attribute in <a> label 
    srcs = re.findall(r"<a\s.*?>", html)
    for src in srcs:
        s = re.sub(r"<a\s.*?href\s*=\s*[\"\']\s*([#\w*:/{1,2}\.]+).*?>", r"\1", src)
        if s == src:
            continue
        s = s.strip()
        if s[0] == "#" or s.lower()[0:10] == "javascript" or s.lower()[0:6] == "mailto":
            continue
        if s[0] == '/':
            s = urlparse.urljoin(url, s)
        linklist.append(s)
    #get the text and get rid of HTML labels
    text = re.sub(r"<script\s+.*?>.*?</script>", '#', html, re.DOTALL)
    scripts = re.findall(r"<script\s+.*?>.*?</script>", html, re.DOTALL)
    f = open("js.txt", "w")
    [f.write(s+"\r\n") for s in scripts]
    f.close()
    f2 = open("out.txt", "w")
    f2.write(text)
    
    return linklist
    

if __name__ == "__main__":
    links = getLinkList("http://www.sina.com.cn")
    for link in links:
        print(link)
