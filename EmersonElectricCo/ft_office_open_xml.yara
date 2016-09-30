// References:
// http://www.garykessler.net/library/file_sigs.html
// https://issues.apache.org/jira/browse/TIKA-257

rule ft_office_open_xml
{
   meta:
      author = "Jason Batchelor"
      company = "Emerson"
      lastmod = "20140915"
      desc = "Simple metadata attribute indicative of Office Open XML format. Commonly seen in modern office files."

   strings:
      $OOXML = "[Content_Types].xml"

   condition:
      $OOXML at 30
}

