import requests
from cvss import CVSS2, CVSS3

cveTemplate = "CVE-asd-asd"

cveList = ["CVE-2020-7656", "CVE-2020-11022", "CVE-2020-11023"]

attackVectorDictionary = {"N": "N", "A" : "A", "L" : "L"}
attackComplexityDictionary = {"N": "N", "A" : "A", "L" : "L"}
privilegesDictionary = {"N":"N", "S":"L", "M":"H"}
ciaDictionary = {"C":"H", "P":"L", "N":"N"}


def convertToCVSS3(cvss2String):
	cvss3string = "CVSS:3.1/AV:A/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
	cvss2parts = cvss2String.split('/')
	av, ac, pr, c, i, a = "", "", "", "", "", ""
	for part in cvss2parts:
		subparts = part.split(":")
		if subparts[0] == "AV":
			av = attackVectorDictionary[subparts[1]]
		elif subparts[0] == "AC":
			ac = attackComplexityDictionary[subparts[1]]
		elif subparts[0] == "Au":
			pr = privilegesDictionary[subparts[1]]
		elif subparts[0] == "C":
			c = ciaDictionary[subparts[1]]
		elif subparts[0] == "I":
			i = ciaDictionary[subparts[1]]
		elif subparts[0] == "A":
			a = ciaDictionary[subparts[1]]

	cvss3string = "CVSS:3.1/AV:" + av + "/AC:" + ac + "/PR:" + pr + "/UI:N/S:U/C:" + c + "/I:" + i + "/A:" + a
	cvss3Obj = CVSS3(cvss3string)
	return cvss3Obj.clean_vector()


for cveId in cveList:
	data = requests.get("https://services.nvd.nist.gov/rest/json/cve/1.0/"+cveId)
	data = data.json()
	cveImpactObject = data["result"]["CVE_Items"][0]["impact"]

	if "baseMetricV3" in cveImpactObject:
		print (cveImpactObject["baseMetricV3"]["cvssV3"]["vectorString"] + "   ------------> " + cveId)
	elif "baseMetricV2" in cveImpactObject:
		print(convertToCVSS3(cveImpactObject["baseMetricV2"]["cvssV2"]["vectorString"]) + "   ------------> " + cveId)