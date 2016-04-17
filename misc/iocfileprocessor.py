# -*- coding: utf-8 -*-

"""
Component of
Hades IOC Scanner
2015 Molnár Marell
Procedures for converting standard IOC file formats to scan confgiuration items. 
Scan configuration items are standard JSON files containing observables and indicators for the scanner.
The structure is partly built from: http://openioc.org/terms/Common.iocterms

"""

class scan:
    def to_JSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, 
            sort_keys=True, indent=4)

def openioctoscan(iocfile):
    
