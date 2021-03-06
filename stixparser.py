# -*- coding: utf-8 -*-

"""
Hades IOC Scanner
2015 Molnár Marell
"""

import sys
from stix.core import STIXPackage
from cybox.core import ObservableComposition
from cybox.core import Observables
import json
import os
import traceback

iocname = ""

def init():
    '''Initialize files'''
    os.mkdir(iocname)
    logfile = open(os.path.join(iocname,"conversion.log"), 'w')
    logfile.close()
    reportfile = open(os.path.join(iocname,"report.log"),'w')
    reportfile.close()
    scanfile = open(os.path.join(iocname,"scan.json"),'w')
    scanfile.close()

def log(line):
    '''Write log lines to logfile'''
    logfile = open(os.path.join(iocname,"conversion.log"), 'a')
    logfile.write(line + '\n')
    logfile.close()

def report(line):
    '''Write messages for the conversion report'''
    log(line)
    reportfile = open(os.path.join(iocname,"report.log"),'a')
    reportfile.write(line + '\n')
    reportfile.close()

def walkobservables(obs):
    '''Recursive function for checking observables in an Observables, Observable_composition, Observable tree'''
    try:
        remove = Observables()
        for x in obs.observables:
            if walkobservables(x) is None:
                remove.add(x)
        for x in remove:
            obs.remove(x)
        return obs
    except AttributeError:
        pass
    try:
        remove = Observables()
        for x in obs.observable_composition.observables:
            if walkobservables(x) is None:
                remove.add(x)
        for x in remove:
            obs.observable_composition.observables.remove(x)
        return obs
    except AttributeError:
        pass
    try:
        if not checkcompatible_observable(obs):
            return None
    except AttributeError:
       pass
    return obs

def checkcompatible_observable(obs):
    '''Function for checking whether we can process a given observable'''
    if "Custom_Properties" in obs.to_xml():
        report("Unknown custom property in object: " + str(obs.id_))
        return False
    compatible_observables = ["AccountObj",
                                "AddressObj",
                                "DeviceObj",
                                "DiskObj",
                                "DNSCacheObj",
                                "DNSQueryObj",
                                "DNSRecordObj",
                                "DomainNameObj",
                                "FileObj",
                                "HostnameObj",
                                "NetworkConnectionObj",
                                "PortObj",
                                "ProcessObj",
                                "UnixFileObj",
                                "UnixProcessObj",
                                "UnixUserAccountObj",
                                "UserAccountObj",
                                "WinComputerAccountObj",
                                "WinDriverObj",
                                "WinEventLogObj",
                                "WinExecutableFileObj",
                                "WinHandleObj",
                                "WinHookObj",
                                "WinProcessObj",
                                "WinRegistryKeyObj",
                                "WinServiceObj",
                                "WinTaskObj",
                                "WinUserAccountObj"]
    for x in compatible_observables:
        if x in obs.to_xml():
            report("Found compatible " + x + " observable with id: " + obs.id_)
            return True
    report("Unknown type: " + str(obs.object_.properties.to_xml().split('\n')[0].split(':')[0].replace('<','')) + "in object: " + str(obs.id_))
    return False

def getobservable_by_id(pkg, obs_id):
    '''Returns observable from package by id'''
    if pkg.observables:
        for x in pkg.observables:
            if obs_id in str(x._id):
                return x
    return None

def getindicator_by_id(pkg, ind_id):
    '''Returns indicator from package by id'''
    if pkg.indicators:
        for x in pkg.indicators:
            if ind_id in str(x._id):
                return x
    return None

def strip_observables(pkg_path):
    '''Strips observable from a package, support multiple structures'''
    result = Observables()
    pkg = STIXPackage.from_xml(pkg_path)
    processed = []
    for ind in pkg.indicators:
        if ind.composite_indicator_expression:
            """The indicator is a compsite structure, this references other indicators, which reference the observables..."""
            cyboxobject = ObservableComposition()
            cyboxobject.operator = str(ind.observable_composition_operator)
            for x in ind.composite_indicator_expression:
                """For every indicator in the composite list, get referenced indicator"""
                ref_ind = getindicator_by_id(pkg, str(x._idref))
                if ref_ind.observables:
                    for y in ref_ind.observables:
                        """For every referenced observable, get the object"""
                        ref_obs = getobservable_by_id(pkg, y._idref)
                        if ref_obs:
                            cyboxobject.add(ref_obs)
                            processed.append(ref_obs.id_)
            result.add(cyboxobject)
        if ind.observables:
            for x in ind.observables:
                if x is not None:
                    if x.id_ not in processed:
                        result.add(x)
                        processed.append(x.id_)
    if pkg.observables:
        for x in pkg.observables:
            if x is not None:
                if x.id_ not in processed:
                    result.add(x)
    scanfile = open(os.path.join(iocname,"scan.json"),'w')
    scanfile.write(json.dumps(walkobservables(result).to_dict(), indent=4))
    scanfile.close()

def parse(name, iocfile):
    '''Parse an iocfile, create report, create scan file'''
    try:
        global iocname
        iocname = name
        init()
    except:
        print "Error initializing"
        traceback.print_exc()
    try:
        strip_observables(iocfile)
    except:
        log("Unexpected error while creating report file")
        log(traceback.format_exc())

#parse("stuxnet", "C:\Users\Malmortius\Downloads\openioc-to-stix-master\openioc-to-stix-master\examples\stuxnet.stix.xml")
parse("PoisonIvy", "C:\Users\Malmortius\Downloads\poison_ivy-stix-1.2\Poison Ivy\\fireeye-pivy-report-with-indicators.xml")
