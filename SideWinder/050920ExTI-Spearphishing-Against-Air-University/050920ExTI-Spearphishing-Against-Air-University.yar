import "pe"
rule sidewinder_stage1_dropper: APT_SideWinder {    
    meta:
        author = " Ebryx DFIR"
        date = "14-05-2020"
        description = "Detects SideWinder’s stage-1 JavaScript dropper"
        tlp = "Green"
    strings:
        $enum1 = "finally{window.close()" fullword
        $enum2 = "fileEnum.moveFirst()" fullword
        $enum3 = "GetFolder"
        $enum4 = "GetSpecialFolder"
        $com1 = "<script"
        $com2 = "javascript"
        $com3 = "</script>"
        
    condition:
        filesize <= 323KB and (2 of ($com*) and 3 of ($enum*))
}

rule sidewinder_linkzip_dropped_dll : APT_SideWinder {
    meta:
        author = "Ebryx DFIR"
        date = "14-05-2020"
        description = "Detects LinkZip.dll exploit generator by James Forshaw"
        tlp = "Green"
    strings:
        $str1 = "James Forshaw 2017" fullword ascii
        $str2 = "LegalCopyrightCopyright"
        $str3 = "OriginalFilename" wide
        $str4 = "mscoree.dll"
        $str5 = "LinkZip" ascii
        $str6 = "WebRequest"
        $str7 = "'System.Reflection.Assembly Load(Byte[])" ascii
        $str8 = "mshta.exe" wide
        $str9 = "File-not-Written" wide
    condition:
        filesize <= 10KB and (5 of ($str*)) and uint16be(0) == 0x4D5A
}

rule sidewinder_stinstaller_dropped_dll : APT_SideWinder {
    meta:
        author = "Ebryx DFIR"
        date = "14-05-2020"
        description = "Detects StInstaller.dll which acts as a stage-II downloader"
        tlp = "Green"
    strings:
        $str1 = "OriginalFilename" wide
        $str2 = "mscoree.dll"
        $str3 = "StInstaller" ascii
        $str4 = "Duser.dll"
        $str5 = "hijackdllname" fullword ascii
        $str6 = "v2.0.50727"
        $str7 = "Already installed" fullword wide
        $str8 = "'System.Reflection.Assembly Load(Byte[])" ascii
        $str9 = "File-not-Written" wide
    condition:
        filesize <= 10KB and (5 of ($str*)) and uint16be(0) == 0x4D5A
}

rule sidewinder_pdf_doc_spearphishing : APT_SideWinder {
    meta:
        author = "Ebryx DFIR"
        date = "14-05-2020"
        description = "Detects .lnk file sent in email containing the command to contact C2 domain"
        tlp = "Green"
    strings:
        $str1 = "cftmo.exe"
        $str2 = "user-pc"
        $str3 = "C:\\Windows\\System32\\"
        $str4 = {6D 00 73 00 48 00 74 00 61}
    condition:
        filesize <= 297KB and all of them
}

