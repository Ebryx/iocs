/*

Last Updated: 06 Feb 2019
Detection Date: 15 Jan 2019
Author: Ebryx DFIR Team
Description: Latest IOCs of skypeJob malware dropper that serves the intrusion point for APT38/FashCash by Lazarus/HiddenCobra

*/

import "pe"
import "hash" 

rule skypeJob_C2 {

    meta:
      description = "skypeJob campaign possibly APT38/Lazarus"
        author = "Ebryx DFIR Team"
        tlp = "White"
        date = "2019-01-15"

    strings:
        $ip1 = "45.32.114.96"
        $ip2 = "104.227.146.249"
        $ip3 = "2.21.242.227"
        $ip4 = "185.136.165.202"
        $domain1 = "ecombox.store"
        $domain2 = "autoif.online"
        $domain3 = "kair.xyz"
        $domain4 = "vanxuangroup.edu.vn"

    condition:
        $domain1   or  
        $domain2   or  
        $domain3   or  
        $domain4   or  
        $ip1   or  
        $ip2   or  
        $ip3   or
        $ip4
}

rule skypeJob_possible_variant_of_Ratankba_REG_TIME_script {

    meta:
      description = "skypeJob campaign possibly related to APT38/Lazarus"
        author = "Ebryx DFIR Team"
        tlp = "White"
        date = "2019-01-15"

    strings:
        $b64encoded = "FromBase64String"
        $method = "RijndaelManaged"
        $pass = "PowershellAgent"

    condition:
        $b64encoded and
        $method and
        $pass
}

rule skypeJob_ratankba_dropper {

    meta:
      description = "skypeJob campaign possibly related to APT38/Lazarus"
        author = "Ebryx DFIR Team"
        tlp = "White"
        date = "2019-01-15"

    strings:
        $temp_logfile = "tmp0914.tmp"
        $b64uid = "base64StrUID"
        $windef = "REG_WINDEF"
        $winreg = "WIN_REG"
        $elevated_service = "AutoProtect"
        $descrypto = "DESCryptoServiceProvider"
        $encrypt = "EncryptDES"
        $admin_check = "whoami /groups | findstr /c:\"S-1-5-32-544\" | findstr /c:\"Enabled group\" && goto:isadministrator"
        $bypass = "cmd.exe /c powershell.exe -ep bypass -windowstyle hidden -file '+$schedulePath+'"
        $cmd = "start-process powershell.exe -argumentlist $cmd -windowstyle hidden | out-file -filepath $job_path"
    
    condition:
        $temp_logfile and
        $b64uid and
        $windef and
        $winreg and
        $elevated_service and
        $descrypto and
        $encrypt and
        $admin_check and
        $bypass and
        $cmd
}


rule skypeJob {

    meta:
        description = "skypeJob possibly related to campaign APT38/Lazarus"
        author = "Ebryx DFIR Team"
        tlp = "White"
        date = "2019-01-15"

    condition:
        filesize < 2MB and
        hash.md5(0, filesize) == "2025d91c1cdd33db576b2c90ef4067c7"   or  
      hash.md5(0, filesize) == "5ad8143d954ebd5de6be0a40e0f65732"   or  
      hash.md5(0, filesize) == "cb29db3900204071323a940c2a9434b8"   or  
      hash.md5(0, filesize) == "c89116edebbee98f09a8d962c2c45a64"   or  
      hash.md5(0, filesize) == "c9ed87e9f99c631cda368f6f329ee27e"   or  
      hash.md5(0, filesize) == "636f8bd214d092ae3feb547599b4935e"   or  
      hash.md5(0, filesize) == "7e369b464a483fa3bb8ef08ac58e0d59"   or  
      hash.md5(0, filesize) == "8a41520c89dce75a345ab20ee352fef0"   or  
      hash.md5(0, filesize) == "586bb8024f8337459a1d1f40ff9e5c39"   or  
      hash.md5(0, filesize) == "77b7549747f940d67330f408e648dc33"   or  
      hash.md5(0, filesize) == "c47df47414d300b2fcdc36cb5ca75570"   or  
      hash.md5(0, filesize) == "b145210f4b204e482c23113f6cac57a9"   or  
      hash.md5(0, filesize) == "123a86353ebf69219fd80fca9d90dbf2"   or  
      hash.md5(0, filesize) == "5cc28f3f32e7274f13378a724a5ec33a"   or  
      hash.md5(0, filesize) == "13bbb68bcd19bf1aea0f95986d254b7b"   or  
      hash.md5(0, filesize) == "f34b72471a205c4eee5221ab9a349c55"   or  
      hash.md5(0, filesize) == "df934e2d23507a7f413580eae11bb7dc"   or  
      hash.md5(0, filesize) == "bda82f0d9e2cb7996d2eefdd1e5b41c4"   or  
      hash.md5(0, filesize) == "34404a3fb9804977c6ab86cb991fb130"   or  
      hash.md5(0, filesize) == "52ec074d8cb8243976963674dd40ffe7"   or  
      hash.md5(0, filesize) == "4c26b2d0e5cd3bfe0a3d07c4b85909a4"   or  
      hash.md5(0, filesize) == "b484b0dff093f358897486b58266d069"   or  
      hash.sha1(0, filesize) == "ec80c302c91c6caf5343cfd3fabf43b0bbd067a5"   or  
      hash.sha1(0, filesize) == "e8f0df6c44414644d37ba03a7d022e3c30181628"   or  
      hash.sha1(0, filesize) == "607ae893fad74cc39fafbbcb2ba65cec88acfaac"   or  
      hash.sha1(0, filesize) == "06441863a53212498ac9d9b43dc90a975f6accc8"   or  
      hash.sha1(0, filesize) == "943feef623db1143f4b9c957fee4c94753cfb6a5"   or  
      hash.sha1(0, filesize) == "1611b6156871e3e9be52ea79916ade46879b7d32"   or  
      hash.sha1(0, filesize) == "f631e1f49b71804ec3909558ff831e98fdcb383f"   or  
      hash.sha1(0, filesize) == "3ad86e1776018eb3743be06996d7a63963673a57"   or  
      hash.sha1(0, filesize) == "6b082f085a0e5416cc8c84779a94b375b3d98776"   or  
      hash.sha1(0, filesize) == "d71445d0fe05fe03eb4e36057a69687ea9f76bb6"   or  
      hash.sha1(0, filesize) == "a427815c5e48f23d08a72d5001da3bcaaaea9ca6"   or  
      hash.sha1(0, filesize) == "fca6d22c5ba55baf769ab07ab91db1832ff6e551"   or  
      hash.sha1(0, filesize) == "d83eee57105ba111fccd11da8dc39b6f48980ff0"   or  
      hash.sha1(0, filesize) == "32292b4e125287a6567e3879d53d0d8d82bcdf01"   or  
      hash.sha1(0, filesize) == "3aa4bc4bbb35cf068eec65460d46aec4a17097be"   or  
      hash.sha1(0, filesize) == "e8b58b9db83b4902a607559301f6985763d2647a"   or  
      hash.sha1(0, filesize) == "5ce51e3882c40961caf2317a3209831ed77c9c40"   or  
      hash.sha1(0, filesize) == "9ff715209d99d2e74e64f9db894c114a8d13229a"   or  
      hash.sha1(0, filesize) == "b345e6fae155bfaf79c67b38cf488bb17d5be56d"   or  
      hash.sha1(0, filesize) == "a0ebe36c61d4de405fe531ecf013720a3d56d5a1"   or  
      hash.sha1(0, filesize) == "157cfb98caa48c2adb3475305c88986e777d9aa3"   or  
      hash.sha1(0, filesize) == "a20ef335481c2b3a942df1879fca7762f2c69704"   or  
      hash.sha256(0, filesize) == "bed916831e8c9babfb6d08644058a61e3547d621f847c081309f616aed06c2fe"   or  
      hash.sha256(0, filesize) == "974ccadc8a128b6fcfa50c6496cf3fed0bc58ed5151623d946330975be36f0b4"   or  
      hash.sha256(0, filesize) == "e1bd6bae9d014a995c7cafd09c43f4480b907e70093cbf1c9029384bd7e14100"   or  
      hash.sha256(0, filesize) == "43a61479d9d27ba7d11f4fe128a80a7b19f0f9151eaadd654e1318c6c6007a5c"   or  
      hash.sha256(0, filesize) == "802efe9c41909354921009bd54be7dcf1ee14fcfaf62dacbcdaafbe051a711e3"   or  
      hash.sha256(0, filesize) == "0f56ebca33efe0a2755d3b380167e1f5eab4e6180518c03b28d5cffd5b675d26"   or  
      hash.sha256(0, filesize) == "bf4437e1447ad1c1ea57a5d97bd6197969f2f56c44dc97323a4520ce33d4496c"   or  
      hash.sha256(0, filesize) == "8a0e6c50a6483f2f01a458cd0cb4e485605778c42c9708b07b820968132efb76"   or  
      hash.sha256(0, filesize) == "b9662abb28b9ae8b98e568a9b805f6ee90df6dd84416fffa4af8f7465b35f02a"   or  
      hash.sha256(0, filesize) == "254560408ece689c1f2cd57bfada422371b7520495ef60599e3ae959d1a98f70"   or  
      hash.sha256(0, filesize) == "dfc145064d3d9b066a84a2aac0823e8db47ce2335d10dd105281088eaeb1b77c"   or  
      hash.sha256(0, filesize) == "fae3fddb17b0baa4bba7446e41229a0543957b22a9265cb5a0cdf9385ce5afbc"   or  
      hash.sha256(0, filesize) == "034ba72b544091684795dc1b60fb566f4081bf9c29b725f31287a94d0436e39c"   or  
      hash.sha256(0, filesize) == "18f0ad8c58558d6eb8129f32cbc2905d0b63822185506b7c3bca49d423d837c7"   or  
      hash.sha256(0, filesize) == "63e87877eb6a2b2bbba2fc6b1d13550f7d982b0c3b9ee8e2d902fc6e0774f744"   or  
      hash.sha256(0, filesize) == "a1f06d69bd6379e310b10a364d689f21499953fa1118ec699a25072779de5d9b"   or  
      hash.sha256(0, filesize) == "5d25465ec4d51c6b61947990fb148d0b1ee8a344069d5ac956ef4ea6a61af879"   or  
      hash.sha256(0, filesize) == "f3ca8f15ca582dd486bd78fd57c2f4d7b958163542561606bebd250c827022de"   or  
      hash.sha256(0, filesize) == "c6930e298bba86c01d0fe2c8262c46b4fce97c6c5037a193904cfc634246fbec"   or  
      hash.sha256(0, filesize) == "d48b211533f37e082a907d4ee3b0364e5a363f1da14f74a81b187e1ce19945a8"   or  
      hash.sha256(0, filesize) == "0e3552c8232e007f421f241ea4188ea941f4d34eab311a5c2341488749d892c7"   or  
      hash.sha256(0, filesize) == "f12db45c32bda3108adb8ae7363c342fdd5f10342945b115d830701f95c54fa9"
}

rule skypeJob_powersploit_ReflectivePEInjection_script {

    meta:
      description = "skypeJob campaign possibly related to APT38/Lazarus/Bluenoroff"
        author = "Ebryx DFIR Team"
        tlp = "White"
        date = "2019-01-15"

    strings:
        $pid = "266296"
        $virtualmem1 = "VirtualAllocEx"
        $virtualmem2 = "VirtualFreeEx"
        $virtualmem3 = "VirtualProtect"
        $virtualmem4 = "WriteProcessMemory   "
        $kernel32 = "kernel32.dll"
        $mscvrt = "msvcrt.dll"
        $advapi = "Advapi32.dll"
        $check_priv = "LookupPrivilegeValue"
        $ntdll = "NtDll.dll"
        $library = "Invoke-MemoryLoadLibrary"
        $privdebug = "SeDebugPrivilege"
        $privenabled = "SE_PRIVILEGE_ENABLED"

    condition:
        $pid or
        ($virtualmem1 and
        $virtualmem2 and
        $virtualmem3 and
        $virtualmem4 and
        $kernel32 and
        $mscvrt and
        $advapi and
        $check_priv and
        $ntdll and
        $library and
        $privdebug and
        $privenabled)
}

rule SkypeJob_PowerRatankba_malware_dropper {
   meta:
      description = "SkypeJob_PowerRatankba malware dropper"
      author = "@VK_Intel"
      type = "experimental"
      date = "2019-01-15"
      hash1 = "f12db45c32bda3108adb8ae7363c342fdd5f10342945b115d830701f95c54fa9"
   strings:
      $f0 = "ThreadProc" fullword wide ascii
      $f1 = "SendUrl" fullword wide ascii
      $ps1 = "ps1" fullword wide ascii
      $b64 = "FromBase64String" fullword wide ascii
      $pdb = "F:\\05.GenereatePDF\\CardOffer\\salary\\salary\\obj\\Release\\ApplicationPDF.pdb" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and
         filesize < 1000KB and
         pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and
         ( $f0 and $f1 and $ps1 and #b64 > 2 )
      ) or ( all of them )
}

rule SkypeJob_PowerRatankba_malware_dropper_B {
   meta:
      description = "SkypeJob_PowerRatankba_malware_dropper_B"
      author = "@VK_Intel"
      date = "2019-01-15"
      hash1 = "db8163d054a35522d0dec35743cfd2c9872e0eb446467b573a79f84d61761471"
   strings:
      $f0 = "function EncryptDES" fullword ascii
      $s0 = "$ProID = Start-Process powershell.exe -PassThru -WindowStyle Hidden -ArgumentList" fullword ascii
      $s1 = "$respTxt = HttpRequestFunc_doprocess -szURI $szFullURL -szMethod $szMethod -contentData $contentData;" fullword ascii
      $s2 = "$cmdSchedule = 'schtasks /create /tn \"ProxyServerUpdater\"" ascii
      $s3 = "/tr \"powershell.exe -ep bypass -windowstyle hidden -file " ascii
      $s4 = "C:\\\\Users\\\\Public\\\\Documents\\\\tmp' + -join " ascii
      $s5 = "$cmdResult = cmd.exe /c $cmdInst | Out-String;" fullword ascii
      $s6 = "whoami /groups | findstr /c:\"S-1-5-32-544\"" fullword ascii
   condition:
      filesize < 500KB and $f0 and 2 of ($s*) 
}
