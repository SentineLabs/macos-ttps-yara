// YARA rule set for detecting potential malicious TTPs in a file sample
// Author: Phil Stokes, SentinelLabs
// Date: 29 August, 2023
// Ref: https://s1.ai/BigBins-macOS

rule Stealer {
 	strings:
       		$a = "dump-generic-passwords"
		$b = "keychain-db"
       		$A = "dump-generic-passwords" base64
		$B = "keychain-db" base64
   	condition:
 		any of them
}

rule VM_Detection {
        meta:
		mitre = "T1082 System Information Discovery"
 	strings:
       		$a = "ioreg-c"
		$a1 = "ioreg -c"
                $a2 = "ioreg -l"
		$a3 = "ioreg -rd"
		$a4 = "ioreg -ad2"
		$b = "IOPlatformExpertDevice"
		$c = "IOPlatformSerialNumber"
		$d = "vmware" nocase
		$e = "parallels" nocase
		$f = "SPHardwareDataType"
		$g = "SPNetworkDataType"
		$h = "SPUSBDataType"
		$i = "sysctl hw"
		$j = "hw.model"
		$k = "machdep.cpu.brand_string"
       		$A = "ioreg-c" base64
		$A1 = "ioreg -c" base64
                $A2 = "ioreg -l" base64
		$A3 = "ioreg -rd" base64
		$A4 = "ioreg -ad2" base64
		$B = "IOPlatformExpertDevice" base64
		$C = "IOPlatformSerialNumber" base64
		$D = "vmware" base64
		$D1 = "VMware" base64
		$E = "parallels" base64
		$E1 = "Parallels" base64
		$F = "SPHardwareDataType" base64
		$G = "SPNetworkDataType" base64
		$H = "SPUSBDataType" base64
		$I = "sysctl hw" base64
		$J = "hw.model" base64
		$K = "machdep.cpu.brand_string" base64
   	condition:
 		any of them 
}

rule Evasion {
        meta:
	        mitre = "T1562 Disable or Modify Tools"
 	strings:
       		$a = "killall" 
		$b = "kill -9"
		$c = "pkill" 
		$d = "sleep"
		$e = "sleepForTimeInterval"
                $i = "debug" nocase
		$w = "waitpid"
       		$A = "killall" base64
		$B = "kill -9" base64
		$C = "pkill" base64
		$D = "sleep" base64
		$E = "sleepForTimeInterval" base64
                $I = "debug" base64
		$W = "waitpid" base64

   	condition:
 		any of them
}

rule System_Discovery {
        meta:
	        mitre = "T1082 System Information Discovery"
 	strings:
       		$a = "sw_vers" 
		$b = "spctl" 
		$c = "test-devid-status"
		$d = "csrutil"
		$e = "df -m / |"
		$f = "__kCFSystemVersionProductNameKey"
		$g = "__kCFSystemVersionProductVersionKey"
       		$A = "sw_vers" base64
		$B = "spctl" base64
		$C = "test-devid-status" base64
		$D = "csrutil" base64
		$E = "df -m / |" base64
		$F = "__kCFSystemVersionProductNameKey" base64
		$G = "__kCFSystemVersionProductVersionKey" base64
   	condition:
 		any of them
}

rule Password_Spoofing {
 	strings:
       		$a = "with hidden answer"
       		$A = "with hidden answer" base64
   	condition:
 		any of them
}

rule Privilege_Escalation {
	meta:
		mitre = ""
 	strings:
       		$a = "with administrator privileges"
		$b = "sudo" fullword 
		$b0 = "sudo -S" // read password from standard input
		$b1 = "sudoers"
		$c = "with hidden answer"
       		$A = "with administrator privileges" base64
		$B = "sudo" base64
		$B0 = "sudo -S" base64 // read password from standard input
		$B1 = "sudoers" base64
		$C = "with hidden answer" base64
   	condition:
 		any of them 
}

rule Permissions_Modification {
	meta:
		mitre = "T1222 File and Directory Permissions Modification"
 	strings:
       		$a = "chmod -R"
		$b = "chmod -x"
		$c = "chmod 7"
		$c1 = "chmod 07"
		$c2 = "_chmod"
		$d = "chown -R"
		$e = "chown root"
       		$A = "chmod -R" base64
		$B = "chmod -x" base64
		$C = "chmod 7" base64
		$C1 = "chmod 07" base64
		$C2 = "_chmod" base64
		$D = "chown -R" base64
		$E = "chown root" base64
	condition:
 		any of them
}

rule Persistence {
        meta:
                mitre = "T1053, T1543, T1569 Create or Modify System Process, TA0003 Persistence"		
 	strings:
       		$a = "crontab"
		$b = "LaunchAgents"
		$c = "LaunchDaemons"
		$d = "periodic"
		$e = "Login Items"
		$f = "launchctl load"
		$g = "launchctl start"
       		$A = "crontab" base64
		$B = "LaunchAgents" base64 
		$C = "LaunchDaemons" base64
		$D = "periodic" base64
		$E = "Login Items" base64
		$F = "launchctl load" base64
		$G = "launchctl start" base64
   	condition:
 		any of them
}

rule Bypass_Trust_Controls {
 	meta:
		mitre = "T1553 Bypass or Subvert Trust Controls" 		
 	strings:
       		$a = "xattr"  
		$b = "tccutil" 
		$c = "TCC.db"
		$d = "com.apple.quarantine"
       		$A = "xattr" base64 
		$B = "tccutil" base64
		$C = "TCC.db" base64
		$D = "com.apple.quarantine" base64
   	condition:
 		any of them
}

rule User_Discovery {
	meta:
	 	mitre = "T1033 System Owner/User Discovery"
 	strings:
       		$a = "whoami" 
		$b = "HOME"
		$c = "getenv"
       		$A = "whoami" base64 
		$B = "HOME" base64
		$C = "getenv" base64
   	condition:
 		any of them
}

rule Process_Discovery {
 	meta:
		mitre = "T1057 Process Discovery"
 	strings:
       		$a = "ps ax"
		$b = "ps -p -o"
		$c = "ps -eAo"
		$d = "ps -ef"
		$e = "ps aux"
       		$A = "ps ax" base64
		$B = "ps -p -o" base64
		$C = "ps -eAo" base64
		$D = "ps -ef" base64
		$E = "ps aux" base64

   	condition:
		any of them
}

rule File_Discovery {
 	meta:
		mitre = "T1083 File and Directory Discovery"
 	strings:
       		$a = "dirname"
		$b = "basename"
		$A = "dirname" base64
		$B = "basename" base64
   	condition:
 		any of them
}

rule Hidden_Process_Deception {
 	meta:
		mitre = ""
 	strings:
       		$a = "/.com.apple."
		$a1 = "/.google."
		$a2 = ".plist"
		$l1 = "/LaunchAgents/"
		$l2 = "/LaunchDaemons/"
       		$A = "/.com.apple." base64
		$A1 = "/.google." base64
		$A2 = ".plist" base64
		$L1 = "/LaunchAgents/" base64  
		$L2 = "/LaunchDaemons/" base64
   	condition:
 	  (2 of ($a*) or 2 of ($A*)) and (1 of ($l*) or 1 of ($L*))
}

rule TimeStomp {
 	meta:
        	mitre = "T1070 Indicator Removal on Host: Timestomp, T1036 Masquerading"
 	strings:
       		$a = "touch" fullword
		$A = "touch" base64
   	condition:
 		any of them
}

rule Unencrypted_HTTP_Protocol {
 	meta:
		mitre = "T1639.001 Exfiltration Over Unencrypted Non-C2 Protocol"
 	strings:
       		$h = "http://"
		$H = "http://" base64
		$apple = "http://www.apple.com/DTDs"
		$t = "tcp" fullword
		$t1 = "/dev/tcp"
		$T1 = "/dev/tcp" base64
   	condition:
 		any of them 
}


rule IP_Address_Pattern {
 	meta:
		mitre = "n/a"
 	strings:
       		$a = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/
   	condition:
 		any of them
}

rule Command_Line_Interpreter {
 	meta:
		mitre = "T1059 Command and Scripting Interpreter"
 	strings:
		$s1 = "/usr/bin"
		$s2 = "bash"
		$s3 = "zsh"
       		$aa = "osascript"
		$ab = "/usr/bin/osascript"
		$ac = "display dialog"
		$ad = "tell app"
		$ae = "bash -c"
		$ae0 = "bash -i"
		$ae1 = "/bin/bash"
		$ae2 = "bash" fullword
		$af = "eval" fullword
		$ag = "os.popen"
		$az = "zsh -c"
       		$aA = "osascript" base64
		$aB = "/usr/bin/osascript" base64
		$aB1 = "/usr/bin" base64
		$aC = "display dialog" base64
		$aD = "tell app" base64
		$aE = "bash -c" base64
		$aE0 = "bash -i" base64
		$aE1 = "/bin/bash" base64
		$aE2 = "bash" base64
		$aF = "eval" base64
		$aG = "os.popen" base64
   	condition:
 		 2 of ($s*) or any of ($a*)
}

rule Compile_After_Delivery {
 	meta:
		mitre = "T1027 Obfuscated File or Information: Compile After Delivery"
 	strings:
       		$a = "osacompile"
		$aA = "osacompile" base64
		$na = "NSAppleScript"
		$nb = "compileAndReturnError"
		$Na = "NSAppleScript" base64
		$Nb = "compileAndReturnError" base64


   	condition:
 		any of ($a*) or all of ($n*) or all of ($N*)
}

rule Encryption_Decryption {
 	meta:
		mitre = "T1027 Obfucated File or Information, T1140 Deobfuscate/Decode Files, T1573 Encrypted Channel: Asymmetric Cryptography"
 	strings:
		$aes = "aes_decrypt"
       		$a = "openssl enc"
		$b = "openssl md5"
		$c = "-base64 -d"
		$d = "-base64 -out"
		$e = "aes-256-cbc"
		$o = "/usr/bin/openssl"
		$AES = "aes_decrypt" base64
       		$A = "openssl enc" base64
		$B = "openssl md5" base64
		$C = "-base64 -d" base64
		$D = "-base64 -out" base64
		$E = "aes-256-cbc" base64
		$O = "/usr/bin/openssl" base64
   	condition:
 		any of them
}

rule Hide_Artifacts {
 	meta:
		mitre = "T1564 Hide Artifacts"
 	strings:
       		$a = "mktemp -d"
		$b = "mktemp -t"
		$c = "mkdir -p /tmp"
       		$A = "mktemp -d" base64
		$B = "mktemp -t" base64
		$C = "mkdir -p /tmp" base64
   	condition:
 		any of them
}

rule Command_Control {
 	meta:
		mitre = "TA0010, TA0011, T1048: Command and Control, Exfiltration"
 	strings:
		$z = "curl" fullword
       		$a = "curl -ks"
		$b = "curl -fsL"
		$c = "curl -s -L"
		$d = "curl -L -f"
		$e = "curl --connect-timeout"
		$f = "curl --retry"
		$u = "/usr/bin/curl"
       		$A = "curl -ks" base64
		$B = "curl -fsL" base64
		$C = "curl -s -L" base64
		$D = "curl -L -f" base64
		$E = "curl --connect-timeout" base64
		$F = "curl --retry" base64
		$U = "/usr/bin/curl" base64
   	condition:
 		any of them
}

rule File_Deletion {
 	meta:
		mitre = "T1070.004 File Deletion"
 	strings:
       		$a = "_rmdir"
		$b = "rm -rf"
		$c = "/bin/rm"
       		$A = "_rmdir" base64
		$B = "rm -rf" base64
		$C = "/bin/rm" base64
   	condition:
 		any of them
}

rule System_Network_Discovery {
 	meta:
		mitre = "T1016 System Network Configuration Discovery"
 	strings:
       		$a = "checkip.dyndns.org"
		$n = "/usr/sbin/networksetup"
		$n1 = "listnetworkserviceorder"
		$N = "/usr/sbin/networksetup"  base64
		$N1 = "listnetworkserviceorder" base64
   	condition:
 		any of them
}

rule Adversary_in_the_Middle {
 	meta:
		mitre = "T1557 Adversary in the Middle"
 	strings:
       		$a = "mitmproxy"
       		$A = "mitmproxy" base64
   	condition:
 		any of them
}

rule Reflective_Code_Loading {
 	meta:
		mitre = "T1620 Reflective Code Loading"
 	strings:
       		$a = "execv"
                $as = "NSAppleScript"
		$ase = "executeAndReturnError"
		$b = "fork"
		$n = "NSTask"
		$p = "NSPipe"
       		$A = "execv" base64
                $AS = "NSAppleScript" base64
		$ASE = "executeAndReturnError" base64
		$B = "fork" base64
		$N = "NSTask" base64
		$P = "NSPipe" base64
   	condition:
 		any of them
}

