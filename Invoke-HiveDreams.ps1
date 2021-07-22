<#
    .SYNOPSIS
        A capability to identify and remediate CVE-2021-36934, which enables a standard user to be able to retrieve the SAM, Security, and Software Registry hives in Windows 10 version 1809 or newer. 

        The vulnerability was discovered by @jonasLyk.

    .EXAMPLE
        PS C:\> .\Invoke-HiveDreams.ps1
        
    .NOTES  
        File Name      : Invoke-HiveDreams.ps1
        Version        : v.0.2
        Author         : @WiredPulse
        Created        : 22 Jul 21
#>

function Test-Administrator {
    # Tests to make sure the user is an administrator
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function check{
    if(([environment]::OSVersion.Version).build -lt 17763){
        Write-Host -ForegroundColor red "[-] System is not susceptible to CVE-2021-36934"
        pause
        break
    }
    else{
        Write-Host -ForegroundColor yellow "[+] " -NoNewline; Write-Host -ForegroundColor green "System is a vulnerable version of Windows"
        if((get-acl c:\windows\system32\config\sam).Access |where-object{$_.filesystemrights -like "*read*" -and $_.identityreference -like "*BUILTIN\Users*" -and $_.accesscontroltype -eq "allow"}){
            Write-Host -ForegroundColor yellow "[+] " -NoNewline; Write-Host -ForegroundColor green "Registry hives have Read/Execute rights for BUILTIN/Users"
        }
        else{
            Write-Host -ForegroundColor red "[-] Registry hives don't have improper permissions"
            pause
            main
        }
        if(Get-CimInstance -Namespace root/cimv2 -ClassName win32_shadowcopy){
            Write-Host -ForegroundColor yellow "[+] " -NoNewline; Write-Host -ForegroundColor green "System contains Volume Shadow Copies that could be abused"
            pause
        }
        else{
            Write-Host -ForegroundColor red "[-] System doesn't have any Volume Shadow Copies"
            pause
            main
        }
    }
}

function remediate{
    Write-host -ForegroundColor red "WARNING: This will make the following changes to your system if they exist"
    Write-host -ForegroundColor red "* - Remove improper permissions for the SAM, System, and Software hive"
    Write-host -ForegroundColor red "* - Remove all Volume Shadow Copies"
    Write-host " " 
    Write-host -ForegroundColor green "[1] Continue"
    Write-host -ForegroundColor green "[2] Exit"
    write-host " "
    $q2 = Read-Host " "
    write-host " "
    if($q2 -eq 1){
        Invoke-Command -ScriptBlock {icacls C:\Windows\system32\config\*.* /inheritance:e | out-null}
        if(-not((get-acl c:\windows\system32\config\sam).Access |where-object{$_.filesystemrights -like "*read*" -and $_.identityreference -like "*BUILTIN\Users*" -and $_.accesscontroltype -eq "allow"})){
            Write-Host -ForegroundColor yellow "[+] " -NoNewline; Write-Host -ForegroundColor green "Permissions for the SAM, System, and Software Hive have been fixed"
        }
        if(Get-CimInstance -Namespace root/cimv2 -ClassName win32_shadowcopy){
            Write-Host -ForegroundColor yellow "[+] " -NoNewline; Write-Host -ForegroundColor green "Volume Shadow Copies found"
            Write-Host -ForegroundColor yellow "[+] " -NoNewline; Write-Host -ForegroundColor green "Deleting Volume Shadow Copies"
            vssadmin.exe Delete Shadows /All /Quiet
            if(-not(Get-CimInstance -Namespace root/cimv2 -ClassName win32_shadowcopy)){
                Write-Host -ForegroundColor yellow "[+] " -NoNewline; Write-Host -ForegroundColor green "Volume Shadow Copies are deleted"
            }
        }
    }
    elseif($q2 -eq 2){
        break
    }
}

function main{
    Test-Administrator
    write-host " "
    write-host "###############################################################################################" -ForegroundColor Yellow
    write-host "_____                 _               _    _ _           _____                           " -ForegroundColor Cyan    
    write-host "|_   _|               | |             | |  | (_)         |  __ \                              " -ForegroundColor Cyan
    write-host "  | |  _ ____   _____ | | _____ ______| |__| |___   _____| |  | |_ __ ___  __ _  _ __ ___  ___ " -ForegroundColor Cyan
    write-host "  | | | '_ \ \ / / _ \| |/ / _ \______|  __  | \ \ / / _ \ |  | | '__/ _ \/ _`  |  '_ ` _ \/ __| " -ForegroundColor Cyan
    write-host " _| |_| | | \ V / (_) |   <  __/      | |  | | |\ V /  __/ |__| | | |  __/ (_| | | | | | \__ \" -ForegroundColor Cyan
    write-host "|_____|_| |_|\_/ \___/|_|\_\___|      |_|  |_|_| \_/ \___|_____/|_|  \___|\__,_|_| |_| |_|___/" -ForegroundColor Cyan
    write-host " "                                                                     
    write-host "###############################################################################################" -ForegroundColor Yellow
    write-host " "
    write-host "[1] " -ForegroundColor Cyan -NoNewline; write-host "Vulnerability Check"
    write-host "[2] " -ForegroundColor Cyan -NoNewline; write-host "Remediate Vulnerability"
    write-host "[3] " -ForegroundColor Cyan -NoNewline; write-host "Exit"
    $q = read-host " "
    write-host " "
    if($q -eq 1){
        check
    }
    elseif($q -eq 2){
        remediate
    }
    else{
        break
    }
}

main