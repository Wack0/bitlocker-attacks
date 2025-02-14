# BitLocker Attacks

A list of public attacks on BitLocker. Any public attack with the *potential* to attack BitLocker but where the exact method is still not public (like baton drop) is out of scope.

Most of the attacks are for where the VMK is sealed by TPM only, which is the default setting, and is what [automatic BitLocker](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-bitlocker) uses alongside recovery key escrow to a Microsoft account.

By default, starting from Windows 8, Secure Boot integrity validation is used if Secure Boot is enabled.

If you must seal the VMK by TPM only, the most secure configuration for this is to use legacy integrity validation with PCRs 0, 2, 4, 7, 11 (and also to keep your system fully updated).  
Please note that this will only protect against software attacks.

## Contents

* [Hardware attacks](#hardware-attacks)
* [Software attacks](#software-attacks)

## Hardware attacks

Hardware attacks are typically only useful for when the attacker has physical access to a system where the VMK is sealed by TPM only.

| Summary | Description | Fixed | Public disclosure timeframe | Discovered by |
| ---     | ---         | ---   | ---                         | ---           |
| TPM sniffing: bootmgr communicates with TPM in the clear | Windows Boot Manager communicates with the TPM in the clear, so if a separate TPM chip on the LPC bus is used (ie, not fTPM, or "Pluton"/HSP), a logic analyser on that bus can be used to dump the VMK.<br><br>See also [blog post from Pulse Security](https://pulsesecurity.co.nz/articles/TPM-sniffing), [LPC sniffer Verilog code](https://github.com/denandz/lpc_sniffer_tpm).  | None, but firmware TPMs were not vulnerable anyway | [January 2019](https://web.archive.org/web/20190125001757/https://twitter.com/marcan42/status/1080869868889501696) | marcan |
| Hardware debugger: some systems do not measure into PCR7 before enabling a hardware debugger | [The TCG EFI Platform Specification for TPM](https://trustedcomputinggroup.org/wp-content/uploads/TCG_EFI_Platform_1_22_Final_-v15.pdf) (section 6.4) includes the following: <br><br>"If the platform provides a firmware debugger mode which may be used prior to the UEFI environment or if the platform provides a debugger for the UEFI environment, then the platform SHALL extend an EV_EFI_ACTION event into PCR[7] before allowing use of the debugger"<br><br>Some systems do not perform this measurement before enabling some hardware debuggers (like Intel DCI).<br>Therefore on such a vulnerable system, a Secure Boot bypass (physical access would allow for at least two with Secure Boot still enabled) or hardware attack (writing to SPI flash directly) can be used to enable the hardware debugger; setting a breakpoint (for example) inside `bootmgr!FvebUnsealCallback` can then allow for dumping the VMK. See also [this article from Digital Forensics Research Conference Europe 2023](https://www.sciencedirect.com/science/article/pii/S266628172300015X). | None, for vulnerable systems.<br><br>An exact list of vulnerable systems is unknown. | March 2023 | Brazilian Federal Police |
| fTPM glitching: code execution via glitching to compromise fTPM state entirely | If an on-SoC processor/microcontroller that implements an fTPM is vulnerable to glitching such that code execution can be obtained early in boot, the entire fTPM state can be compromised, leading to VMK dumping (etc). See also [the research article](https://arxiv.org/abs/2304.14717), [payloads/etc for AMD PSP](https://github.com/PSPReverse/ftpm_attack) | IntelME: [November 2021 / Alder Lake](https://www.theregister.com/2022/08/12/intel_ups_protection_against_chip/)<br><br>AMD: unknown, none?<br><br>Others (ARM64, ARMv7, etc): unknown | April 2023 | Hans Niklas Jacob, Christian Werling, Robert Buhren, Jean-Pierre Seifert of Technische Universit ät Berlin - SecT |

## Software attacks

Software attacks are typically vulnerabilities in `bootmgr`, or some other boot application where exploitation is possible with derived BitLocker keys in memory for an arbitrary volume.  
Where code execution can be obtained inside a boot application, it may be possible for an "evil cleaner" attacker to install a bootkit which itself will run with derived keys in memory (or when keys can still be derived), and thus compromise a system where a password or startup key is used instead of or in addition to a TPM.

| Summary | Description | Fixed | Public disclosure timeframe | Discovered by |
| ---     | ---         | ---   | ---                         | ---           |
| Boot environment does not wipe previous keytable when creating a new one | The boot library initialisation function has a set of flags passed to it.<br><br>If bit 7 is set (which is the case for at least bootmgr), any existing key table is ignored, and a new one created.<br><br>The existing key table is not wiped, and remains in memory.<br><br>This allows for an attacker to load bootmgr with arbitrary `osdevice`, then either exploit bootmgr to get code execution, or use RS2+ bootmgr (to ensure only one Secure Boot Policy is present) to load WinPE and use a known vulnerable driver, to find and dump the keytable.<br><br>The use of legacy integrity validation prevents this attack from working, due to the boot application allowlist in BitLocker partition metadata. | Mitigated in January 2022 (by preventing loading bootmgr in most cases).<br><br>Fixed in March 2023 with build 25330 (existing keytable will be mapped and wiped before creating a new one).<br><br>**A downgrade attack would still work to exploit this vulnerability.** | August 2022 (with baton drop); discovered in January 2022. | Rairii |
| Legacy integrity validation implemented associated options incorrectly | **Legacy integrity validation affected (where vulnerable bootmgr is used), secure boot integrity validation not affected at all**<br><br>BitLocker legacy integrity validation walks through all boot options, and either ensures they exist, ensures any unknown options do NOT exist, or ensures they are unchanged by hashing them.<br><br>The original implementation attempted to also walk through associated options, but used the incorrect offset to do so.<br><br>This would allow for crafting a BCD that contained boot options invisible to BitLocker legacy integrity validation.<br><br>Many dangerous options here, in particular `debug`, can lead to BitLocker key table dumping.<br><br>Fixed by using the correct offset when walking through associated options. This bug is CVE-2022-29127. | May 2022 | June 2022 (at emfcamp, thanks to bindiffing) | Matt Wesemann of Microsoft (WDG) |
| [dangerous association](#dangerous-association): Legacy integrity validation implemented associated options incorrectly (part 2) | **Legacy integrity validation affected (where vulnerable bootmgr is used), secure boot integrity validation not affected at all**<br><br>The fix for the previous vuln was incorrect and only checked one level of associated options, whereas code that used the boot options would recurse.<br><br>This would allow for crafting a BCD that contained boot options invisible to BitLocker legacy integrity validation.<br><br>See also [the public disclosure](https://haqueers.com/@Rairii/109439636170607042).<br><br>Fixed by recursing into associated options like other code does. This bug is CVE-2022-22048. | July 2022 | December 2022; discovered in May 2022 when bindiffing previous patch | Rairii |
| [bitpixie](#bitpixie): PXE soft reboot does not wipe derived bitlocker keys from memory | **Only exploitable on UEFI systems (not legacy BIOS, or CSM). Legacy integrity validation affected (where vulnerable bootmgr is used), secure boot integrity validation affected**<br><br>PXE soft reboot is allowed when booting from network, and just does `BS->LoadImage()` and `BS->StartImage()`.<br><br>Derived BitLocker keys are still in memory at the time `BS->StartImage` is called.<br><br>They can then be dumped from memory.<br><br>In addition: BitLocker keys are derived very early into loading a boot application. If loading the PE from disk failed, integrity validation is not performed and derived keys remain in memory.<br><br>A PXE soft reboot can then be performed, thus this bypasses legacy integrity validation too.<br><br>See also [the public disclosure](https://haqueers.com/@Rairii/109817927668949732).<br><br>Fixed by wiping bitlocker keytables in `bootmgr!BlNetSoftReboot` before calling `bootmgr!PxeSoftReboot`. This bug is CVE-2023-21563. | November 2022 (build 25236); January 2023 (backport)<br><br>Where Secure Boot integrity validation is used, **a downgrade attack would still work to exploit this vulnerability.**  | February 2023, discovered in August 2022 | Rairii |
| [push button decrypt](#push-button-decrypt): reset in WinRE can be interrupted during decrypt, enabling attacker to get a shell to disable key protectors | **Windows Server is not vulnerable due to not supporting the reset feature. Legacy integrity validation and secure boot integrity validation affected, where vulnerable winre image is used**<br><br>When booting to a system's WinRE, keys are derived for the associated osvolume. These keys are allowed to stay in memory when doing a push button reset (with data removal).<br><br>Starting a "just remove my files" reset will start decrypting the drive at ~98% completion.<br><br>Rebooting at this point will cause a reboot into winre which will show an error and a button which reboots.<br><br>After rebooting, windows setup is launched into an upgrade screen. `Shift+F10` to get a shell works here.<br><br>A shell here is enough to pause decryption and remove all key protectors, the plaintext VMK can then be used to decrypt the FVEK which can be used with a previously made disk image.<br><br>Fixed by requiring a BitLocker recovery key before a reset. This bug is CVE-2022-41099. | November 2022 (winre image must be patched manually) | May 2023 | Unknown |
| [dubious disk](https://wack0.github.io/dubiousdisk/): arbitrary code execution in the context of the boot environment | Exploitation of this bug or its variants achieves arbitrary code execution in the context of the boot environment, therefore allowing for either derivation of bitlocker keys (with arbitrary code execution in bootmgr) or dumping of the bitlocker keytable (with arbitrary code execution in some other boot application).<br><br>This bug and variants of it are CVE-2022-30203, CVE-2023-21560, CVE-2023-28269, CVE-2023-28249, (unknown), and CVE-2024-38065. | Various fixes between July 2022 and July 2024. **A downgrade attack would still work to exploit these vulnerabilities.** | June 2024 (public writeup, missing the variant fixed in July 2024); originally discovered in August 2021 and exploited between January and March 2022 | Rairii |
| break out in hives: systemdatadevice element causes winload to use attacker specified SYSTEM hive | Starting from Windows 10 (th1), support for the `systemdatadevice` element was added to winload. If present, winload reads the SYSTEM hive from this device instead of osdevice.<br><br>Thus, attacker can grab SYSTEM hive from WinPE, modify Setup!CmdLine to cmd.exe, and cause winload to use this hive when booting WinRE.<br><br>When booting WinRE after this, a SYSTEM shell will open with the bitlocker keys in memory for osvolume if they were derived; thus, bitlocker bypass.<br><br>Fixed by removing the ability to load SYSTEM hive from systemdatadevice. This bug is CVE-2024-20666. | January 2024 (winre image must be patched manually) | February 2025; discovered in March 2023 | Rairii |
| break out in hives 2: alternative method for exploiting systemdatadevice element, usable with a downgrade attack | The fix for break out in hives updated winload.<br><br>However, earlier (unfixed) revisions of winload can **potentially** still run to boot its major version of Windows (may not work in practise for every version).<br><br>Thus, attacker can bring in an old winload, modify BCD to boot from it, and repeat the attack, however a different exploitation method must be used.<br><br>**The `winpe` element must be set in BCD (if it is not, the SYSTEM hive in the bitlocker encrypted osvolume will get corrupted!)**<br><br>The working SYSTEM hive here would come from an `install.wim` image of the same major version of Windows (not WinPE/WinRE). The Win32 subsystem will not be able to initialise fully, but smss can be configured in `ControlSet001\Control\Session Manager!SetupExecute` to achieve arbitrary native subsystem code execution as SYSTEM with derived keys in memory.<br><br>Fixed by wiping `systemdatadevice` element in bootmgr if Secure Boot is enabled, but the fix was only applied to the PCA 2023-signed bootmgr_ex, so **without the KB5025885 mitigation enabled, this vulnerability is still present and remains unfixed.** This bug is CVE-2025-21213. | January 2025, in PCA2023-signed bootmgr_ex only | February 2025; discovered in January 2024 (after the original fix) | Rairii |


### dangerous association

A vulnerable system will have the May 2022 or June 2022 updates installed, but not any later updates.

The associated options GUID is part of the hashed data, so the used device element must be marked as not verified.  
There are no elements that can be used on Windows 7 and below (although when custom non-default settings are used, it could still be possible).  
On Windows 8 and above, `osloader!osdevice` is not verified by default, and as such can be used.  
The easiest way to exploit this is to use the BCD raw device editor, bcdeditmod **(still not publicly released yet, it will happen eventually)**, although editing the BCD registry hive manually is also possible (figure it out yourself).

Exploitation involves:
* take the BCD from your target device, create two device elements
* copy the osdevice from `{default}` to the first one
* set the associated options GUID in `{default}!osdevice` to the first device element
* set the associated options GUID in `{first}!osdevice` to the second device element
* set whatever "dangerous" options (like `debug`) in the second device element
* boot the target device using that BCD and the same `bootmgfw` binary it was using

### bitpixie

This vulnerability existed for over 17 years, the earliest known build it was introduced in being `6.0.5231.2 (winmain_idx03.051004-2120)` from October 2005.  
Where Secure Boot integrity validation is used, a downgrade attack would still work to exploit this vulnerability.

Set up a PXE boot server with a vulnerable `bootmgfw.efi` (where legacy integrity validation is used, this must be the `bootmgfw.efi` from the target device) renamed correctly for EFI booting.

For the BCD, set up one default entry where `device` is the BitLocker encrypted osdevice; `path` is `"\"`; and a recovery sequence.

The recovery sequence should point to a single `startup` entry, where `device` is boot, `path` points to an EFI application to run (from the PXE server); and `pxesoftreboot` is enabled.

When Secure Boot is disabled, that EFI application can just be an application to scan physical memory looking for a BitLocker keytable to dump.

When Secure Boot is enabled, that EFI application can use a known Secure Boot bypass (where physical access is required if needed).  
For exploiting a Windows boot application in this way, you will need to replace the BCD with your second one on the PXE server.  
This means pressing an arrow key during `bootmgr` startup to force the boot menu to show; and then replacing the BCD on the PXE server at that point.

### push button decrypt

Exploitation involves:
* **Dump the bitlocker protected osvolume to a disk image.** This method to get the FVEK leads to actual data loss!
* Boot to WinRE using whatever means (force it by startup repair if needed, or just set bootsequence BCD element, etc).
* Start a reset (Troubleshoot -> Reset this PC -> Remove everything). It's quicker to choose "Local reinstall". Be sure to choose "Just remove my files".  
  * Choosing to "keep files" will ask for recovery key.
  * If the system's WinRE is not vulnerable, it will also ask for a recovery key.
* When the reset gets to ~98%, shut the system down forcefully (via holding power button down 7 seconds / etc).
* Power the system back on, it should boot to WinRE again and show an error. Dismissing the error should reboot.
* When you see the blue "updating" screen, press Shift+F10 to get to a shell.
* Execute `manage-bde -pause C:` followed by `manage-bde -protectors -delete C:`
* Shut the system down forcefully (again).

At this point, the on-disk BitLocker metadata will contain a plaintext VMK.  
Dump it, and use that VMK to decrypt the FVEK.  
The decrypted FVEK can be used on the disk image made previously to decrypt the partition.

Please note: I only successfully exploited this issue on Windows 10 in very specific circumstances (TPM-only BitLocker with no recovery key).
  However, [others have successfully exploited this issue using a vulnerable WinRE on Windows 11 (Nickel)](https://blog.scrt.ch/2023/08/14/cve-2022-41099-analysis-of-a-bitlocker-drive-encryption-bypass/).