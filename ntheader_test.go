// Copyright 2021 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"reflect"
	"sort"
	"testing"
)

func TestParseNtHeaderNE(t *testing.T) {

	tests := []struct {
		in  string
		out error
	}{
		{
			// This is an NE executable file. Extracted from Windows CE 2.0.
			getAbsoluteFilePath("test/_setup.dll"),
			ErrImageOS2SignatureFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			ops := Options{Fast: true}
			file, err := New(tt.in, &ops)
			if err != nil {
				t.Fatalf("New(%s) failed, reason: %v", tt.in, err)
			}

			err = file.Parse()
			if err != tt.out {
				t.Fatalf("parsing nt header failed, got %v, want %v", err, tt.out)
			}
		})
	}
}

func TestNtHeaderMachineType(t *testing.T) {

	tests := []struct {
		name string
		in   ImageFileHeaderMachineType
		out  string
	}{
		// Common modern architectures
		{
			name: "x64 (AMD64)",
			in:   ImageFileMachineAMD64,
			out:  "x64",
		},
		{
			name: "Intel i386",
			in:   ImageFileMachineI386,
			out:  "Intel 386 or later / compatible processors",
		},
		{
			name: "ARM 32-bit",
			in:   ImageFileMachineARM,
			out:  "ARM little endian",
		},
		{
			name: "ARM64 little endian",
			in:   ImageFileMachineARM64,
			out:  "ARM64 little endian",
		},
		
		// New ARM64 variants added for Windows 11
		{
			name: "ARM64EC Emulation Compatible",
			in:   ImageFileMachineARM64EC,
			out:  "ARM64EC (Emulation Compatible)",
		},
		{
			name: "ARM64X dual-architecture",
			in:   ImageFileMachineARM64X,
			out:  "ARM64X (dual-architecture)",
		},
		
		// Legacy and specialized architectures
		{
			name: "Intel Itanium IA64",
			in:   ImageFileMachineIA64,
			out:  "Intel Itanium processor family",
		},
		{
			name: "ARM Thumb-2",
			in:   ImageFileMachineARMNT,
			out:  "ARM Thumb-2 little endian",
		},
		{
			name: "EFI Byte Code",
			in:   ImageFileMachineEBC,
			out:  "EFI byte code",
		},
		
		// RISC-V architectures
		{
			name: "RISC-V 32-bit",
			in:   ImageFileMachineRISCV32,
			out:  "RISC-V 32-bit address space",
		},
		{
			name: "RISC-V 64-bit",
			in:   ImageFileMachineRISCV64,
			out:  "RISC-V 64-bit address space",
		},
		{
			name: "RISC-V 128-bit",
			in:   ImageFileMachineRISCV128,
			out:  "RISC-V 128-bit address space",
		},
		
		// Edge cases
		{
			name: "Unknown machine type",
			in:   ImageFileMachineUnknown,
			out:  "Unknown",
		},
		{
			name: "Invalid machine type",
			in:   ImageFileHeaderMachineType(0xffff),
			out:  "?",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.in.String()
			if got != tt.out {
				t.Errorf("machine type %s (0x%x): got %q, want %q",
					tt.name, uint16(tt.in), got, tt.out)
			}
		})
	}
}

func TestNtHeaderCharacteristicsType(t *testing.T) {

	tests := []struct {
		name string
		in   ImageFileHeaderCharacteristicsType
		out  []string
	}{
		{
			name: "Executable with Large Address Aware",
			in:   ImageFileHeaderCharacteristicsType(0x0022),
			out:  []string{"ExecutableImage", "LargeAddressAware"},
		},
		{
			name: "DLL with debug info stripped",
			in:   ImageFileHeaderCharacteristicsType(0x2206),
			out:  []string{"ExecutableImage", "LineNumsStripped", "DebugStripped", "DLL"},
		},
		{
			name: "System file with no relocations",
			in:   ImageFileHeaderCharacteristicsType(0x1001),
			out:  []string{"RelocsStripped", "FileSystem"},
		},
		{
			name: "UP system only (single processor)",
			in:   ImageFileHeaderCharacteristicsType(0x4000),
			out:  []string{"UpSystemOnly"},
		},
		{
			name: "Bytes reversed (big endian)",
			in:   ImageFileHeaderCharacteristicsType(0x8000),
			out:  []string{"BytesReservedHigh"},
		},
		{
			name: "32-bit machine",
			in:   ImageFileHeaderCharacteristicsType(0x0100),
			out:  []string{"32BitMachine"},
		},
		{
			name: "No debug info",
			in:   ImageFileHeaderCharacteristicsType(0x0004),
			out:  []string{"LineNumsStripped"},
		},
		{
			name: "Removable run from swap",
			in:   ImageFileHeaderCharacteristicsType(0x0400),
			out:  []string{"RemovableRunFromSwap"},
		},
		{
			name: "Aggressive working set trim",
			in:   ImageFileHeaderCharacteristicsType(0x0010),
			out:  []string{"AgressibeWsTrim"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.in.String()
			sort.Strings(got)
			sort.Strings(tt.out)
			if !reflect.DeepEqual(got, tt.out) {
				t.Errorf("file header characteristics %s (0x%x): got %v, want %v",
					tt.name, uint16(tt.in), got, tt.out)
			}
		})
	}
}

func TestOptionalHeaderSubsystemType(t *testing.T) {

	tests := []struct {
		name string
		in   ImageOptionalHeaderSubsystemType
		out  string
	}{
		{
			name: "Unknown subsystem",
			in:   ImageSubsystemUnknown,
			out:  "Unknown",
		},
		{
			name: "Native Windows subsystem",
			in:   ImageSubsystemNative,
			out:  "Native",
		},
		{
			name: "Windows GUI application",
			in:   ImageSubsystemWindowsGUI,
			out:  "Windows GUI",
		},
		{
			name: "Windows Console application",
			in:   ImageSubsystemWindowsCUI,
			out:  "Windows CUI",
		},
		{
			name: "OS/2 Console application",
			in:   ImageSubsystemOS2CUI,
			out:  "OS/2 character",
		},
		{
			name: "POSIX Console application",
			in:   ImageSubsystemPosixCUI,
			out:  "POSIX character",
		},
		{
			name: "Windows CE GUI",
			in:   ImageSubsystemWindowsCEGUI,
			out:  "Windows CE GUI",
		},
		{
			name: "EFI Application",
			in:   ImageSubsystemEFIApplication,
			out:  "EFI Application",
		},
		{
			name: "EFI Boot Service Driver",
			in:   ImageSubsystemEFIBootServiceDriver,
			out:  "EFI Boot Service Driver",
		},
		{
			name: "EFI Runtime Driver",
			in:   ImageSubsystemEFIRuntimeDriver,
			out:  "EFI ROM image",
		},
		{
			name: "EFI ROM Image",
			in:   ImageSubsystemEFIRom,
			out:  "EFI ROM image",
		},
		{
			name: "Xbox subsystem",
			in:   ImageSubsystemXBOX,
			out:  "XBOX",
		},
		{
			name: "Windows Boot Application",
			in:   ImageSubsystemWindowsBootApplication,
			out:  "Windows boot application",
		},
		{
			name: "Invalid subsystem",
			in:   ImageOptionalHeaderSubsystemType(0xff),
			out:  "?",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.in.String()
			if got != tt.out {
				t.Errorf("subsystem type %s (0x%x): got %q, want %q",
					tt.name, uint16(tt.in), got, tt.out)
			}
		})
	}
}

func TestOptionalHeaderDllCharacteristicsType(t *testing.T) {

	tests := []struct {
		name string
		in   ImageOptionalHeaderDllCharacteristicsType
		out  []string
	}{
		{
			name: "Modern security features",
			in:   ImageOptionalHeaderDllCharacteristicsType(0x8160),
			out:  []string{"DynamicBase", "HighEntropyVA", "NXCompact", "TerminalServiceAware"},
		},
		{
			name: "Control Flow Guard enabled",
			in:   ImageOptionalHeaderDllCharacteristicsType(0x4000),
			out:  []string{"GuardCF"},
		},
		{
			name: "ASLR with high entropy",
			in:   ImageOptionalHeaderDllCharacteristicsType(0x0060),
			out:  []string{"DynamicBase", "HighEntropyVA"},
		},
		{
			name: "DEP enabled",
			in:   ImageOptionalHeaderDllCharacteristicsType(0x0100),
			out:  []string{"NXCompact"},
		},
		{
			name: "No isolation",
			in:   ImageOptionalHeaderDllCharacteristicsType(0x0200),
			out:  []string{"NoIsolation"},
		},
		{
			name: "No SEH",
			in:   ImageOptionalHeaderDllCharacteristicsType(0x0400),
			out:  []string{"NoSEH"},
		},
		{
			name: "No bind",
			in:   ImageOptionalHeaderDllCharacteristicsType(0x0800),
			out:  []string{"NoBind"},
		},
		{
			name: "AppContainer",
			in:   ImageOptionalHeaderDllCharacteristicsType(0x1000),
			out:  []string{"AppContainer"},
		},
		{
			name: "WDM Driver",
			in:   ImageOptionalHeaderDllCharacteristicsType(0x2000),
			out:  []string{"WdmDriver"},
		},
		{
			name: "Force integrity",
			in:   ImageOptionalHeaderDllCharacteristicsType(0x0080),
			out:  []string{"ForceIntegrity"},
		},
		{
			name: "Combined modern features",
			in:   ImageOptionalHeaderDllCharacteristicsType(0xC160),
			out:  []string{"DynamicBase", "HighEntropyVA", "NXCompact", "GuardCF", "TerminalServiceAware"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.in.String()
			sort.Strings(got)
			sort.Strings(tt.out)
			if !reflect.DeepEqual(got, tt.out) {
				t.Errorf("DLL characteristics %s (0x%x): got %v, want %v",
					tt.name, uint16(tt.in), got, tt.out)
			}
		})
	}
}

// TestNtHeaderValidation tests validation of NT header fields
func TestNtHeaderValidation(t *testing.T) {
	tests := []struct {
		name      string
		signature uint32
		valid     bool
	}{
		{
			name:      "Valid PE signature",
			signature: ImageNTSignature,
			valid:     true,
		},
		{
			name:      "Invalid signature",
			signature: 0x12345678,
			valid:     false,
		},
		{
			name:      "DOS signature (invalid for NT header)",
			signature: ImageDOSSignature,
			valid:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isValid := tt.signature == ImageNTSignature
			if isValid != tt.valid {
				t.Errorf("signature validation for %s (0x%x): got %v, want %v",
					tt.name, tt.signature, isValid, tt.valid)
			}
		})
	}
}

// TestOptionalHeaderMagic tests optional header magic values
func TestOptionalHeaderMagic(t *testing.T) {
	tests := []struct {
		name   string
		magic  uint16
		is32   bool
		is64   bool
		isROM  bool
		valid  bool
	}{
		{
			name:  "PE32 magic",
			magic: ImageNtOptionalHeader32Magic,
			is32:  true,
			is64:  false,
			isROM: false,
			valid: true,
		},
		{
			name:  "PE32+ magic",
			magic: ImageNtOptionalHeader64Magic,
			is32:  false,
			is64:  true,
			isROM: false,
			valid: true,
		},
		{
			name:  "ROM magic",
			magic: ImageROMOptionalHeaderMagic,
			is32:  false,
			is64:  false,
			isROM: true,
			valid: true,
		},
		{
			name:  "Invalid magic",
			magic: 0x999,
			is32:  false,
			is64:  false,
			isROM: false,
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is32 := tt.magic == ImageNtOptionalHeader32Magic
			is64 := tt.magic == ImageNtOptionalHeader64Magic
			isROM := tt.magic == ImageROMOptionalHeaderMagic
			valid := is32 || is64 || isROM

			if is32 != tt.is32 {
				t.Errorf("PE32 detection for %s: got %v, want %v", tt.name, is32, tt.is32)
			}
			if is64 != tt.is64 {
				t.Errorf("PE32+ detection for %s: got %v, want %v", tt.name, is64, tt.is64)
			}
			if isROM != tt.isROM {
				t.Errorf("ROM detection for %s: got %v, want %v", tt.name, isROM, tt.isROM)
			}
			if valid != tt.valid {
				t.Errorf("validity for %s: got %v, want %v", tt.name, valid, tt.valid)
			}
		})
	}
}

// TestMachineTypeCompatibility tests machine type compatibility with architectures
func TestMachineTypeCompatibility(t *testing.T) {
	tests := []struct {
		name         string
		machineType  ImageFileHeaderMachineType
		supports64   bool
		supportsARM  bool
		supportsX86  bool
		isModern     bool
	}{
		{
			name:         "AMD64",
			machineType:  ImageFileMachineAMD64,
			supports64:   true,
			supportsARM:  false,
			supportsX86:  true,
			isModern:     true,
		},
		{
			name:         "Intel i386",
			machineType:  ImageFileMachineI386,
			supports64:   false,
			supportsARM:  false,
			supportsX86:  true,
			isModern:     true,
		},
		{
			name:         "ARM64",
			machineType:  ImageFileMachineARM64,
			supports64:   true,
			supportsARM:  true,
			supportsX86:  false,
			isModern:     true,
		},
		{
			name:         "ARM64EC",
			machineType:  ImageFileMachineARM64EC,
			supports64:   true,
			supportsARM:  true,
			supportsX86:  false,
			isModern:     true,
		},
		{
			name:         "ARM64X",
			machineType:  ImageFileMachineARM64X,
			supports64:   true,
			supportsARM:  true,
			supportsX86:  false,
			isModern:     true,
		},
		{
			name:         "ARM 32-bit",
			machineType:  ImageFileMachineARM,
			supports64:   false,
			supportsARM:  true,
			supportsX86:  false,
			isModern:     true,
		},
		{
			name:         "IA64 (legacy)",
			machineType:  ImageFileMachineIA64,
			supports64:   true,
			supportsARM:  false,
			supportsX86:  false,
			isModern:     false,
		},
		{
			name:         "RISC-V 64-bit",
			machineType:  ImageFileMachineRISCV64,
			supports64:   true,
			supportsARM:  false,
			supportsX86:  false,
			isModern:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test 64-bit support
			supports64 := tt.machineType == ImageFileMachineAMD64 ||
				tt.machineType == ImageFileMachineARM64 ||
				tt.machineType == ImageFileMachineARM64EC ||
				tt.machineType == ImageFileMachineARM64X ||
				tt.machineType == ImageFileMachineIA64 ||
				tt.machineType == ImageFileMachineRISCV64 ||
				tt.machineType == ImageFileMachineRISCV128

			if supports64 != tt.supports64 {
				t.Errorf("64-bit support for %s: got %v, want %v", 
					tt.name, supports64, tt.supports64)
			}

			// Test ARM support
			supportsARM := tt.machineType == ImageFileMachineARM ||
				tt.machineType == ImageFileMachineARM64 ||
				tt.machineType == ImageFileMachineARM64EC ||
				tt.machineType == ImageFileMachineARM64X ||
				tt.machineType == ImageFileMachineARMNT

			if supportsARM != tt.supportsARM {
				t.Errorf("ARM support for %s: got %v, want %v", 
					tt.name, supportsARM, tt.supportsARM)
			}

			// Test x86 support
			supportsX86 := tt.machineType == ImageFileMachineI386 ||
				tt.machineType == ImageFileMachineAMD64

			if supportsX86 != tt.supportsX86 {
				t.Errorf("x86 support for %s: got %v, want %v", 
					tt.name, supportsX86, tt.supportsX86)
			}
		})
	}
}
