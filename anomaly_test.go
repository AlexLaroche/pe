// Copyright 2021 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"strings"
	"testing"
	"time"
)

func TestGetAnomalies(t *testing.T) {

	tests := []struct {
		in  string
		out []string
	}{
		{
			getAbsoluteFilePath(
				"test/050708404553416d103652a7ca1f887ab81f533a019a0eeff0e6bb460a202cde"),
			[]string{AnoReservedDataDirectoryEntry},
		},
		{
			getAbsoluteFilePath(
				"test/0585495341e0ffaae1734acb78708ff55cd3612d844672d37226ef63d12652d0"),
			[]string{AnoAddressOfEntryPointNull, AnoMajorSubsystemVersion},
		},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			file, err := New(tt.in, &Options{})
			if err != nil {
				t.Fatalf("New(%s) failed, reason: %v", tt.in, err)
			}
			err = file.Parse()
			if err != nil {
				t.Fatalf("Parse(%s) failed, reason: %v", tt.in, err)
			}

			err = file.GetAnomalies()
			if err != nil {
				t.Fatalf("GetAnomalies(%s) failed, reason: %v", tt.in, err)
			}

			for _, ano := range tt.out {
				if !stringInSlice(ano, file.Anomalies) {
					t.Errorf("anomaly(%s) not found in anomalies, got: %v", ano, file.Anomalies)
				}
			}

		})
	}
}

func TestDetectPackedBinary(t *testing.T) {
	tests := []struct {
		name              string
		sections          []Section
		imports           []Import
		exports           Export
		expectedAnomalies []string
	}{
		{
			name: "Normal binary with low entropy",
			sections: []Section{
				{
					Header: ImageSectionHeader{
						Name:            [8]uint8{'t', 'e', 'x', 't', 0, 0, 0, 0},
						Characteristics: ImageSectionMemExecute,
					},
					Entropy: floatPtr(5.0),
				},
				{
					Header: ImageSectionHeader{
						Name: [8]uint8{'d', 'a', 't', 'a', 0, 0, 0, 0},
					},
					Entropy: floatPtr(3.0),
				},
			},
			imports:           make([]Import, 10), // Normal number of imports
			exports:           Export{Functions: make([]ExportFunction, 5)},
			expectedAnomalies: []string{},
		},
		{
			name: "High entropy sections (potential packing)",
			sections: []Section{
				{
					Header: ImageSectionHeader{
						Name:            [8]uint8{'t', 'e', 'x', 't', 0, 0, 0, 0},
						Characteristics: ImageSectionMemExecute,
					},
					Entropy: floatPtr(8.2), // Very high entropy
				},
				{
					Header: ImageSectionHeader{
						Name: [8]uint8{'d', 'a', 't', 'a', 0, 0, 0, 0},
					},
					Entropy: floatPtr(7.8), // High entropy
				},
				{
					Header: ImageSectionHeader{
						Name: [8]uint8{'r', 's', 'r', 'c', 0, 0, 0, 0},
					},
					Entropy: floatPtr(3.0), // Normal entropy
				},
			},
			imports: make([]Import, 2), // Few imports
			exports: Export{},          // No exports
			expectedAnomalies: []string{
				"has very high entropy",
				"Very few imports and no exports",
			},
		},
		{
			name: "UPX packer signatures",
			sections: []Section{
				{
					Header: ImageSectionHeader{
						Name: [8]uint8{'U', 'P', 'X', '0', 0, 0, 0, 0},
					},
					Entropy: floatPtr(6.0),
				},
				{
					Header: ImageSectionHeader{
						Name: [8]uint8{'U', 'P', 'X', '1', 0, 0, 0, 0},
					},
					Entropy: floatPtr(7.0),
				},
			},
			imports: make([]Import, 3),
			exports: Export{},
			expectedAnomalies: []string{
				"UPX packer signature detected",
				"UPX packer signature detected",
			},
		},
		{
			name: "Commercial protector signatures",
			sections: []Section{
				{
					Header: ImageSectionHeader{
						Name: [8]uint8{'.', 't', 'h', 'e', 'm', 'i', 'd', 'a'},
					},
					Entropy: floatPtr(7.5),
				},
				{
					Header: ImageSectionHeader{
						Name: [8]uint8{'.', 'v', 'm', 'p', 0, 0, 0, 0},
					},
					Entropy: floatPtr(8.0),
				},
			},
			imports: make([]Import, 1),
			exports: Export{},
			expectedAnomalies: []string{
				"Commercial protector signature detected",
				"Commercial protector signature detected",
			},
		},
		{
			name: "No executable sections (unusual)",
			sections: []Section{
				{
					Header: ImageSectionHeader{
						Name:            [8]uint8{'d', 'a', 't', 'a', '1', 0, 0, 0},
						Characteristics: 0, // No execute flag
					},
					Entropy: floatPtr(4.0),
				},
				{
					Header: ImageSectionHeader{
						Name:            [8]uint8{'d', 'a', 't', 'a', '2', 0, 0, 0},
						Characteristics: 0, // No execute flag
					},
					Entropy: floatPtr(5.0),
				},
			},
			imports:           make([]Import, 5),
			exports:           Export{Functions: make([]ExportFunction, 2)},
			expectedAnomalies: []string{"No executable sections found"},
		},
		{
			name: "Too many executable sections",
			sections: []Section{
				{
					Header: ImageSectionHeader{
						Name:            [8]uint8{'t', 'e', 'x', 't', '1', 0, 0, 0},
						Characteristics: ImageSectionMemExecute,
					},
					Entropy: floatPtr(6.0),
				},
				{
					Header: ImageSectionHeader{
						Name:            [8]uint8{'t', 'e', 'x', 't', '2', 0, 0, 0},
						Characteristics: ImageSectionMemExecute,
					},
					Entropy: floatPtr(6.0),
				},
				{
					Header: ImageSectionHeader{
						Name:            [8]uint8{'t', 'e', 'x', 't', '3', 0, 0, 0},
						Characteristics: ImageSectionMemExecute,
					},
					Entropy: floatPtr(6.0),
				},
				{
					Header: ImageSectionHeader{
						Name:            [8]uint8{'t', 'e', 'x', 't', '4', 0, 0, 0},
						Characteristics: ImageSectionMemExecute,
					},
					Entropy: floatPtr(6.0),
				},
			},
			imports:           make([]Import, 5),
			exports:           Export{Functions: make([]ExportFunction, 2)},
			expectedAnomalies: []string{"Unusually high number of executable sections"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := &File{
				Sections:  tt.sections,
				Imports:   tt.imports,
				Export:    tt.exports,
				Anomalies: []string{},
			}

			file.detectPackedBinary()

			// Check that expected anomalies are present
			for _, expectedAnomaly := range tt.expectedAnomalies {
				found := false
				for _, anomaly := range file.Anomalies {
					if strings.Contains(anomaly, expectedAnomaly) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected anomaly containing '%s' not found in: %v",
						expectedAnomaly, file.Anomalies)
				}
			}

			// If no anomalies expected, check that none were added
			if len(tt.expectedAnomalies) == 0 && len(file.Anomalies) > 0 {
				t.Errorf("Expected no anomalies, but got: %v", file.Anomalies)
			}
		})
	}
}

func TestEnhancedAnomalyDetection(t *testing.T) {
	tests := []struct {
		name           string
		sectionEntropy bool
		shouldDetect   bool
	}{
		{
			name:           "Section entropy enabled - should run detection",
			sectionEntropy: true,
			shouldDetect:   true,
		},
		{
			name:           "Section entropy disabled - should skip detection",
			sectionEntropy: false,
			shouldDetect:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := &File{
				opts: &Options{
					SectionEntropy: tt.sectionEntropy,
				},
				Sections: []Section{
					{
						Header: ImageSectionHeader{
							Name: [8]uint8{'U', 'P', 'X', '0', 0, 0, 0, 0},
						},
						Entropy: floatPtr(8.0),
					},
				},
				Imports:   []Import{},
				Export:    Export{},
				Anomalies: []string{},
			}

			file.enhancedAnomalyDetection()

			hasAnomalies := len(file.Anomalies) > 0
			if hasAnomalies != tt.shouldDetect {
				t.Errorf("Enhanced detection expected to detect anomalies: %v, got: %v",
					tt.shouldDetect, hasAnomalies)
			}
		})
	}
}

func TestIntegrationWithGetAnomalies(t *testing.T) {
	// Test that enhanced anomaly detection is integrated into GetAnomalies()
	file := &File{
		opts: &Options{
			SectionEntropy: true,
		},
		NtHeader: ImageNtHeader{
			FileHeader: ImageFileHeader{
				NumberOfSections: 2,
			},
			OptionalHeader: ImageOptionalHeader32{
				NumberOfRvaAndSizes: 16,
			},
		},
		Sections: []Section{
			{
				Header: ImageSectionHeader{
					Name: [8]uint8{'U', 'P', 'X', '0', 0, 0, 0, 0},
				},
				Entropy: floatPtr(8.5), // Very high entropy
			},
		},
		Imports:   []Import{},
		Export:    Export{},
		Anomalies: []string{},
		FileInfo: FileInfo{
			Is32: true,
		},
	}

	err := file.GetAnomalies()
	if err != nil {
		t.Fatalf("GetAnomalies() error = %v", err)
	}

	// Should have detected UPX signature
	foundUPX := false
	for _, anomaly := range file.Anomalies {
		if strings.Contains(anomaly, "UPX packer signature") {
			foundUPX = true
			break
		}
	}

	if !foundUPX {
		t.Errorf("GetAnomalies() should have detected UPX signature through enhanced detection")
	}
}

func TestFileHeaderAnomalies(t *testing.T) {
	tests := []struct {
		name              string
		file              *File
		expectedAnomalies []string
	}{
		{
			name: "Normal file header",
			file: &File{
				opts: &Options{SectionEntropy: false},
				NtHeader: ImageNtHeader{
					FileHeader: ImageFileHeader{
						NumberOfSections:     5,
						TimeDateStamp:        uint32(time.Now().Unix()),
						SizeOfOptionalHeader: 0xE0,
					},
					OptionalHeader: ImageOptionalHeader32{
						AddressOfEntryPoint:   0x1000,
						SizeOfHeaders:         0x1000,
						ImageBase:             0x400000,
						SectionAlignment:      0x1000,
						SizeOfImage:           0x2000,
						MajorSubsystemVersion: 5,
						Win32VersionValue:     0,
						CheckSum:              0,
						NumberOfRvaAndSizes:   16,
					},
				},
				FileInfo:  FileInfo{Is32: true},
				Anomalies: []string{},
			},
			expectedAnomalies: []string{},
		},
		{
			name: "High number of sections",
			file: &File{
				opts: &Options{SectionEntropy: false},
				NtHeader: ImageNtHeader{
					FileHeader: ImageFileHeader{
						NumberOfSections:     15,
						TimeDateStamp:        uint32(time.Now().Unix()),
						SizeOfOptionalHeader: 0xE0,
					},
					OptionalHeader: ImageOptionalHeader32{
						AddressOfEntryPoint:   0x1000,
						SizeOfHeaders:         0x1000,
						ImageBase:             0x400000,
						SectionAlignment:      0x1000,
						SizeOfImage:           0x2000,
						MajorSubsystemVersion: 5,
						Win32VersionValue:     0,
						CheckSum:              0,
						NumberOfRvaAndSizes:   16,
					},
				},
				FileInfo:  FileInfo{Is32: true},
				Anomalies: []string{},
			},
			expectedAnomalies: []string{AnoNumberOfSections10Plus},
		},
		{
			name: "Null timestamp",
			file: &File{
				opts: &Options{SectionEntropy: false},
				NtHeader: ImageNtHeader{
					FileHeader: ImageFileHeader{
						NumberOfSections:     5,
						TimeDateStamp:        0,
						SizeOfOptionalHeader: 0xE0,
					},
					OptionalHeader: ImageOptionalHeader32{
						AddressOfEntryPoint:   0x1000,
						SizeOfHeaders:         0x1000,
						ImageBase:             0x400000,
						SectionAlignment:      0x1000,
						SizeOfImage:           0x2000,
						MajorSubsystemVersion: 5,
						Win32VersionValue:     0,
						CheckSum:              0,
						NumberOfRvaAndSizes:   16,
					},
				},
				FileInfo:  FileInfo{Is32: true},
				Anomalies: []string{},
			},
			expectedAnomalies: []string{AnoPETimeStampNull},
		},
		{
			name: "Future timestamp",
			file: &File{
				opts: &Options{SectionEntropy: false},
				NtHeader: ImageNtHeader{
					FileHeader: ImageFileHeader{
						NumberOfSections:     5,
						TimeDateStamp:        uint32(time.Now().Add(48 * time.Hour).Unix()),
						SizeOfOptionalHeader: 0xE0,
					},
					OptionalHeader: ImageOptionalHeader32{
						AddressOfEntryPoint:   0x1000,
						SizeOfHeaders:         0x1000,
						ImageBase:             0x400000,
						SectionAlignment:      0x1000,
						SizeOfImage:           0x2000,
						MajorSubsystemVersion: 5,
						Win32VersionValue:     0,
						CheckSum:              0,
						NumberOfRvaAndSizes:   16,
					},
				},
				FileInfo:  FileInfo{Is32: true},
				Anomalies: []string{},
			},
			expectedAnomalies: []string{AnoPETimeStampFuture},
		},
		{
			name: "Zero sections",
			file: &File{
				opts: &Options{SectionEntropy: false},
				NtHeader: ImageNtHeader{
					FileHeader: ImageFileHeader{
						NumberOfSections:     0,
						TimeDateStamp:        uint32(time.Now().Unix()),
						SizeOfOptionalHeader: 0xE0,
					},
					OptionalHeader: ImageOptionalHeader32{
						AddressOfEntryPoint:   0x1000,
						SizeOfHeaders:         0x1000,
						ImageBase:             0x400000,
						SectionAlignment:      0x1000,
						SizeOfImage:           0x2000,
						MajorSubsystemVersion: 5,
						Win32VersionValue:     0,
						CheckSum:              0,
						NumberOfRvaAndSizes:   16,
					},
				},
				FileInfo:  FileInfo{Is32: true},
				Anomalies: []string{},
			},
			expectedAnomalies: []string{AnoNumberOfSectionsNull},
		},
		{
			name: "Zero optional header size",
			file: &File{
				opts: &Options{SectionEntropy: false},
				NtHeader: ImageNtHeader{
					FileHeader: ImageFileHeader{
						NumberOfSections:     5,
						TimeDateStamp:        uint32(time.Now().Unix()),
						SizeOfOptionalHeader: 0,
					},
					OptionalHeader: ImageOptionalHeader32{
						AddressOfEntryPoint:   0x1000,
						SizeOfHeaders:         0x1000,
						ImageBase:             0x400000,
						SectionAlignment:      0x1000,
						SizeOfImage:           0x2000,
						MajorSubsystemVersion: 5,
						Win32VersionValue:     0,
						CheckSum:              0,
						NumberOfRvaAndSizes:   16,
					},
				},
				FileInfo:  FileInfo{Is32: true},
				Anomalies: []string{},
			},
			expectedAnomalies: []string{AnoSizeOfOptionalHeaderNull},
		},
		{
			name: "Uncommon PE32 optional header size",
			file: &File{
				opts: &Options{SectionEntropy: false},
				NtHeader: ImageNtHeader{
					FileHeader: ImageFileHeader{
						NumberOfSections:     5,
						TimeDateStamp:        uint32(time.Now().Unix()),
						SizeOfOptionalHeader: 0xF0,
					},
					OptionalHeader: ImageOptionalHeader32{
						AddressOfEntryPoint:   0x1000,
						SizeOfHeaders:         0x1000,
						ImageBase:             0x400000,
						SectionAlignment:      0x1000,
						SizeOfImage:           0x2000,
						MajorSubsystemVersion: 5,
						Win32VersionValue:     0,
						CheckSum:              0,
						NumberOfRvaAndSizes:   16,
					},
				},
				FileInfo:  FileInfo{Is32: true},
				Anomalies: []string{},
			},
			expectedAnomalies: []string{AnoUncommonSizeOfOptionalHeader32},
		},
		{
			name: "Uncommon PE64 optional header size",
			file: &File{
				opts: &Options{SectionEntropy: false},
				NtHeader: ImageNtHeader{
					FileHeader: ImageFileHeader{
						NumberOfSections:     5,
						TimeDateStamp:        uint32(time.Now().Unix()),
						SizeOfOptionalHeader: 0x100,
					},
					OptionalHeader: ImageOptionalHeader64{
						AddressOfEntryPoint:   0x1000,
						SizeOfHeaders:         0x1000,
						ImageBase:             0x140000000,
						SectionAlignment:      0x1000,
						SizeOfImage:           0x2000,
						MajorSubsystemVersion: 5,
						Win32VersionValue:     0,
						CheckSum:              0,
						NumberOfRvaAndSizes:   16,
					},
				},
				FileInfo:  FileInfo{Is64: true},
				Anomalies: []string{},
			},
			expectedAnomalies: []string{AnoUncommonSizeOfOptionalHeader64},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.file.GetAnomalies()
			if err != nil {
				t.Fatalf("GetAnomalies() error = %v", err)
			}

			// Check expected anomalies
			for _, expectedAnomaly := range tt.expectedAnomalies {
				found := false
				for _, anomaly := range tt.file.Anomalies {
					if strings.Contains(anomaly, expectedAnomaly) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected anomaly '%s' not found in: %v", expectedAnomaly, tt.file.Anomalies)
				}
			}

			// If no anomalies expected, check none were added
			if len(tt.expectedAnomalies) == 0 && len(tt.file.Anomalies) > 0 {
				t.Errorf("Expected no anomalies, but got: %v", tt.file.Anomalies)
			}
		})
	}
}

func TestOptionalHeaderAnomalies(t *testing.T) {
	tests := []struct {
		name              string
		file              *File
		expectedAnomalies []string
	}{
		{
			name: "Null entry point",
			file: &File{
				opts: &Options{SectionEntropy: false},
				NtHeader: ImageNtHeader{
					FileHeader: ImageFileHeader{NumberOfSections: 1},
					OptionalHeader: ImageOptionalHeader32{
						AddressOfEntryPoint:   0,
						SizeOfHeaders:         0x1000,
						ImageBase:             0x400000,
						SectionAlignment:      0x1000,
						SizeOfImage:           0x2000,
						MajorSubsystemVersion: 5,
						Win32VersionValue:     0,
						CheckSum:              0,
						NumberOfRvaAndSizes:   16,
					},
				},
				FileInfo:  FileInfo{Is32: true},
				Anomalies: []string{},
			},
			expectedAnomalies: []string{AnoAddressOfEntryPointNull},
		},
		{
			name: "Entry point less than headers size",
			file: &File{
				opts: &Options{SectionEntropy: false},
				NtHeader: ImageNtHeader{
					FileHeader: ImageFileHeader{NumberOfSections: 1},
					OptionalHeader: ImageOptionalHeader32{
						AddressOfEntryPoint:   0x500,
						SizeOfHeaders:         0x1000,
						ImageBase:             0x400000,
						SectionAlignment:      0x1000,
						SizeOfImage:           0x2000,
						MajorSubsystemVersion: 5,
						Win32VersionValue:     0,
						CheckSum:              0,
						NumberOfRvaAndSizes:   16,
					},
				},
				FileInfo:  FileInfo{Is32: true},
				Anomalies: []string{},
			},
			expectedAnomalies: []string{AnoAddressOfEPLessSizeOfHeaders},
		},
		{
			name: "Null image base PE32",
			file: &File{
				opts: &Options{SectionEntropy: false},
				NtHeader: ImageNtHeader{
					FileHeader: ImageFileHeader{NumberOfSections: 1},
					OptionalHeader: ImageOptionalHeader32{
						AddressOfEntryPoint:   0x1000,
						SizeOfHeaders:         0x1000,
						ImageBase:             0,
						SectionAlignment:      0x1000,
						SizeOfImage:           0x2000,
						MajorSubsystemVersion: 5,
						Win32VersionValue:     0,
						CheckSum:              0,
						NumberOfRvaAndSizes:   16,
					},
				},
				FileInfo:  FileInfo{Is32: true},
				Anomalies: []string{},
			},
			expectedAnomalies: []string{AnoImageBaseNull},
		},
		{
			name: "Invalid subsystem version",
			file: &File{
				opts: &Options{SectionEntropy: false},
				NtHeader: ImageNtHeader{
					FileHeader: ImageFileHeader{NumberOfSections: 1},
					OptionalHeader: ImageOptionalHeader32{
						AddressOfEntryPoint:   0x1000,
						SizeOfHeaders:         0x1000,
						ImageBase:             0x400000,
						SectionAlignment:      0x1000,
						SizeOfImage:           0x2000,
						MajorSubsystemVersion: 10,
						Win32VersionValue:     0,
						CheckSum:              0,
						NumberOfRvaAndSizes:   16,
					},
				},
				FileInfo:  FileInfo{Is32: true},
				Anomalies: []string{},
			},
			expectedAnomalies: []string{AnoMajorSubsystemVersion},
		},
		{
			name: "Non-zero Win32VersionValue",
			file: &File{
				opts: &Options{SectionEntropy: false},
				NtHeader: ImageNtHeader{
					FileHeader: ImageFileHeader{NumberOfSections: 1},
					OptionalHeader: ImageOptionalHeader32{
						AddressOfEntryPoint:   0x1000,
						SizeOfHeaders:         0x1000,
						ImageBase:             0x400000,
						SectionAlignment:      0x1000,
						SizeOfImage:           0x2000,
						MajorSubsystemVersion: 5,
						Win32VersionValue:     0x12345,
						CheckSum:              0,
						NumberOfRvaAndSizes:   16,
					},
				},
				FileInfo:  FileInfo{Is32: true},
				Anomalies: []string{},
			},
			expectedAnomalies: []string{AnonWin32VersionValue},
		},
		{
			name: "Non-standard NumberOfRvaAndSizes",
			file: &File{
				opts: &Options{SectionEntropy: false},
				NtHeader: ImageNtHeader{
					FileHeader: ImageFileHeader{NumberOfSections: 1},
					OptionalHeader: ImageOptionalHeader32{
						AddressOfEntryPoint:   0x1000,
						SizeOfHeaders:         0x1000,
						ImageBase:             0x400000,
						SectionAlignment:      0x1000,
						SizeOfImage:           0x2000,
						MajorSubsystemVersion: 5,
						Win32VersionValue:     0,
						CheckSum:              0,
						NumberOfRvaAndSizes:   0xA,
					},
				},
				FileInfo:  FileInfo{Is32: true},
				Anomalies: []string{},
			},
			expectedAnomalies: []string{AnoNumberOfRvaAndSizes},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.file.GetAnomalies()
			if err != nil {
				t.Fatalf("GetAnomalies() error = %v", err)
			}

			// Check expected anomalies
			for _, expectedAnomaly := range tt.expectedAnomalies {
				found := false
				for _, anomaly := range tt.file.Anomalies {
					if strings.Contains(anomaly, expectedAnomaly) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected anomaly '%s' not found in: %v", expectedAnomaly, tt.file.Anomalies)
				}
			}
		})
	}
}

func TestPE64Anomalies(t *testing.T) {
	tests := []struct {
		name              string
		file              *File
		expectedAnomalies []string
	}{
		{
			name: "PE64 null image base",
			file: &File{
				opts: &Options{SectionEntropy: false},
				NtHeader: ImageNtHeader{
					FileHeader: ImageFileHeader{NumberOfSections: 1},
					OptionalHeader: ImageOptionalHeader64{
						AddressOfEntryPoint:   0x1000,
						SizeOfHeaders:         0x1000,
						ImageBase:             0,
						SectionAlignment:      0x1000,
						SizeOfImage:           0x2000,
						MajorSubsystemVersion: 5,
						Win32VersionValue:     0,
						CheckSum:              0,
						NumberOfRvaAndSizes:   16,
					},
				},
				FileInfo:  FileInfo{Is64: true},
				Anomalies: []string{},
			},
			expectedAnomalies: []string{AnoImageBaseNull},
		},
		{
			name: "PE64 non-standard NumberOfRvaAndSizes",
			file: &File{
				opts: &Options{SectionEntropy: false},
				NtHeader: ImageNtHeader{
					FileHeader: ImageFileHeader{NumberOfSections: 1},
					OptionalHeader: ImageOptionalHeader64{
						AddressOfEntryPoint:   0x1000,
						SizeOfHeaders:         0x1000,
						ImageBase:             0x140000000,
						SectionAlignment:      0x1000,
						SizeOfImage:           0x2000,
						MajorSubsystemVersion: 5,
						Win32VersionValue:     0,
						CheckSum:              0,
						NumberOfRvaAndSizes:   0xA,
					},
				},
				FileInfo:  FileInfo{Is64: true},
				Anomalies: []string{},
			},
			expectedAnomalies: []string{AnoNumberOfRvaAndSizes},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.file.GetAnomalies()
			if err != nil {
				t.Fatalf("GetAnomalies() error = %v", err)
			}

			// Check expected anomalies
			for _, expectedAnomaly := range tt.expectedAnomalies {
				found := false
				for _, anomaly := range tt.file.Anomalies {
					if strings.Contains(anomaly, expectedAnomaly) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected anomaly '%s' not found in: %v", expectedAnomaly, tt.file.Anomalies)
				}
			}
		})
	}
}

func TestAddAnomaly(t *testing.T) {
	tests := []struct {
		name             string
		initialAnomalies []string
		anomalyToAdd     string
		expectedCount    int
	}{
		{
			name:             "Add to empty list",
			initialAnomalies: []string{},
			anomalyToAdd:     "Test anomaly",
			expectedCount:    1,
		},
		{
			name:             "Add duplicate anomaly",
			initialAnomalies: []string{"Test anomaly"},
			anomalyToAdd:     "Test anomaly",
			expectedCount:    1,
		},
		{
			name:             "Add new anomaly",
			initialAnomalies: []string{"Existing anomaly"},
			anomalyToAdd:     "New anomaly",
			expectedCount:    2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := &File{
				Anomalies: make([]string, len(tt.initialAnomalies)),
			}
			copy(file.Anomalies, tt.initialAnomalies)

			file.addAnomaly(tt.anomalyToAdd)

			if len(file.Anomalies) != tt.expectedCount {
				t.Errorf("Expected %d anomalies, got %d: %v", tt.expectedCount, len(file.Anomalies), file.Anomalies)
			}

			// Check that the anomaly is present
			found := false
			for _, anomaly := range file.Anomalies {
				if anomaly == tt.anomalyToAdd {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Anomaly '%s' not found in list: %v", tt.anomalyToAdd, file.Anomalies)
			}
		})
	}
}

func TestSectionPackingDetection(t *testing.T) {
	tests := []struct {
		name              string
		sections          []Section
		imports           []Import
		exports           Export
		expectedAnomalies []string
	}{
		{
			name: "Suspicious packed section names",
			sections: []Section{
				{
					Header: ImageSectionHeader{
						Name: [8]uint8{'.', 'p', 'a', 'c', 'k', 0, 0, 0},
					},
					Entropy: floatPtr(6.0),
				},
				{
					Header: ImageSectionHeader{
						Name: [8]uint8{'.', 'p', 'a', 'c', 'k', 'e', 'd', 0},
					},
					Entropy: floatPtr(7.0),
				},
			},
			imports: make([]Import, 5),
			exports: Export{Functions: make([]ExportFunction, 2)},
			expectedAnomalies: []string{
				"Suspicious packed section name",
				"Suspicious packed section name",
			},
		},
		{
			name: "High entropy proportion",
			sections: []Section{
				{
					Header: ImageSectionHeader{
						Name:            [8]uint8{'t', 'e', 'x', 't', 0, 0, 0, 0},
						Characteristics: ImageSectionMemExecute,
					},
					Entropy: floatPtr(7.8), // High entropy
				},
				{
					Header: ImageSectionHeader{
						Name: [8]uint8{'d', 'a', 't', 'a', 0, 0, 0, 0},
					},
					Entropy: floatPtr(7.6), // High entropy
				},
			},
			imports: make([]Import, 5),
			exports: Export{Functions: make([]ExportFunction, 2)},
			expectedAnomalies: []string{
				"High proportion of sections with elevated entropy",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := &File{
				Sections:  tt.sections,
				Imports:   tt.imports,
				Export:    tt.exports,
				Anomalies: []string{},
			}

			file.detectPackedBinary()

			// Check expected anomalies
			for _, expectedAnomaly := range tt.expectedAnomalies {
				found := false
				for _, anomaly := range file.Anomalies {
					if strings.Contains(anomaly, expectedAnomaly) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected anomaly containing '%s' not found in: %v",
						expectedAnomaly, file.Anomalies)
				}
			}
		})
	}
}

func TestEdgeCases(t *testing.T) {
	t.Run("Empty sections list", func(t *testing.T) {
		file := &File{
			Sections:  []Section{},
			Imports:   []Import{},
			Export:    Export{},
			Anomalies: []string{},
		}

		file.detectPackedBinary()

		// Should not crash and should not add any anomalies related to sections
		// (other anomalies might be added based on imports/exports)
	})

	t.Run("Nil entropy pointers", func(t *testing.T) {
		file := &File{
			Sections: []Section{
				{
					Header: ImageSectionHeader{
						Name: [8]uint8{'t', 'e', 's', 't', 0, 0, 0, 0},
					},
					Entropy: nil, // No entropy calculated
				},
			},
			Imports:   []Import{},
			Export:    Export{},
			Anomalies: []string{},
		}

		file.detectPackedBinary()

		// Should not crash when entropy is nil
	})

	t.Run("Mixed section characteristics", func(t *testing.T) {
		file := &File{
			Sections: []Section{
				{
					Header: ImageSectionHeader{
						Name:            [8]uint8{'t', 'e', 'x', 't', '1', 0, 0, 0},
						Characteristics: ImageSectionMemExecute | ImageSectionMemRead,
					},
					Entropy: floatPtr(6.0),
				},
				{
					Header: ImageSectionHeader{
						Name:            [8]uint8{'d', 'a', 't', 'a', 0, 0, 0, 0},
						Characteristics: ImageSectionMemRead | ImageSectionMemWrite,
					},
					Entropy: floatPtr(4.0),
				},
			},
			Imports:   make([]Import, 10),
			Export:    Export{Functions: make([]ExportFunction, 5)},
			Anomalies: []string{},
		}

		file.detectPackedBinary()

		// Should correctly identify 1 executable section
	})
}

func TestChecksumAnomaly(t *testing.T) {
	// Test for checksum validation - when checksum is non-zero but doesn't match calculated value
	// This test demonstrates the anomaly detection logic but can't easily mock the checksum calculation
	file := &File{
		opts: &Options{SectionEntropy: false},
		NtHeader: ImageNtHeader{
			FileHeader: ImageFileHeader{NumberOfSections: 1},
			OptionalHeader: ImageOptionalHeader32{
				AddressOfEntryPoint:   0x1000,
				SizeOfHeaders:         0x1000,
				ImageBase:             0x400000,
				SectionAlignment:      0x1000,
				SizeOfImage:           0x2000,
				MajorSubsystemVersion: 5,
				Win32VersionValue:     0,
				CheckSum:              0, // Zero checksum should not trigger anomaly
				NumberOfRvaAndSizes:   16,
			},
		},
		FileInfo:  FileInfo{Is32: true},
		Anomalies: []string{},
	}

	err := file.GetAnomalies()
	if err != nil {
		t.Fatalf("GetAnomalies() error = %v", err)
	}

	// Zero checksum should not add invalid checksum anomaly
	for _, anomaly := range file.Anomalies {
		if strings.Contains(anomaly, "checksum is invalid") {
			t.Errorf("Unexpected checksum anomaly found with zero checksum: %v", file.Anomalies)
		}
	}
}

func TestSizeOfImageAnomaly(t *testing.T) {
	// Test for SizeOfImage not being multiple of SectionAlignment
	file := &File{
		opts: &Options{SectionEntropy: false},
		NtHeader: ImageNtHeader{
			FileHeader: ImageFileHeader{NumberOfSections: 1},
			OptionalHeader: ImageOptionalHeader32{
				AddressOfEntryPoint:   0x1000,
				SizeOfHeaders:         0x1000,
				ImageBase:             0x400000,
				SectionAlignment:      0x1000,
				SizeOfImage:           0x2001, // Not multiple of SectionAlignment
				MajorSubsystemVersion: 5,
				Win32VersionValue:     0,
				CheckSum:              0,
				NumberOfRvaAndSizes:   16,
			},
		},
		FileInfo:  FileInfo{Is32: true},
		Anomalies: []string{},
	}

	err := file.GetAnomalies()
	if err != nil {
		t.Fatalf("GetAnomalies() error = %v", err)
	}

	// Should detect invalid SizeOfImage
	found := false
	for _, anomaly := range file.Anomalies {
		if strings.Contains(anomaly, "Invalid SizeOfImage") {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Expected SizeOfImage anomaly not found in: %v", file.Anomalies)
	}
}

func TestBenchmarkDetectPackedBinary(t *testing.T) {
	// Performance test with large number of sections
	sections := make([]Section, 50)
	for i := 0; i < 50; i++ {
		sections[i] = Section{
			Header: ImageSectionHeader{
				Name:            [8]uint8{'s', 'e', 'c', byte('0' + i%10), 0, 0, 0, 0},
				Characteristics: ImageSectionMemExecute,
			},
			Entropy: floatPtr(float64(i%8) + 1.0),
		}
	}

	file := &File{
		Sections:  sections,
		Imports:   make([]Import, 100),
		Export:    Export{Functions: make([]ExportFunction, 50)},
		Anomalies: []string{},
	}

	// Should complete without issues
	file.detectPackedBinary()

	// Should detect high number of executable sections
	found := false
	for _, anomaly := range file.Anomalies {
		if strings.Contains(anomaly, "Unusually high number of executable sections") {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Expected high executable sections anomaly not found")
	}
}

// Helper function to create float64 pointer
func floatPtr(f float64) *float64 {
	return &f
}
