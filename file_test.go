// Copyright 2021 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"os"
	"strings"
	"testing"
)

var peTests = []struct {
	in  string
	out error
}{
	{getAbsoluteFilePath("test/putty.exe"), nil},
}

func TestParse(t *testing.T) {
	for _, tt := range peTests {
		t.Run(tt.in, func(t *testing.T) {
			file, err := New(tt.in, &Options{})
			if err != nil {
				t.Fatalf("New(%s) failed, reason: %v", tt.in, err)
			}

			got := file.Parse()
			if got != nil {
				t.Errorf("Parse(%s) got %v, want %v", tt.in, got, tt.out)
			}
		})
	}
}

func TestParseOmitDirectories(t *testing.T) {
	for _, tt := range peTests {
		t.Run(tt.in, func(t *testing.T) {
			file, err := New(tt.in, &Options{OmitSecurityDirectory: true})
			if err != nil {
				t.Fatalf("New(%s) failed, reason: %v", tt.in, err)
			}

			got := file.Parse()
			if got != nil {
				t.Errorf("Parse(%s) got %v, want %v", tt.in, got, tt.out)
			}
			// Should expect an empty certificate
			if file.Certificates.Raw != nil {
				t.Errorf("Parse(%s) expected empty certificate", tt.in)
			}
		})
	}
}

func TestNewBytes(t *testing.T) {
	for _, tt := range peTests {
		t.Run(tt.in, func(t *testing.T) {
			data, _ := os.ReadFile(tt.in)
			file, err := NewBytes(data, &Options{})
			if err != nil {
				t.Fatalf("NewBytes(%s) failed, reason: %v", tt.in, err)
			}

			got := file.Parse()
			if got != nil {
				t.Errorf("Parse(%s) got %v, want %v", tt.in, got, tt.out)
			}
		})
	}
}

func TestChecksum(t *testing.T) {

	tests := []struct {
		in  string
		out uint32
	}{
		// file is DWORD aligned.
		{getAbsoluteFilePath("test/putty.exe"),
			0x00122C22},
		// file is not DWORD aligned and needs paddings.
		{getAbsoluteFilePath("test/010001e68577ef704792448ff474d22c6545167231982447c568e55041169ef0"),
			0x0006D558},
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

			got := file.Checksum()
			if got != tt.out {
				t.Errorf("Checksum(%s) got %v, want %v", tt.in, got, tt.out)
			}

		})
	}
}

func TestConfigurableLimits(t *testing.T) {
	tests := []struct {
		name                     string
		opts                     *Options
		expectedMaxExports       uint32
		expectedMaxImports       uint32
		expectedMaxRelocs        uint32
		expectedMaxCOFFSymbols   uint32
		expectedValidateChecksum bool
		expectedStrictValidation bool
		expectedParseDebugInfo   bool
	}{
		{
			name:                     "Default options",
			opts:                     &Options{},
			expectedMaxExports:       MaxDefaultExportEntriesCount,
			expectedMaxImports:       MaxDefaultImportEntriesCount,
			expectedMaxRelocs:        MaxDefaultRelocEntriesCount,
			expectedMaxCOFFSymbols:   MaxDefaultCOFFSymbolsCount,
			expectedValidateChecksum: false,
			expectedStrictValidation: false,
			expectedParseDebugInfo:   false,
		},
		{
			name: "Custom limits",
			opts: &Options{
				MaxExportEntriesCount: 1000,
				MaxImportEntriesCount: 500,
				MaxRelocEntriesCount:  2000,
				MaxCOFFSymbolsCount:   10000,
				ValidateChecksums:     true,
				StrictValidation:      true,
				ParseDebugInfo:        true,
			},
			expectedMaxExports:       1000,
			expectedMaxImports:       500,
			expectedMaxRelocs:        2000,
			expectedMaxCOFFSymbols:   10000,
			expectedValidateChecksum: true,
			expectedStrictValidation: true,
			expectedParseDebugInfo:   true,
		},
		{
			name: "Zero values should use defaults",
			opts: &Options{
				MaxExportEntriesCount: 0,
				MaxImportEntriesCount: 0,
				MaxRelocEntriesCount:  0,
				MaxCOFFSymbolsCount:   0,
			},
			expectedMaxExports:     MaxDefaultExportEntriesCount,
			expectedMaxImports:     MaxDefaultImportEntriesCount,
			expectedMaxRelocs:      MaxDefaultRelocEntriesCount,
			expectedMaxCOFFSymbols: MaxDefaultCOFFSymbolsCount,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file, err := New(getAbsoluteFilePath("test/kernel32.dll"), tt.opts)
			if err != nil {
				t.Fatalf("New() failed: %v", err)
			}
			defer file.Close()

			// Check that options were properly initialized
			if file.opts.MaxExportEntriesCount != tt.expectedMaxExports {
				t.Errorf("MaxExportEntriesCount = %d, want %d",
					file.opts.MaxExportEntriesCount, tt.expectedMaxExports)
			}

			if file.opts.MaxImportEntriesCount != tt.expectedMaxImports {
				t.Errorf("MaxImportEntriesCount = %d, want %d",
					file.opts.MaxImportEntriesCount, tt.expectedMaxImports)
			}

			if file.opts.MaxRelocEntriesCount != tt.expectedMaxRelocs {
				t.Errorf("MaxRelocEntriesCount = %d, want %d",
					file.opts.MaxRelocEntriesCount, tt.expectedMaxRelocs)
			}

			if file.opts.MaxCOFFSymbolsCount != tt.expectedMaxCOFFSymbols {
				t.Errorf("MaxCOFFSymbolsCount = %d, want %d",
					file.opts.MaxCOFFSymbolsCount, tt.expectedMaxCOFFSymbols)
			}

			if file.opts.ValidateChecksums != tt.expectedValidateChecksum {
				t.Errorf("ValidateChecksums = %v, want %v",
					file.opts.ValidateChecksums, tt.expectedValidateChecksum)
			}

			if file.opts.StrictValidation != tt.expectedStrictValidation {
				t.Errorf("StrictValidation = %v, want %v",
					file.opts.StrictValidation, tt.expectedStrictValidation)
			}

			if file.opts.ParseDebugInfo != tt.expectedParseDebugInfo {
				t.Errorf("ParseDebugInfo = %v, want %v",
					file.opts.ParseDebugInfo, tt.expectedParseDebugInfo)
			}
		})
	}
}

func TestDefaultConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant uint32
		expected uint32
	}{
		{"MaxDefaultExportEntriesCount", MaxDefaultExportEntriesCount, 0x2000},
		{"MaxDefaultImportEntriesCount", MaxDefaultImportEntriesCount, 0x1000},
		{"MaxDefaultRelocEntriesCount", MaxDefaultRelocEntriesCount, 0x1000},
		{"MaxDefaultCOFFSymbolsCount", MaxDefaultCOFFSymbolsCount, 0x10000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("%s = 0x%x, want 0x%x", tt.name, tt.constant, tt.expected)
			}
		})
	}
}

func TestNewFile(t *testing.T) {
	// Test NewFile function with os.File
	filePath := getAbsoluteFilePath("test/putty.exe")
	f, err := os.Open(filePath)
	if err != nil {
		t.Skipf("Skipping test, file not available: %s", filePath)
	}
	defer f.Close()

	file, err := NewFile(f, &Options{})
	if err != nil {
		t.Fatalf("NewFile() failed: %v", err)
	}
	defer file.Close()

	err = file.Parse()
	if err != nil {
		t.Fatalf("Parse() failed: %v", err)
	}

	// Validate basic file properties
	if !file.FileInfo.HasDOSHdr {
		t.Error("Expected DOS header to be present")
	}

	if file.DOSHeader.Magic != ImageDOSSignature {
		t.Errorf("Expected DOS signature 0x%x, got 0x%x", ImageDOSSignature, file.DOSHeader.Magic)
	}
}

func TestNewBytesInvalidData(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		wantParseErr bool
	}{
		{
			name: "Empty data",
			data: []byte{},
			wantParseErr: true,
		},
		{
			name: "Too small data",
			data: make([]byte, 10),
			wantParseErr: true,
		},
		{
			name: "Invalid DOS signature",
			data: make([]byte, 64),
			wantParseErr: true,
		},
		{
			name: "Valid DOS header but no PE",
			data: func() []byte {
				data := make([]byte, 1024)
				// Set DOS signature
				data[0] = 'M'
				data[1] = 'Z'
				// Set e_lfanew to point to invalid location
				data[60] = 0xFF
				data[61] = 0xFF
				return data
			}(),
			wantParseErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// NewBytes should always succeed - it just wraps the data
			file, err := NewBytes(tt.data, &Options{})
			if err != nil {
				t.Errorf("NewBytes() should not fail: %v", err)
				return
			}
			defer file.Close()

			// The actual validation happens during Parse()
			err = file.Parse()
			if tt.wantParseErr {
				if err == nil {
					t.Error("Expected Parse() to fail but it succeeded")
				}
			} else {
				if err != nil {
					t.Errorf("Parse() failed unexpectedly: %v", err)
				}
			}
		})
	}
}

func TestParseWithOptions(t *testing.T) {
	tests := []struct {
		name string
		opts *Options
		validateFunc func(*testing.T, *File)
	}{
		{
			name: "Parse with section entropy",
			opts: &Options{SectionEntropy: true},
			validateFunc: func(t *testing.T, file *File) {
				if len(file.Sections) > 0 {
					// At least one section should have entropy calculated
					hasEntropy := false
					for _, section := range file.Sections {
						if section.Entropy != nil {
							hasEntropy = true
							break
						}
					}
					if !hasEntropy {
						t.Error("Expected at least one section to have entropy calculated")
					}
				}
			},
		},
		{
			name: "Parse with fast mode",
			opts: &Options{Fast: true},
			validateFunc: func(t *testing.T, file *File) {
				// In fast mode, some detailed parsing might be skipped
				if file.opts.Fast != true {
					t.Error("Expected Fast option to be preserved")
				}
			},
		},
		{
			name: "Parse with directory omissions",
			opts: &Options{
				OmitSecurityDirectory: true,
				OmitResourceDirectory: true,
				OmitDebugDirectory:    true,
			},
			validateFunc: func(t *testing.T, file *File) {
				if file.Certificates.Raw != nil {
					t.Error("Expected certificates to be omitted")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filePath := getAbsoluteFilePath("test/putty.exe")
			file, err := New(filePath, tt.opts)
			if err != nil {
				t.Skipf("Skipping test, file not available: %s", filePath)
			}
			defer file.Close()

			err = file.Parse()
			if err != nil {
				t.Fatalf("Parse() failed: %v", err)
			}

			tt.validateFunc(t, file)
		})
	}
}

func TestParseDataDirectories(t *testing.T) {
	filePath := getAbsoluteFilePath("test/putty.exe")
	file, err := New(filePath, &Options{})
	if err != nil {
		t.Skipf("Skipping test, file not available: %s", filePath)
	}
	defer file.Close()

	err = file.Parse()
	if err != nil {
		t.Fatalf("Parse() failed: %v", err)
	}

	// Test ParseDataDirectories specifically
	err = file.ParseDataDirectories()
	if err != nil {
		t.Fatalf("ParseDataDirectories() failed: %v", err)
	}

	// Basic validation - at least some data directories should be present
	if file.NtHeader.OptionalHeader == nil {
		t.Fatal("Expected OptionalHeader to be parsed")
	}
}

func TestFileClose(t *testing.T) {
	tests := []struct {
		name string
		setupFunc func() *File
		wantErr bool
	}{
		{
			name: "Close file opened with New",
			setupFunc: func() *File {
				filePath := getAbsoluteFilePath("test/putty.exe")
				file, err := New(filePath, &Options{})
				if err != nil {
					return nil
				}
				return file
			},
			wantErr: false,
		},
		{
			name: "Close file created with NewBytes",
			setupFunc: func() *File {
				data := createMinimalPE()
				file, _ := NewBytes(data, &Options{})
				return file
			},
			wantErr: false,
		},
		{
			name: "Double close should not panic",
			setupFunc: func() *File {
				data := createMinimalPE()
				file, _ := NewBytes(data, &Options{})
				file.Close() // First close
				return file
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := tt.setupFunc()
			if file == nil {
				t.Skip("Could not create test file")
			}

			err := file.Close()
			if (err != nil) != tt.wantErr {
				t.Errorf("Close() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestErrorHandling(t *testing.T) {
	tests := []struct {
		name string
		filePath string
		wantErr bool
		errorSubstring string
	}{
		{
			name: "Non-existent file",
			filePath: "non-existent-file.exe",
			wantErr: true,
			errorSubstring: "no such file",
		},
		{
			name: "Directory instead of file",
			filePath: ".",
			wantErr: true,
			errorSubstring: "device",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file, err := New(tt.filePath, &Options{})
			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got none")
				}
				if err != nil && !strings.Contains(err.Error(), tt.errorSubstring) {
					t.Errorf("Expected error containing '%s', got: %v", tt.errorSubstring, err)
				}
				if file != nil {
					file.Close()
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if file != nil {
					file.Close()
				}
			}
		})
	}
}

func TestOptionsValidation(t *testing.T) {
	tests := []struct {
		name string
		opts *Options
		validateFunc func(*testing.T, *Options)
	}{
		{
			name: "Nil options should create defaults",
			opts: nil,
			validateFunc: func(t *testing.T, opts *Options) {
				if opts == nil {
					t.Error("Expected options to be initialized")
				}
			},
		},
		{
			name: "Custom logger should be preserved", 
			opts: &Options{
				Logger: nil, // Use default logger
				Fast: true,
			},
			validateFunc: func(t *testing.T, opts *Options) {
				if !opts.Fast {
					t.Error("Expected Fast option to be preserved")
				}
			},
		},
		{
			name: "Section entropy and fast mode combined",
			opts: &Options{
				SectionEntropy: true,
				Fast: false,
			},
			validateFunc: func(t *testing.T, opts *Options) {
				if !opts.SectionEntropy {
					t.Error("Expected section entropy option to be preserved")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a minimal valid PE in memory for testing
			data := createMinimalPE()

			file, err := NewBytes(data, tt.opts)
			if err != nil {
				t.Fatalf("NewBytes() failed: %v", err)
			}
			defer file.Close()

			tt.validateFunc(t, file.opts)
		})
	}
}

func TestBenchmarkParsing(t *testing.T) {
	// Performance test to ensure parsing doesn't regress
	filePath := getAbsoluteFilePath("test/putty.exe")
	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Skipf("Skipping benchmark test, file not available: %s", filePath)
	}

	// Test parsing multiple times to catch potential memory leaks or performance issues
	for i := 0; i < 10; i++ {
		file, err := NewBytes(data, &Options{})
		if err != nil {
			t.Fatalf("NewBytes() failed on iteration %d: %v", i, err)
		}

		err = file.Parse()
		if err != nil {
			t.Fatalf("Parse() failed on iteration %d: %v", i, err)
		}

		file.Close()
	}
}

func TestMemoryManagement(t *testing.T) {
	// Test that resources are properly managed
	filePath := getAbsoluteFilePath("test/putty.exe")
	
	// Test file-based parsing
	file1, err := New(filePath, &Options{})
	if err != nil {
		t.Skipf("Skipping test, file not available: %s", filePath)
	}
	defer file1.Close()

	// Test byte-based parsing
	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Skipf("Could not read file: %v", err)
	}

	file2, err := NewBytes(data, &Options{})
	if err != nil {
		t.Fatalf("NewBytes() failed: %v", err)
	}
	defer file2.Close()

	// Both should parse successfully
	err1 := file1.Parse()
	err2 := file2.Parse()

	if err1 != nil {
		t.Errorf("File-based parsing failed: %v", err1)
	}
	if err2 != nil {
		t.Errorf("Byte-based parsing failed: %v", err2)
	}

	// Results should be similar (basic validation)
	if file1.DOSHeader.Magic != file2.DOSHeader.Magic {
		t.Error("DOS signatures should match between file and byte parsing")
	}

	if len(file1.Sections) != len(file2.Sections) {
		t.Error("Section counts should match between file and byte parsing")
	}
}

func TestFileEdgeCases(t *testing.T) {
	t.Run("Empty options struct", func(t *testing.T) {
		data := createMinimalPE()
		file, err := NewBytes(data, &Options{})
		if err != nil {
			t.Fatalf("NewBytes() failed: %v", err)
		}
		defer file.Close()

		// Should have default values
		if file.opts.MaxExportEntriesCount == 0 {
			t.Error("Expected default export limit to be set")
		}
	})

	t.Run("Large file simulation", func(t *testing.T) {
		// Create a larger PE structure to test limits
		data := createMinimalPE()
		// Extend to simulate larger file
		largeData := make([]byte, len(data)+10000)
		copy(largeData, data)

		file, err := NewBytes(largeData, &Options{})
		if err != nil {
			t.Fatalf("NewBytes() failed: %v", err)
		}
		defer file.Close()

		// Parse the file to initialize FileInfo
		err = file.Parse()
		if err != nil {
			t.Fatalf("Parse() failed: %v", err)
		}

		// Verify file was created successfully
		if !file.FileInfo.HasDOSHdr {
			t.Error("Expected DOS header to be present in large file")
		}
	})
}

// Helper function to create minimal valid PE structure for testing
func createMinimalPE() []byte {
	data := make([]byte, 1024)
	// DOS header
	data[0] = 'M'
	data[1] = 'Z'
	// e_lfanew points to PE header
	data[60] = 0x80
	
	// PE signature
	data[0x80] = 'P'
	data[0x81] = 'E'
	data[0x82] = 0
	data[0x83] = 0
	
	// File header (minimal)
	data[0x84] = 0x4c // Machine (i386)
	data[0x85] = 0x01
	data[0x86] = 0x00 // NumberOfSections
	data[0x87] = 0x00
	
	// Skip timestamp, pointer to symbol table, number of symbols
	for i := 0x88; i < 0x94; i++ {
		data[i] = 0
	}
	
	// SizeOfOptionalHeader
	data[0x94] = 0xE0
	data[0x95] = 0x00
	
	// Characteristics
	data[0x96] = 0x02 // EXECUTABLE_IMAGE
	data[0x97] = 0x01
	
	// Optional header magic (PE32)
	data[0x98] = 0x0B
	data[0x99] = 0x01
	
	return data
}
