// Copyright 2024 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"strings"
	"testing"
)

func TestArchitectureDirectoryParsing(t *testing.T) {
	tests := []struct {
		name        string
		rva         uint32
		size        uint32
		expectLog   bool
		expectAnomaly bool
	}{
		{
			name:        "Empty directory (common case)",
			rva:         0,
			size:        0,
			expectLog:   false,
			expectAnomaly: false,
		},
		{
			name:        "Architecture directory with data",
			rva:         0x1000,
			size:        0x100,
			expectLog:   true,
			expectAnomaly: true,
		},
		{
			name:        "Zero RVA with size",
			rva:         0,
			size:        0x100,
			expectLog:   false,
			expectAnomaly: false,
		},
		{
			name:        "RVA with zero size",
			rva:         0x1000,
			size:        0,
			expectLog:   false,
			expectAnomaly: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a minimal PE file for testing
			file := &File{
				Anomalies: []string{},
				NtHeader: ImageNtHeader{
					FileHeader: ImageFileHeader{
						Machine: ImageFileMachineARM64X, // Use ARM64X to test hybrid PE logic
					},
				},
			}
			// Set up a basic logger - we'll use nil since the function handles it gracefully
			file.logger = nil

			err := file.parseArchitectureDirectory(tt.rva, tt.size)
			if err != nil {
				t.Errorf("parseArchitectureDirectory() error = %v", err)
				return
			}

			// Check if anomaly was added when expected
			hasAnomaly := len(file.Anomalies) > 0
			if hasAnomaly != tt.expectAnomaly {
				t.Errorf("Expected anomaly = %v, got = %v", tt.expectAnomaly, hasAnomaly)
			}

			// If anomaly is expected, check it contains relevant information
			if tt.expectAnomaly && hasAnomaly {
				anomaly := file.Anomalies[0]
				if !strings.Contains(anomaly, "Architecture directory") {
					t.Errorf("Anomaly should mention architecture directory, got: %s", anomaly)
				}
				if !strings.Contains(anomaly, "not fully parsed") {
					t.Errorf("Anomaly should mention parsing status, got: %s", anomaly)
				}
			}
		})
	}
}

func TestArchitectureDirectoryForDifferentMachineTypes(t *testing.T) {
	tests := []struct {
		name        string
		machineType ImageFileHeaderMachineType
		rva         uint32
		size        uint32
		description string
	}{
		{
			name:        "ARM64X with architecture data",
			machineType: ImageFileMachineARM64X,
			rva:         0x1000,
			size:        0x100,
			description: "Should handle ARM64X dual-architecture metadata",
		},
		{
			name:        "ARM64EC with architecture data",
			machineType: ImageFileMachineARM64EC,
			rva:         0x2000,
			size:        0x200,
			description: "Should handle ARM64EC emulation metadata",
		},
		{
			name:        "x64 with architecture data (unusual)",
			machineType: ImageFileMachineAMD64,
			rva:         0x3000,
			size:        0x50,
			description: "Should handle unexpected architecture data on x64",
		},
		{
			name:        "i386 with no architecture data (normal)",
			machineType: ImageFileMachineI386,
			rva:         0,
			size:        0,
			description: "Should handle normal case for i386",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := &File{
				Anomalies: []string{},
				NtHeader: ImageNtHeader{
					FileHeader: ImageFileHeader{
						Machine: tt.machineType,
					},
				},
			}
			file.logger = nil

			err := file.parseArchitectureDirectory(tt.rva, tt.size)
			if err != nil {
				t.Errorf("parseArchitectureDirectory() error = %v", err)
			}

			// Architecture directory with data should always generate an anomaly
			// since it's not fully implemented yet
			expectAnomaly := tt.rva != 0 && tt.size != 0
			hasAnomaly := len(file.Anomalies) > 0

			if hasAnomaly != expectAnomaly {
				t.Errorf("Machine type %s: expected anomaly = %v, got = %v", 
					tt.machineType.String(), expectAnomaly, hasAnomaly)
			}
		})
	}
}

// Mock logger for testing
type mockLogger struct {
	lastMessage string
	lastLevel   string
}

func (m *mockLogger) Info(msg string, keyvals ...interface{}) {
	m.lastMessage = msg
	m.lastLevel = "info"
}

func (m *mockLogger) Error(msg string, keyvals ...interface{}) {
	m.lastMessage = msg
	m.lastLevel = "error"
}

func (m *mockLogger) Debug(msg string, keyvals ...interface{}) {
	m.lastMessage = msg
	m.lastLevel = "debug"
}

func (m *mockLogger) Warn(msg string, keyvals ...interface{}) {
	m.lastMessage = msg
	m.lastLevel = "warn"
}