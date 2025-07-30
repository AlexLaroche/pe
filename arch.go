// Copyright 2022 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import "fmt"

// Architecture-specific data. This data directory is not used
// (set to all zeros) for I386, IA64, or AMD64 architecture.
// For hybrid PE files (ARM64X, ARM64EC), this may contain architecture metadata.
func (pe *File) parseArchitectureDirectory(rva, size uint32) error {
	// Skip parsing if directory is empty (common case)
	if rva == 0 || size == 0 {
		return nil
	}
	
	// For hybrid PE files, architecture directory may contain:
	// - Code integrity metadata for dual-architecture binaries
	// - ARM64EC thunk information
	// - Architecture-specific configuration data
	
	// Currently, the Microsoft PE specification doesn't define a standard
	// structure for this directory. Implementation would depend on specific
	// use cases and reverse engineering of existing ARM64X/ARM64EC binaries.
	
	// Log that architecture directory is present but not fully parsed
	if pe.logger != nil {
		pe.logger.Info("Architecture directory present but parsing not implemented", 
			"rva", rva, "size", size, "machine", pe.NtHeader.FileHeader.Machine.String())
	}
	
	// Mark as anomaly for further investigation
	pe.Anomalies = append(pe.Anomalies, 
		fmt.Sprintf("Architecture directory present at RVA 0x%x (size: %d bytes) - not fully parsed", rva, size))
	
	return nil
}
