package main

import (
	"github.com/Mimoja/MFT-Common"
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"strconv"
)

func analyse(entry MFTCommon.FlashImage) error {
	Bundle.Log.WithField("entry", entry).Infof("Searching for IFD :  %s ", entry.ID.GetID())
	// Check for IFD Header
	IFD_HEADER, _ := hex.DecodeString("5aa5f00f")

	reader, err := Bundle.Storage.GetFile(entry.ID.GetID())
	if err != nil {
		Bundle.Log.WithField("entry", entry).
			WithError(err).
			Errorf("could not fetch file: %s : %v", entry.ID.GetID(), err)
		return err
	}
	defer reader.Close()

	bts, err := ioutil.ReadAll(reader)

	if err != nil {
		Bundle.Log.WithField("entry", entry).
			WithError(err).
			Errorf("Cannot read file: %v", err)
		return err
	}

	headerBytes := bts[:0x20]

	//println("Headerbytes are: " + hex.Dump(headerBytes))

	var magicOffset int64

	// Old images start with IFD header
	if bytes.Equal(headerBytes[:4], IFD_HEADER) {
		Bundle.Log.WithField("entry", entry).Infof("Found old intel flash image")
		magicOffset = 0
	} else if bytes.Equal(headerBytes[0x10:0x10+4], IFD_HEADER) {
		Bundle.Log.WithField("entry", entry).Infof("Found new intel flash image")
		magicOffset = 0x10
	} else {
		Bundle.Log.WithField("entry", entry).Infof("Could not find Flash Header\n")
		entry.FirmwareOffset = 0
		_, err = Bundle.DB.ES.Update().
			Index("flashimages").
			Type("flashimage").
			Id(entry.ID.GetID()).
			Doc(map[string]interface{}{"IFD": nil, "FirmwareOffset": entry.FirmwareOffset}).
			Do(context.Background())

		if err != nil {
			Bundle.Log.WithField("entry", entry).
				WithError(err).
				Errorf("Cannot update FlashOffset: %v", err)
			return err
		}
		return Bundle.MessageQueue.BiosImagesQueue.MarshalAndSend(entry)
	}

	fd := readBinaryIFD(reader, magicOffset)
	pfd := parseBinary(fd)

	// write BIOS and ME

	region, _, _, _ := MFTCommon.GetRegionByNumber(pfd, 1)
	start, _, err := getRegionLimits(region)

	if err != nil {
		Bundle.Log.WithField("entry", entry).
			WithError(err).
			Errorf("Cannot get region limits: %v", err)
		return err
	}

	entry.FirmwareOffset = start
	entry.INTEL = &MFTCommon.IntelFirmware{IFD: &pfd}

	//TODO handle ME

	_, err = Bundle.DB.ES.Update().
		Index("flashimages").
		Type("flashimage").
		Id(entry.ID.GetID()).
		Doc(map[string]interface{}{"INTEL": entry.INTEL, "FirmwareOffset": entry.FirmwareOffset}).
		Do(context.Background())

	if err != nil {
		Bundle.Log.WithField("entry", entry).
			WithError(err).
			Errorf("Cannot update ifd: %v", err)
		return err
	}

	return nil
}

func getRegionLimits(region MFTCommon.RegionSectionEntry) (int64, int64, error) {
	start, _ := strconv.ParseInt(region.START, 0, 64)
	end, _ := strconv.ParseInt(region.END, 0, 64)
	erro, _ := strconv.ParseInt("0x00FFF000", 0, 64)

	iserror := start >= erro || start >= end

	//TODO is  (start | error) always 0x00FFFFFF when unused?
	var err error
	if iserror {
		err = fmt.Errorf("unused Region")
	}

	return start, end, err
}

func parseBinary(descriptor BinaryFlashDescriptor) MFTCommon.IntelFlashDescriptor {
	var fd MFTCommon.IntelFlashDescriptor

	fd.HeaderOffset = descriptor.HeaderOffset
	fd.Version = descriptor.Version

	fd.HEADER = MFTCommon.FlashDescriptorHeader{
		FLVALSIG: toHexString(descriptor.Header.Flvalsig, 8),
		FLMAP0: MFTCommon.FlashDescriptorHeaderFLMAP0{
			RESERVED0: getBits(descriptor.Header.Flmap0, 27, 31),
			NR:        getBits(descriptor.Header.Flmap0, 24, 26),
			FRBA:      toHexString(getBits(descriptor.Header.Flmap0, 16, 23)<<4, 0),
			RESERVED2: getBits(descriptor.Header.Flmap0, 13, 15),
			RESERVED3: getBits(descriptor.Header.Flmap0, 12, 12),
			RESERVED4: getBits(descriptor.Header.Flmap0, 11, 11),
			RESERVED5: getBits(descriptor.Header.Flmap0, 10, 10),
			NC:        getBits(descriptor.Header.Flmap0, 8, 9) + 1,
			FCBA:      toHexString(getBits(descriptor.Header.Flmap0, 0, 7)<<4, 0),
		},
		FLMAP1: MFTCommon.FlashDescriptorHeaderFLMAP1{
			ISL:       toHexString(getBits(descriptor.Header.Flmap1, 24, 31), 8),
			FPSBA:     toHexString(getBits(descriptor.Header.Flmap1, 16, 23)<<4, 2),
			RESERVED0: getBits(descriptor.Header.Flmap1, 11, 15),
			NM:        getBits(descriptor.Header.Flmap1, 8, 10),
			FMBA:      toHexString(getBits(descriptor.Header.Flmap1, 0, 7)<<4, 0),
		},
		FLMAP2: MFTCommon.FlashDescriptorHeaderFLMAP2{
			RIL:     toHexString(getBits(descriptor.Header.Flmap2, 24, 31), 8),
			ICCRIBA: toHexString(getBits(descriptor.Header.Flmap2, 16, 23), 4),
			PSL:     toHexString(getBits(descriptor.Header.Flmap2, 8, 15), 4),
			FMSBA:   toHexString(getBits(descriptor.Header.Flmap2, 0, 7)<<4, 0),
		},
		RESERVED: descriptor.Header.Reserved,
		FLUMAP1: MFTCommon.FlashDescriptorHeaderFLUMAP1{
			RESERVED0: getBits(descriptor.Header.Flumap1, 16, 31),
			VTL:       getBits(descriptor.Header.Flumap1, 8, 15),
			VTBA:      toHexString(getBits(descriptor.Header.Flumap1, 0, 7)<<4, 6),
		},
	}

	fd.OEM = descriptor.OEM

	var maxRegions int
	var base_mask uint32

	if fd.Version == 1 {
		maxRegions = 5
		base_mask = uint32(0xfff)
	} else {
		maxRegions = 9
		base_mask = uint32(0x7fff)
	}

	limit_mask := uint32(base_mask << 16)

	for i := 0; i < maxRegions; i++ {
		var regionData = descriptor.FR.Flreg[i]

		rs := MFTCommon.RegionSectionEntry{
			START: toHexString((regionData&base_mask)<<12, 8),
			END:   toHexString(((regionData&limit_mask)>>4)|0xfff, 8),
		}

		switch i {
		case 0:
			fd.REGION.FLASH = rs
			break

		case 1:
			fd.REGION.BIOS = rs
			break

		case 2:
			fd.REGION.ME = rs
			break

		case 3:
			fd.REGION.ETHERNET = rs
			break

		case 4:
			fd.REGION.PLATFORM = rs
			break

		case 5:
			fd.REGION.EXPANSION = rs
			break

		case 6:
			fd.REGION.RESERVED2 = rs
			break

		case 7:
			fd.REGION.RESERVED3 = rs
			break

		case 8:
			fd.REGION.EC = rs
			break
		}
	}

	var componentSize uint8

	if fd.Version == 1 {
		componentSize = 3
	} else {
		componentSize = 4
	}
	cs := MFTCommon.ComponentSection{
		FLCOMP: MFTCommon.ComponentSectionFLCOMP{
			DualOutputFastReadSupport:  isBitSet(descriptor.FC.Flcomp, 30),
			ReadIDStatusClockFrequency: getSPIFrequency(getBits(descriptor.FC.Flcomp, 27, 29), fd.Version),
			WriteEraseClockFrequency:   getSPIFrequency(getBits(descriptor.FC.Flcomp, 24, 26), fd.Version),
			FastReadClockFrequency:     getSPIFrequency(getBits(descriptor.FC.Flcomp, 21, 23), fd.Version),
			FastReadSupport:            isBitSet(descriptor.FC.Flcomp, 20),
			ReadClockFrequency:         getSPIFrequency(getBits(descriptor.FC.Flcomp, 17, 19), fd.Version),
			Component1Density:          getDensity(getBits(descriptor.FC.Flcomp, 0, componentSize-1)),
			Component2Density:          getDensity(getBits(descriptor.FC.Flcomp, componentSize, componentSize*2-1)),
		},

		FLILL: MFTCommon.ComponentSectionFLILL{
			InvalidInstruction0: toHexString(getBits(descriptor.FC.Flill, 0, 7), 2),
			InvalidInstruction1: toHexString(getBits(descriptor.FC.Flill, 8, 15), 2),
			InvalidInstruction2: toHexString(getBits(descriptor.FC.Flill, 16, 23), 2),
			InvalidInstruction3: toHexString(getBits(descriptor.FC.Flill, 24, 31), 2),
		},
		FLPB: MFTCommon.ComponentSectionFLPB{
			FlashPartitionBoundaryAddress: toHexString(getBits(descriptor.FC.Flpb, 0, 15)<<12, 8),
		},
	}
	fd.COMPONENT = cs

	for i := 0; i < len(descriptor.FPS.Pchstrp); i++ {
		fd.PCHSTRAP[i] = toHexString(descriptor.FPS.Pchstrp[i], 8)
	}

	fd.MASTER = MFTCommon.MasterSection{
		BIOS:     parseFLMSTR(descriptor.FM.Flmstr1, fd.Version),
		ME:       parseFLMSTR(descriptor.FM.Flmstr2, fd.Version),
		ETHERNET: parseFLMSTR(descriptor.FM.Flmstr3, fd.Version),
		RESERVED: parseFLMSTR(descriptor.FM.Flmstr4, fd.Version),
		EC:       parseFLMSTR(descriptor.FM.Flmstr5, fd.Version),
	}

	for index, element := range descriptor.FMS.Data {
		fd.STRAP[index] = toHexString(element, 8)
	}

	for i := 0; i < len(descriptor.VSCC); i++ {
		Vscc := descriptor.VSCC[i]
		var mfc MFTCommon.MEFlashControl

		mfc.COMPONENT.DeviceID0 = toHexString(getBits(Vscc.Jid, 8, 15), 2)
		mfc.COMPONENT.DeviceID1 = toHexString(getBits(Vscc.Jid, 16, 23), 2)
		mfc.COMPONENT.VendorID = toHexString(getBits(Vscc.Jid, 0, 7), 2)

		mfc.CONTROL.LowerEraseOpcode = toHexString(getBits(Vscc.Vscc, 24, 31), 2)
		if Vscc.Vscc&(1<<20) != 0 {
			mfc.CONTROL.LowerWriteEnableOnWriteStatus = "0x06"
		} else {
			mfc.CONTROL.LowerWriteEnableOnWriteStatus = "0x50"
		}

		if Vscc.Vscc&(1<<19) != 0 {
			mfc.CONTROL.LowerWriteStatusRequired = true
		} else {
			mfc.CONTROL.LowerWriteStatusRequired = false
		}

		if Vscc.Vscc&(1<<18) != 0 {
			mfc.CONTROL.LowerWriteGranularity = 64
		} else {
			mfc.CONTROL.LowerWriteGranularity = 1
		}
		switch (Vscc.Vscc >> 16) & 3 {
		case 0:
			mfc.CONTROL.LowerBlockAndSectorEraseSize = "0x00FF"
			break
		case 1:
			mfc.CONTROL.LowerBlockAndSectorEraseSize = "0x1000"
			break
		case 2:
			mfc.CONTROL.LowerBlockAndSectorEraseSize = "0x2000"
			break
		case 3:
			mfc.CONTROL.LowerBlockAndSectorEraseSize = "0x8000"
			break
		}

		mfc.CONTROL.UpperEraseOpcode = toHexString(getBits(Vscc.Vscc, 8, 15), 2)
		if Vscc.Vscc&(1<<4) != 0 {
			mfc.CONTROL.UpperWriteEnableOnWriteStatus = "0x06"
		} else {
			mfc.CONTROL.UpperWriteEnableOnWriteStatus = "0x50"
		}

		if Vscc.Vscc&(1<<3) != 0 {
			mfc.CONTROL.UpperWriteStatusRequired = true
		} else {
			mfc.CONTROL.UpperWriteStatusRequired = false
		}

		if Vscc.Vscc&(1<<2) != 0 {
			mfc.CONTROL.UpperWriteGranularity = 64
		} else {
			mfc.CONTROL.UpperWriteGranularity = 1
		}
		switch (Vscc.Vscc) & 3 {
		case 0:
			mfc.CONTROL.UpperBlockAndSectorEraseSize = "0x00FF"
			break
		case 1:
			mfc.CONTROL.UpperBlockAndSectorEraseSize = "0x1000"
			break
		case 2:
			mfc.CONTROL.UpperBlockAndSectorEraseSize = "0x2000"
			break
		case 3:
			mfc.CONTROL.UpperBlockAndSectorEraseSize = "0x8000"
			break
		}

		fd.FLASHCONTROL = append(fd.FLASHCONTROL, mfc)
	}

	return fd
}

func getSPIFrequency(freq uint32, ifdversion uint32) uint32 {

	SPI_FREQUENCY_20MHZ := 0
	SPI_FREQUENCY_33MHZ := 1
	SPI_FREQUENCY_48MHZ := 2
	SPI_FREQUENCY_50MHZ_30MHZ := 4
	SPI_FREQUENCY_17MHZ := 6

	switch int(freq) {
	case SPI_FREQUENCY_20MHZ:
		return 20
		break
	case SPI_FREQUENCY_33MHZ:
		return 33
		break
	case SPI_FREQUENCY_48MHZ:
		return 48
		break
	case SPI_FREQUENCY_50MHZ_30MHZ:
		// this can technically never happen, as long as the IFD version is guessed!
		if ifdversion == 1 {
			return 30
		} else {
			return 50
		}
		break
	case SPI_FREQUENCY_17MHZ:
		return 17

	}
	return 0
}

func getDensity(density uint32) uint32 {
	COMPONENT_DENSITY_512KB := 0
	COMPONENT_DENSITY_1MB := 1
	COMPONENT_DENSITY_2MB := 2
	COMPONENT_DENSITY_4MB := 3
	COMPONENT_DENSITY_8MB := 4
	COMPONENT_DENSITY_16MB := 5
	COMPONENT_DENSITY_32MB := 6
	COMPONENT_DENSITY_64MB := 7
	COMPONENT_DENSITY_UNUSED := 0xf

	switch int(density) {
	case COMPONENT_DENSITY_512KB:
		return 1 << 19

	case COMPONENT_DENSITY_1MB:
		return 1 << 20

	case COMPONENT_DENSITY_2MB:
		return 1 << 21

	case COMPONENT_DENSITY_4MB:
		return 1 << 22

	case COMPONENT_DENSITY_8MB:
		return 1 << 23

	case COMPONENT_DENSITY_16MB:
		return 1 << 24

	case COMPONENT_DENSITY_32MB:
		return 1 << 25

	case COMPONENT_DENSITY_64MB:
		return 1 << 26

	case COMPONENT_DENSITY_UNUSED:
		return 0

	}
	return 0xFFFFFFFF
}

func parseFLMSTR(flmstr uint32, ifdVersion uint32) MFTCommon.MasterSectionEntry {
	var wr_shift uint32
	var rd_shift uint32

	FLMSTR_WR_SHIFT_V1 := uint32(24)
	FLMSTR_RD_SHIFT_V1 := uint32(16)

	FLMSTR_WR_SHIFT_V2 := uint32(20)
	FLMSTR_RD_SHIFT_V2 := uint32(8)

	if ifdVersion == 1 {
		wr_shift = FLMSTR_WR_SHIFT_V1
		rd_shift = FLMSTR_RD_SHIFT_V1
	} else {
		wr_shift = FLMSTR_WR_SHIFT_V2
		rd_shift = FLMSTR_RD_SHIFT_V2
	}

	entry := MFTCommon.MasterSectionEntry{
		FlashDescriptorReadAccess:     isBitSet(flmstr, rd_shift+0),
		FlashDescriptorWriteAccess:    isBitSet(flmstr, wr_shift+0),
		HostCPUBIOSRegionReadAccess:   isBitSet(flmstr, rd_shift+1),
		HostCPUBIOSRegionWriteAccess:  isBitSet(flmstr, wr_shift+1),
		IntelMERegionReadAccess:       isBitSet(flmstr, rd_shift+2),
		IntelMERegionWriteAccess:      isBitSet(flmstr, wr_shift+2),
		GbERegionReadAccess:           isBitSet(flmstr, rd_shift+3),
		GbERegionWriteAccess:          isBitSet(flmstr, wr_shift+3),
		PlatformDataRegionReadAccess:  isBitSet(flmstr, rd_shift+4),
		PlatformDataRegionWriteAccess: isBitSet(flmstr, wr_shift+4),
		ECRegionReadAccess:            isBitSet(flmstr, rd_shift+8),
		ECRegionWriteAccess:           isBitSet(flmstr, wr_shift+8),
		RequesterID:                   toHexString(getBits(flmstr, 0, 15), 8),
	}
	return entry
}

func isBitSet(val uint32, bit uint32) bool {
	return (val & (1 << bit)) != 0
}

func toHexString(val uint32, zeroFilll uint32) string {
	formatString := fmt.Sprintf("0x%%0%dX", zeroFilll)
	return fmt.Sprintf(formatString, val)
}

func getBits(val uint32, start uint8, end uint8) uint32 {
	var mask uint32

	for i := 0; i <= int(end-start); i++ {
		mask <<= 1
		mask |= 1
	}

	return (val >> start) & mask
}
