package main

import (
	"encoding/binary"
	"github.com/minio/minio-go"
)

type BinaryFlashDescriptor struct {
	HeaderOffset uint32
	Version      uint32
	Header       BinaryFlashDescriptorHeader
	OEM          [0x40]uint8
	FR           BinaryFR
	FC           BinaryFC
	FPS          BinaryFPS
	FM           BinaryFM
	FMS          BinaryFMS
	VSCC         []BinaryVSCC
}

type BinaryFlashDescriptorHeader struct {
	Flvalsig uint32
	Flmap0   uint32
	Flmap1   uint32
	Flmap2   uint32
	Reserved [3804 / 4]uint32
	Flumap1  uint32
}

type BinaryFR struct {
	Flreg [9]uint32
}

type BinaryFC struct {
	Flcomp uint32
	Flill  uint32
	Flpb   uint32
}

type BinaryFPS struct {
	Pchstrp [18]uint32
}

type BinaryFM struct {
	Flmstr1 uint32
	Flmstr2 uint32
	Flmstr3 uint32
	Flmstr4 uint32
	Flmstr5 uint32
}

type BinaryFMS struct {
	Data [8]uint32
}
type BinaryVSCC struct {
	Jid  uint32
	Vscc uint32
}

func readBinaryIFD(reader *minio.Object, offset int64) BinaryFlashDescriptor {

	var FlashDescriptor BinaryFlashDescriptor

	Bundle.Log.Infof("Reading FD")
	reader.Seek(offset, 0)

	FlashDescriptor.HeaderOffset = uint32(offset)
	FlashDescriptor.Header = readIFDHeader(reader)

	frba := ((FlashDescriptor.Header.Flmap0 >> 16) & 0xFF) << 4
	var fr BinaryFR
	reader.Seek(int64(frba), 0)
	binary.Read(reader, binary.LittleEndian, &fr)
	FlashDescriptor.FR = fr

	fcba := (FlashDescriptor.Header.Flmap0 & 0xFF) << 4
	var fc BinaryFC
	reader.Seek(int64(fcba), 0)
	binary.Read(reader, binary.LittleEndian, &fc)
	FlashDescriptor.FC = fc

	if FlashDescriptor.Version == 0 {
		//IFD Version 1 is using 20MHZ
		readFreq := (FlashDescriptor.FC.Flcomp >> 17) & 7
		if readFreq == 0 {
			FlashDescriptor.Version = 1
		} else {
			FlashDescriptor.Version = 2
		}
		Bundle.Log.Infof("Guessed IFDVersion to be %d\n", FlashDescriptor.Version)
	}

	fpsba := ((FlashDescriptor.Header.Flmap1 >> 16) & 0xFF) << 4
	var fps BinaryFPS
	reader.Seek(int64(fpsba), 0)
	binary.Read(reader, binary.LittleEndian, &fps)
	FlashDescriptor.FPS = fps

	fmba := ((FlashDescriptor.Header.Flmap1) & 0xFF) << 4
	var fm BinaryFM
	reader.Seek(int64(fmba), 0)
	binary.Read(reader, binary.LittleEndian, &fm)
	FlashDescriptor.FM = fm

	fmsba := ((FlashDescriptor.Header.Flmap2) & 0xFF) << 4
	var fms BinaryFMS
	reader.Seek(int64(fmsba), 0)
	binary.Read(reader, binary.LittleEndian, &fms)
	FlashDescriptor.FMS = fms

	vtl := (FlashDescriptor.Header.Flumap1 >> 8) & 0xFF
	vtba := (FlashDescriptor.Header.Flumap1 & 0xFF) << 4

	reader.Seek(int64(vtba), 0)
	for i := uint32(0); i < vtl; i++ {
		var Vscc BinaryVSCC
		binary.Read(reader, binary.LittleEndian, &Vscc)
		FlashDescriptor.VSCC = append(FlashDescriptor.VSCC, Vscc)
	}

	reader.Seek(0xF00, 0)
	binary.Read(reader, binary.LittleEndian, &FlashDescriptor.OEM)

	return FlashDescriptor
}

func readIFDHeader(reader *minio.Object) BinaryFlashDescriptorHeader {

	var fd BinaryFlashDescriptorHeader
	binary.Read(reader, binary.LittleEndian, &fd)
	return fd
}
