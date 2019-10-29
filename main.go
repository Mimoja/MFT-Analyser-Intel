package main

import (
	"MimojaFirmwareToolkit/pkg/Common"
	"encoding/json"
)

const NumberOfWorker = 2

func worker(id int, file <-chan MFTCommon.FlashImage) {

	for true {
		entry := <-file
		Bundle.Log.WithField("entry", entry).Infof("Handeling %s in Worker %d\n", entry.ID.GetID(), id)
		analyse(entry)
	}
}

var Bundle MFTCommon.AppBundle

func main() {
	Bundle = MFTCommon.Init("IFDAnalyser")

	entries := make(chan MFTCommon.FlashImage, NumberOfWorker)
	for w := 1; w <= NumberOfWorker; w++ {
		go worker(w, entries)
	}

	Bundle.MessageQueue.FlashImagesQueue.RegisterCallback("IFDUnpacker", func(payload string) error {

		Bundle.Log.WithField("payload", payload).Debug("Got new Message!")
		var file MFTCommon.FlashImage
		err := json.Unmarshal([]byte(payload), &file)
		if err != nil {
			Bundle.Log.WithError(err).Error("Could not unmarshall json: %v", err)
		}

		entries <- file

		return nil
	})
	Bundle.Log.Info("Starting up!")
	select {}
}
