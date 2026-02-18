package relay

import (
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
)

func (r *Relay) StartPullRelay(url, mount, password string, burstSize int) {
	go func() {
		for {
			logrus.WithField("url", url).Info("Attempting to pull relay stream")
			
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				logrus.WithError(err).Error("Failed to create relay request")
				time.Sleep(5 * time.Second)
				continue
			}

			// Add headers for better compatibility
			req.Header.Set("User-Agent", "TinyIce/0.1.0")
			req.Header.Set("Icy-MetaData", "1")
			req.Header.Set("Accept", "*/*")

			// Some servers might require auth
			if password != "" {
				req.SetBasicAuth("source", password)
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				logrus.WithError(err).Error("Relay connection failed")
				time.Sleep(5 * time.Second)
				continue
			}

			if resp.StatusCode != http.StatusOK {
				logrus.WithField("status", resp.Status).Error("Relay server returned non-200")
				resp.Body.Close()
				time.Sleep(5 * time.Second)
				continue
			}

			logrus.WithField("mount", mount).Info("Relay stream connected and pulling")
			
			stream := r.GetOrCreateStream(mount)
			if burstSize > 0 {
				stream.SetBurstSize(burstSize)
			}
			stream.SourceIP = "relay-pull"

			// Use Icy headers as fallback
			name := resp.Header.Get("Ice-Name")
			if name == "" { name = resp.Header.Get("Icy-Name") }
			
			desc := resp.Header.Get("Ice-Description")
			if desc == "" { desc = resp.Header.Get("Icy-Description") }
			
			genre := resp.Header.Get("Ice-Genre")
			if genre == "" { genre = resp.Header.Get("Icy-Genre") }
			
			bitrate := resp.Header.Get("Ice-Bitrate")
			if bitrate == "" { bitrate = resp.Header.Get("Icy-Br") }

			stream.UpdateMetadata(
				name,
				desc,
				genre,
				resp.Header.Get("Ice-Url"),
				bitrate,
				resp.Header.Get("Content-Type"),
				false,
				false,
			)

			buf := make([]byte, 8192)
			for {
				n, err := resp.Body.Read(buf)
				if n > 0 {
					stream.Broadcast(buf[:n], r)
				}
				if err != nil {
					logrus.WithError(err).Warn("Relay pull interrupted")
					break
				}
			}

			resp.Body.Close()
			r.RemoveStream(mount)
			logrus.Info("Relay waiting to reconnect...")
			time.Sleep(2 * time.Second)
		}
	}()
}
