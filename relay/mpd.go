package relay

import (
	"bufio"
	"fmt"
	"net"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
)

type MPDServer struct {
	Port     string
	streamer *Streamer
	listener net.Listener
}

func NewMPDServer(port string, s *Streamer) *MPDServer {
	return &MPDServer{
		Port:     port,
		streamer: s,
	}
}

func (m *MPDServer) Start() error {
	addr := m.Port
	if !strings.Contains(addr, ":") {
		addr = ":" + addr
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	m.listener = l
	logrus.Infof("MPD Server listening on %s", addr)

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go m.handleConnection(conn)
		}
	}()

	return nil
}

func (m *MPDServer) Stop() {
	if m.listener != nil {
		m.listener.Close()
	}
}

func (m *MPDServer) handleConnection(conn net.Conn) {
	defer conn.Close()
	writer := bufio.NewWriter(conn)
	reader := bufio.NewReader(conn)

		// Greeting
		writer.WriteString("OK MPD 0.23.5\n")
		writer.Flush()
	
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
					line = strings.TrimSpace(line)
					if line == "" {
						continue
					}
			
					cmd := strings.Split(line, " ")[0]
					// args := strings.TrimPrefix(line, cmd+" ")
			
					switch cmd {			case "status":
				m.handleStatus(writer)
			case "currentsong":
				m.handleCurrentSong(writer)
			case "play":
				m.streamer.Play()
				writer.WriteString("OK\n")
			case "stop":
				m.streamer.Stop()
				writer.WriteString("OK\n")
			case "ping":
				writer.WriteString("OK\n")
			case "close":
				return
			case "listall", "listallinfo":
				m.handleListAll(writer)
			case "listplaylists":
				writer.WriteString("OK\n")
			case "lsinfo":
				m.handleListAll(writer)
			case "outputs":
				fmt.Fprintf(writer, "outputid: 0\noutputname: %s\noutputenabled: 1\n", m.streamer.OutputMount)
				writer.WriteString("OK\n")
			case "config":
				writer.WriteString("OK\n")
			case "stats":
				fmt.Fprintf(writer, "uptime: 0\nplaytime: 0\nartists: 0\nalbums: 0\nsongs: %d\n", len(m.streamer.Playlist))
				writer.WriteString("OK\n")
			default:
				logrus.Debugf("MPD: Unknown command: %s", cmd)
				writer.WriteString("OK\n") // Be lenient for now
			}
			writer.Flush()
		}}

func (m *MPDServer) handleStatus(w *bufio.Writer) {
	state := "stop"
	if m.streamer.State == StatePlaying {
		state = "play"
	} else if m.streamer.State == StatePaused {
		state = "pause"
	}

	fmt.Fprintf(w, "state: %s\n", state)
	fmt.Fprintf(w, "volume: 100\n")
	fmt.Fprintf(w, "repeat: 0\n")
	fmt.Fprintf(w, "random: 0\n")
	fmt.Fprintf(w, "single: 0\n")
	fmt.Fprintf(w, "consume: 0\n")
	fmt.Fprintf(w, "playlist: 1\n")
	fmt.Fprintf(w, "playlistlength: %d\n", len(m.streamer.Playlist))
	w.WriteString("OK\n")
}

func (m *MPDServer) handleCurrentSong(w *bufio.Writer) {
	m.streamer.mu.RLock()
	defer m.streamer.mu.RUnlock()
	fmt.Fprintf(w, "file: %s\n", m.streamer.CurrentFile)
	fmt.Fprintf(w, "Title: %s\n", m.streamer.CurrentFile)
	fmt.Fprintf(w, "Pos: %d\n", m.streamer.CurrentPos)
	fmt.Fprintf(w, "Id: %d\n", m.streamer.CurrentPos)
	w.WriteString("OK\n")
}

func (m *MPDServer) handleListAll(w *bufio.Writer) {
	// Dummy for now, just list what's in the music dir or playlist
	for _, f := range m.streamer.Playlist {
		fmt.Fprintf(w, "file: %s\n", filepath.Base(f))
	}
	w.WriteString("OK\n")
}
