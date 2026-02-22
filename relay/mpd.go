package relay

import (
	"bufio"
	"net"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
)

type MPDServer struct {
	Port     string
	Password string
	streamer *Streamer
	listener net.Listener
}

func NewMPDServer(port, password string, s *Streamer) *MPDServer {
	return &MPDServer{
		Port:     port,
		Password: password,
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

	resp := NewMPDResponse(writer)

	// Greeting
	resp.Greeting("0.23.5")
	writer.Flush()

	authenticated := m.Password == ""

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
		args := strings.TrimPrefix(line, cmd+" ")

		if !authenticated && cmd != "password" && cmd != "close" {
			resp.ACK(5, 0, "", "permission denied")
			writer.Flush()
			continue
		}

		switch cmd {
		case "password":
			if args == m.Password {
				authenticated = true
				resp.OK()
			} else {
				resp.ACK(3, 0, "password", "incorrect password")
			}
		case "status":
			m.handleStatus(resp)
		case "currentsong":
			m.handleCurrentSong(resp)
		case "play":
			m.streamer.Play()
			resp.OK()
		case "stop":
			m.streamer.Stop()
			resp.OK()
		case "pause":
			m.streamer.TogglePlay()
			resp.OK()
		case "next":
			m.streamer.Next()
			resp.OK()
		case "previous":
			// We don't have previous yet, but let's be polite
			resp.OK()
		case "ping":
			resp.OK()
		case "close":
			return
		case "listall", "listallinfo":
			m.handleListAll(resp)
		case "listplaylists":
			resp.OK()
		case "lsinfo":
			m.handleListAll(resp)
		case "outputs":
			resp.Field("outputid", 0)
			resp.Field("outputname", m.streamer.OutputMount)
			resp.Field("outputenabled", 1)
			resp.OK()
		case "config":
			resp.OK()
		case "stats":
			resp.Field("uptime", 0)
			resp.Field("playtime", 0)
			resp.Field("artists", 0)
			resp.Field("albums", 0)
			resp.Field("songs", len(m.streamer.Playlist))
			resp.OK()
		default:
			logrus.Debugf("MPD: Unknown command: %s", cmd)
			resp.OK() // Be lenient for now
		}
		writer.Flush()
	}
}

func (m *MPDServer) handleStatus(resp *MPDResponse) {
	state := "stop"
	if m.streamer.State == StatePlaying {
		state = "play"
	} else if m.streamer.State == StatePaused {
		state = "pause"
	}

	resp.Field("state", state)
	resp.Field("volume", 100)
	resp.Field("repeat", 0)
	resp.Field("random", 0)
	resp.Field("single", 0)
	resp.Field("consume", 0)
	resp.Field("playlist", 1)
	resp.Field("playlistlength", len(m.streamer.Playlist))
	resp.OK()
}

func (m *MPDServer) handleCurrentSong(resp *MPDResponse) {
	m.streamer.mu.RLock()
	defer m.streamer.mu.RUnlock()
	resp.Field("file", m.streamer.CurrentFile)
	resp.Field("Title", m.streamer.CurrentFile)
	resp.Field("Pos", m.streamer.CurrentPos)
	resp.Field("Id", m.streamer.CurrentPos)
	resp.OK()
}

func (m *MPDServer) handleListAll(resp *MPDResponse) {
	// Dummy for now, just list what's in the music dir or playlist
	for _, f := range m.streamer.Playlist {
		resp.Field("file", filepath.Base(f))
	}
	resp.OK()
}
