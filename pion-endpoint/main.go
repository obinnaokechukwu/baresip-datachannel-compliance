package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime/debug"
	"sync"
	"time"

	"github.com/pion/webrtc/v4"
)

type message struct {
	Type       string `json:"type"`
	PayloadHex string `json:"payloadHex"`
}

type request struct {
	BaseURL        string    `json:"baseUrl"`
	Label          string    `json:"label"`
	Messages       []message `json:"messages"`
	TURNURL        string    `json:"turnUrl"`
	TURNUsername   string    `json:"turnUsername"`
	TURNCredential string    `json:"turnCredential"`
	ForceRelay     bool      `json:"forceRelay"`
}

type description struct {
	Type string `json:"type"`
	SDP  string `json:"sdp"`
}

type result struct {
	Verdict             string    `json:"verdict"`
	Failures            []string  `json:"failures"`
	Messages            []message `json:"messages"`
	Offer               string    `json:"offer"`
	Answer              string    `json:"answer"`
	ConnectionState     string    `json:"connectionState"`
	ICEState            string    `json:"iceState"`
	ChannelState        string    `json:"channelState"`
	PionVersion         string    `json:"pionVersion"`
	LocalCandidateType  string    `json:"localCandidateType"`
	RemoteCandidateType string    `json:"remoteCandidateType"`
	SelectedPair        string    `json:"selectedPair"`
}

func pionVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dependency := range info.Deps {
			if dependency.Path == "github.com/pion/webrtc/v4" {
				return dependency.Version
			}
		}
	}
	return "unknown"
}

func signal(
	ctx context.Context,
	client *http.Client,
	input request,
	offer webrtc.SessionDescription,
) (string, description, error) {
	create, err := http.NewRequestWithContext(
		ctx, http.MethodPost, input.BaseURL+"/connect/offerer/data", nil,
	)
	if err != nil {
		return "", description{}, err
	}
	response, err := client.Do(create)
	if err != nil {
		return "", description{}, err
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		return "", description{}, fmt.Errorf(
			"create session returned %s", response.Status,
		)
	}
	sessionID := response.Header.Get("Session-ID")
	if sessionID == "" {
		return "", description{}, errors.New("missing Session-ID")
	}

	payload, err := json.Marshal(description{
		Type: offer.Type.String(),
		SDP:  offer.SDP,
	})
	if err != nil {
		return sessionID, description{}, err
	}
	update, err := http.NewRequestWithContext(
		ctx, http.MethodPut, input.BaseURL+"/sdp", bytes.NewReader(payload),
	)
	if err != nil {
		return sessionID, description{}, err
	}
	update.Header.Set("Content-Type", "application/json")
	update.Header.Set("Session-ID", sessionID)
	response, err = client.Do(update)
	if err != nil {
		return sessionID, description{}, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return sessionID, description{}, fmt.Errorf(
			"set offer returned %s", response.Status,
		)
	}
	var answer description
	if err = json.NewDecoder(response.Body).Decode(&answer); err != nil {
		return sessionID, answer, err
	}
	return sessionID, answer, nil
}

func deleteSession(client *http.Client, baseURL, sessionID string) {
	if sessionID == "" {
		return
	}
	request, err := http.NewRequest(
		http.MethodDelete, baseURL+"/connect", nil,
	)
	if err != nil {
		return
	}
	request.Header.Set("Session-ID", sessionID)
	response, err := client.Do(request)
	if err == nil {
		_ = response.Body.Close()
	}
}

func run(input request) (output result) {
	output.PionVersion = pionVersion()
	output.Verdict = "INFRA_ERROR"
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	config := webrtc.Configuration{}
	if input.TURNURL != "" {
		config.ICEServers = []webrtc.ICEServer{{
			URLs:       []string{input.TURNURL},
			Username:   input.TURNUsername,
			Credential: input.TURNCredential,
		}}
	}
	if input.ForceRelay {
		config.ICETransportPolicy = webrtc.ICETransportPolicyRelay
	}
	pc, err := webrtc.NewPeerConnection(config)
	if err != nil {
		output.Failures = []string{err.Error()}
		return output
	}
	defer pc.Close()

	channel, err := pc.CreateDataChannel(input.Label, nil)
	if err != nil {
		output.Failures = []string{err.Error()}
		return output
	}
	opened := make(chan struct{})
	received := make(chan struct{})
	var openOnce sync.Once
	var receivedOnce sync.Once
	var mutex sync.Mutex
	channel.OnOpen(func() {
		openOnce.Do(func() { close(opened) })
	})
	channel.OnMessage(func(value webrtc.DataChannelMessage) {
		mutex.Lock()
		output.Messages = append(output.Messages, message{
			Type:       map[bool]string{true: "text", false: "binary"}[value.IsString],
			PayloadHex: hex.EncodeToString(value.Data),
		})
		complete := len(output.Messages) == len(input.Messages)
		mutex.Unlock()
		if complete {
			receivedOnce.Do(func() { close(received) })
		}
	})

	gathered := webrtc.GatheringCompletePromise(pc)
	offer, err := pc.CreateOffer(nil)
	if err == nil {
		err = pc.SetLocalDescription(offer)
	}
	if err != nil {
		output.Failures = []string{err.Error()}
		return output
	}
	select {
	case <-gathered:
	case <-ctx.Done():
		output.Failures = []string{"ICE gathering timed out"}
		return output
	}
	local := pc.LocalDescription()
	if local == nil {
		output.Failures = []string{"missing local offer"}
		return output
	}
	output.Offer = local.SDP

	client := &http.Client{Timeout: 45 * time.Second}
	sessionID, answer, err := signal(ctx, client, input, *local)
	defer deleteSession(client, input.BaseURL, sessionID)
	if err != nil {
		output.Failures = []string{err.Error()}
		return output
	}
	output.Answer = answer.SDP
	err = pc.SetRemoteDescription(webrtc.SessionDescription{
		Type: webrtc.SDPTypeAnswer,
		SDP:  answer.SDP,
	})
	if err != nil {
		output.Failures = []string{err.Error()}
		return output
	}

	select {
	case <-opened:
	case <-ctx.Done():
		output.Failures = []string{"data channel open timed out"}
		return output
	}
	for _, item := range input.Messages {
		payload, decodeErr := hex.DecodeString(item.PayloadHex)
		if decodeErr != nil {
			output.Failures = []string{decodeErr.Error()}
			return output
		}
		if item.Type == "text" {
			err = channel.SendText(string(payload))
		} else {
			err = channel.Send(payload)
		}
		if err != nil {
			output.Failures = []string{err.Error()}
			return output
		}
	}

	select {
	case <-received:
	case <-ctx.Done():
		output.Failures = []string{"echo receipt timed out"}
		return output
	}
	output.ConnectionState = pc.ConnectionState().String()
	output.ICEState = pc.ICEConnectionState().String()
	output.ChannelState = channel.ReadyState().String()
	pair, err := pc.SCTP().Transport().ICETransport().
		GetSelectedCandidatePair()
	if err != nil || pair == nil {
		output.Failures = []string{"selected ICE pair unavailable"}
		return output
	}
	output.LocalCandidateType = pair.Local.Typ.String()
	output.RemoteCandidateType = pair.Remote.Typ.String()
	output.SelectedPair = pair.String()
	output.Verdict = "PASS"
	return output
}

func main() {
	content, err := io.ReadAll(os.Stdin)
	if err != nil {
		panic(err)
	}
	var input request
	if err = json.Unmarshal(content, &input); err != nil {
		panic(err)
	}
	output := run(input)
	if err = json.NewEncoder(os.Stdout).Encode(output); err != nil {
		panic(err)
	}
	if output.Verdict != "PASS" {
		os.Exit(1)
	}
}
