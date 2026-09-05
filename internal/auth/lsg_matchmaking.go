package auth

import "fmt"

const (
	bdMatchmakingCreateSession = byte(1)
	bdMatchmakingUpdateSession = byte(2)
	bdMatchmakingDeleteSession = byte(3)
	bdMatchmakingFindByID      = byte(4)
	bdMatchmakingFindSessions  = byte(5)

	mw2MatchmakingCommonAddressSize  = 25
	mw2MatchmakingSessionIDSize      = 8
	mw2MatchmakingSecurityKeySize    = 16
	mw2RemoteFindOpenPublicSlotFloor = int32(2)
)

type mw2MatchmakingInfo struct {
	commonAddress []byte
	sessionID     []byte
	securityKey   []byte
	openPublic    int32
	filledPublic  int32
	openPrivate   int32
	filledPrivate int32
	attributes    [9]int32
}

type mw2MatchmakingSearch struct {
	// gameType is the inverted xblive_rankedmatch value (!ranked).
	gameType int32
	// gameMode is the raw selected playlist/game-mode identifier.
	gameMode          int32
	netcodeVersion    int32
	mapPackFlags      int32
	playlistVersion   int32
	requiredFreeSlots int32
	performance       int32
}

type mw2MatchmakingRequest struct {
	operationID byte
	reserved    byte
	sessionID   []byte
	info        mw2MatchmakingInfo
	queryType   int32
	maxResults  int32
	search      mw2MatchmakingSearch
}

func readMW2MatchmakingInfo(reader *bdBitReader) (mw2MatchmakingInfo, error) {
	commonAddress, err := reader.readBlob(mw2MatchmakingCommonAddressSize)
	if err != nil {
		return mw2MatchmakingInfo{}, fmt.Errorf("read common address: %w", err)
	}
	if len(commonAddress) != mw2MatchmakingCommonAddressSize {
		return mw2MatchmakingInfo{}, fmt.Errorf("common address length is %d, expected %d", len(commonAddress), mw2MatchmakingCommonAddressSize)
	}
	sessionID, err := reader.readBlob(mw2MatchmakingSessionIDSize)
	if err != nil {
		return mw2MatchmakingInfo{}, fmt.Errorf("read session ID: %w", err)
	}
	if len(sessionID) != mw2MatchmakingSessionIDSize {
		return mw2MatchmakingInfo{}, fmt.Errorf("session ID length is %d, expected %d", len(sessionID), mw2MatchmakingSessionIDSize)
	}
	securityKey, err := reader.readBlob(mw2MatchmakingSecurityKeySize)
	if err != nil {
		return mw2MatchmakingInfo{}, fmt.Errorf("read security key: %w", err)
	}
	if len(securityKey) != mw2MatchmakingSecurityKeySize {
		return mw2MatchmakingInfo{}, fmt.Errorf("security key length is %d, expected %d", len(securityKey), mw2MatchmakingSecurityKeySize)
	}

	info := mw2MatchmakingInfo{
		commonAddress: commonAddress,
		sessionID:     sessionID,
		securityKey:   securityKey,
	}
	counts := []*int32{
		&info.openPublic,
		&info.filledPublic,
		&info.openPrivate,
		&info.filledPrivate,
	}
	for index, count := range counts {
		*count, err = reader.readI32()
		if err != nil {
			return mw2MatchmakingInfo{}, fmt.Errorf("read slot count %d: %w", index, err)
		}
	}
	for index := range info.attributes {
		info.attributes[index], err = reader.readI32()
		if err != nil {
			return mw2MatchmakingInfo{}, fmt.Errorf("read matchmaking attribute %d: %w", index, err)
		}
	}
	return info, nil
}

func readMW2MatchmakingSuffix(reader *bdBitReader, hasObjectSuffix bool) error {
	if hasObjectSuffix {
		for index := 0; index < 2; index++ {
			value, err := reader.bits.readBits(8)
			if err != nil {
				return fmt.Errorf("read object suffix byte %d: %w", index, err)
			}
			if value != 0 {
				return fmt.Errorf("object suffix byte %d is %d, expected zero", index, value)
			}
		}
	}
	terminator, err := reader.bits.readBits(5)
	if err != nil {
		return fmt.Errorf("read task terminator: %w", err)
	}
	if terminator != 0 {
		return fmt.Errorf("task terminator is %d, expected zero", terminator)
	}
	// The encrypted record does not expose the task's unpadded bit length.
	// Captured clients leave transport/block padding after this terminator, so
	// it must not be interpreted as another task field.
	return nil
}

func parseMW2MatchmakingRequest(payload []byte) (mw2MatchmakingRequest, error) {
	reader := newBDBitReader(payload)
	typeChecked, err := reader.bits.readBits(1)
	if err != nil || typeChecked != 1 {
		return mw2MatchmakingRequest{}, fmt.Errorf("matchmaking request is missing type-checking marker")
	}
	operationID, err := reader.readU8()
	if err != nil {
		return mw2MatchmakingRequest{}, fmt.Errorf("read matchmaking operation: %w", err)
	}
	request := mw2MatchmakingRequest{operationID: operationID}
	request.reserved, err = reader.readU8()
	if err != nil {
		return request, fmt.Errorf("read matchmaking reserved value: %w", err)
	}
	if request.reserved != 0 {
		return request, fmt.Errorf("matchmaking reserved value is %d, expected zero", request.reserved)
	}

	switch operationID {
	case bdMatchmakingCreateSession, bdMatchmakingUpdateSession:
		request.info, err = readMW2MatchmakingInfo(reader)
		if err != nil {
			return request, err
		}
		err = readMW2MatchmakingSuffix(reader, true)
	case bdMatchmakingDeleteSession, bdMatchmakingFindByID:
		request.sessionID, err = reader.readBlob(mw2MatchmakingSessionIDSize)
		if err == nil && len(request.sessionID) != mw2MatchmakingSessionIDSize {
			err = fmt.Errorf("session ID length is %d, expected %d", len(request.sessionID), mw2MatchmakingSessionIDSize)
		}
		if err == nil {
			err = readMW2MatchmakingSuffix(reader, false)
		}
	case bdMatchmakingFindSessions:
		request.queryType, err = reader.readI32()
		if err == nil {
			request.maxResults, err = reader.readI32()
		}
		searchFields := []*int32{
			&request.search.gameType,
			&request.search.gameMode,
			&request.search.netcodeVersion,
			&request.search.mapPackFlags,
			&request.search.playlistVersion,
			&request.search.requiredFreeSlots,
		}
		for _, field := range searchFields {
			if err == nil {
				*field, err = reader.readI32()
			}
		}
		if err == nil {
			request.search.performance, err = reader.readI32()
		}
		if err == nil {
			err = readMW2MatchmakingSuffix(reader, true)
		}
	default:
		err = fmt.Errorf("unsupported matchmaking operation %d", operationID)
	}
	if err != nil {
		return request, fmt.Errorf("parse matchmaking operation %d: %w", operationID, err)
	}
	return request, nil
}

func (r mw2MatchmakingRequest) isRetailPublicSearch() bool {
	return r.operationID == bdMatchmakingFindSessions &&
		r.reserved == 0 &&
		r.queryType == 2 &&
		r.maxResults == 50
}

func (c *lsgConnection) matchmakingStore() *mw2MatchmakingStore {
	if c.matchmakingSessions == nil {
		c.matchmakingSessions = newMW2MatchmakingStore()
	}
	return c.matchmakingSessions
}

func (c *lsgConnection) matchmakingErrorReply(errorCode uint32) []byte {
	writer := newBDBitWriter()
	writer.writeU64(c.nextTransactionID())
	writer.writeU32(errorCode)
	return writer.bytes()
}

func (c *lsgConnection) matchmakingMutationReply(operationID byte) []byte {
	writer := newBDBitWriter()
	writer.writeU64(c.nextTransactionID())
	writer.writeU32(bdErrorNone)
	writer.writeU8(operationID)
	return writer.bytes()
}

func (c *lsgConnection) matchmakingCreateReply(session mw2StoredMatchmakingSession) []byte {
	writer := newBDBitWriter()
	writer.writeU64(c.nextTransactionID())
	writer.writeU32(bdErrorNone)
	writer.writeU8(bdMatchmakingCreateSession)
	writer.writeU32(1)
	writer.writeBlob(session.sessionID[:])
	writer.writeBlob(session.securityKey[:])
	return writer.bytes()
}

func writeMW2MatchmakingResult(writer *bdBitWriter, session mw2StoredMatchmakingSession) {
	writer.writeBlob(session.commonAddress[:])
	writer.writeBlob(session.sessionID[:])
	writer.writeBlob(session.securityKey[:])
	writer.writeI32(session.openPublic)
	writer.writeI32(session.filledPublic)
	writer.writeI32(session.openPrivate)
	writer.writeI32(session.filledPrivate)
	for _, attribute := range session.attributes {
		writer.writeI32(attribute)
	}
}

func (c *lsgConnection) matchmakingFindResult(session mw2StoredMatchmakingSession) mw2StoredMatchmakingSession {
	if session.ownerID != c.connectionID && session.openPublic < mw2RemoteFindOpenPublicSlotFloor {
		session.openPublic = mw2RemoteFindOpenPublicSlotFloor
	}
	return session
}

func (c *lsgConnection) matchmakingFindReply(sessions []mw2StoredMatchmakingSession) []byte {
	writer := newBDBitWriter()
	writer.writeU64(c.nextTransactionID())
	writer.writeU32(bdErrorNone)
	writer.writeU8(bdMatchmakingFindSessions)
	writer.writeU32(uint32(len(sessions)))
	for _, session := range sessions {
		writeMW2MatchmakingResult(writer, c.matchmakingFindResult(session))
	}
	return writer.bytes()
}

func (c *lsgConnection) handleMatchmakingTask(payload []byte) (byte, []byte, bool) {
	c.lastServiceID = bdServiceMatchmaking
	c.lastOperationID = 0
	c.lastTaskSupported = false
	c.lastMatchmakingSessions = nil
	request, err := parseMW2MatchmakingRequest(payload)
	c.lastOperationID = request.operationID
	if err != nil {
		return lsgTaskReplyType, c.matchmakingErrorReply(bdErrorServiceNotAvailable), true
	}

	switch request.operationID {
	case bdMatchmakingCreateSession:
		session, createErr := c.matchmakingStore().create(request.info, c.connectionID, c.entityID)
		if createErr != nil {
			return lsgTaskReplyType, c.matchmakingErrorReply(bdErrorServiceNotAvailable), true
		}
		c.lastTaskSupported = true
		c.lastMatchmakingSessions = []mw2StoredMatchmakingSession{session}
		return lsgTaskReplyType, c.matchmakingCreateReply(session), true
	case bdMatchmakingUpdateSession:
		if _, ok := c.matchmakingStore().update(request.info, c.connectionID); !ok {
			return lsgTaskReplyType, c.matchmakingErrorReply(bdErrorServiceNotAvailable), true
		}
		c.lastTaskSupported = true
		return lsgTaskReplyType, c.matchmakingMutationReply(request.operationID), true
	case bdMatchmakingDeleteSession:
		if !c.matchmakingStore().delete(request.sessionID, c.connectionID) {
			return lsgTaskReplyType, c.matchmakingErrorReply(bdErrorServiceNotAvailable), true
		}
		c.lastTaskSupported = true
		return lsgTaskReplyType, c.matchmakingMutationReply(request.operationID), true
	case bdMatchmakingFindSessions:
		if request.isRetailPublicSearch() {
			c.lastTaskSupported = true
			sessions := c.matchmakingStore().findForSearch(request.maxResults, request.search, c.connectionID, c.preferEarlierHosts)
			if c.suppressSelfOnly && len(sessions) == 1 && sessions[0].ownerID == c.connectionID {
				sessions = nil
			}
			c.lastMatchmakingSessions = append([]mw2StoredMatchmakingSession(nil), sessions...)
			return lsgTaskReplyType, c.matchmakingFindReply(sessions), true
		}
	}
	return lsgTaskReplyType, c.matchmakingErrorReply(bdErrorServiceNotAvailable), true
}
