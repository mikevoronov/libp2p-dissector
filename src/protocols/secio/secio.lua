-- prevent wireshark loading this file as a plugin
if not _G['secio_dissector'] then return end

local pb = require ("pb")
local SecioState = require ("secio_state")

secio_proto = Proto("secio", "SECIO protocol")

local fields = secio_proto.fields

-- fields related to Propose packets type
fields.propose = ProtoField.bytes ("secio.propose", "Propose", base.NONE, nil, 0, "Propose request")
fields.rand = ProtoField.bytes ("secio.propose.rand", "rand", base.NONE, nil, 0, "Propose random bytes")
fields.pubkey = ProtoField.bytes ("secio.propose.pubkey", "pubkey", base.NONE, nil, 0, "Propose public key")
fields.exchanges = ProtoField.string ("secio.propose.exchanges", "exchanges", base.NONE, nil, 0, "Propose exchanges")
fields.ciphers = ProtoField.string ("secio.propose.ciphers", "ciphers", base.NONE, nil, 0, "Propose ciphers")
fields.hashes = ProtoField.string ("secio.propose.hashes", "hashes", base.NONE, nil, 0, "Propose hashes")

-- fields related to Exchange packets type
fields.exchange = ProtoField.bytes ("secio.exchange", "exchange", base.NONE, nil, 0, "Exchange request")
fields.epubkey = ProtoField.bytes ("secio.exchange.epubkey", "epubkey", base.NONE, nil, 0, "Ephermal public key")
fields.signature = ProtoField.bytes ("secio.exchange.signature", "signature", base.NONE, nil, 0, "Exchange signature")

local function dissect_handshake(buffer, pinfo)
    local is_listener = false

    -- heuristic multistream detector should already set MSState.listener and MSState.dialer fields
    if (is_same_src_address(SecioState.listener, pinfo)) then
        is_listener = true
    elseif (not is_same_src_address(SecioState.dialer, pinfo)) then
        -- some error occured
        print("multistream dissector: ip:port are incorrect")
        return
    end

    if(is_listener) then
        if (SecioState.listenerProposePacketId == -1) then
            SecioState.listenerProposePacketId = pinfo.number
        elseif (SecioState.listenerExchangePacketId == -1) then
            SecioState.listenerExchangePacketId = pinfo.number
        end
    else
        if (SecioState.dialerProposePacketId == -1) then
            SecioState.dialerProposePacketId = pinfo.number
        elseif (SecioState.dialerExchangePacketId == -1) then
            SecioState.dialerExchangePacketId = pinfo.number
        end
    end

    if (
        SecioState.listenerProposePacketId ~= -1 and
        SecioState.dialerProposePacketId ~= -1 and
        SecioState.listenerExchangePacketId ~= -1 and
        SecioState.dialerExchangePacketId ~= -1
    ) then
        SecioState.handshaked = true
    end
end

local function parse_and_set_propose(buffer, tree)
    tree:add(buffer(0, 4), string.format("Propose message size 0x%x bytes", buffer:len()))
    local branch = tree:add("Propose", fields.propose)

    local propose = assert(pb.decode("Propose", buffer:raw(4, -1)))
    local offset = 4

    -- check for fields presence and add them to the tree
    if (propose.rand ~= nil) then
        branch:add(fields.rand, buffer(offset, propose.rand:len() + 3))
        offset = offset + propose.rand:len() + 3
    end

    if (propose.pubkey ~= nil) then
        branch:add(fields.pubkey, buffer(offset, propose.pubkey:len() + 4))
        offset = offset + propose.pubkey:len() + 4
    end

    if (propose.exchanges ~= nil) then
        branch:add(fields.exchanges, buffer(offset, propose.exchanges:len()))
        offset = offset + propose.exchanges:len()
    end

    if (propose.ciphers ~= nil) then
        branch:add(fields.ciphers, buffer(offset + 2, propose.ciphers:len()))
        offset = offset + propose.ciphers:len()
    end

    if (propose.hashes ~= nil) then
        branch:add(fields.hashes, buffer(offset + 4, propose.hashes:len()))
        offset = offset + propose.hashes:len()
    end
end

local function parse_and_set_exchange(buffer, tree)
    tree:add(buffer(0, 4), string.format("Exchange message size 0x%x bytes", buffer:len()))
    local branch = tree:add("Exchange", fields.exchange)

    local exchange = assert(pb.decode("Exchange", buffer:raw(4, -1)))
    local offset = 4

    -- check for fields presence and add them to the tree
    if (exchange.epubkey ~= nil) then
        branch:add(fields.epubkey, buffer(offset, exchange.epubkey:len() + 2))
        offset = offset + exchange.epubkey:len() + 2
    end

    if (exchange.signature ~= nil) then
        branch:add(fields.signature, buffer(offset, exchange.signature:len() + 2))
        offset = offset + exchange.signature:len() + 2
    end
end

function secio_proto.dissector (buffer, pinfo, tree)
    -- the message should be at least 4 bytes
    if buffer:len() < 4 then
        return
    end

    if (next(SecioState.listener) == nil) then
        SecioState:init_with_private(pinfo.private)
    end

    local subtree = tree:add(secio_proto, "SECIO protocol")
    pinfo.cols.protocol = secio_proto.name

    if (not SecioState.handshaked) then
        dissect_handshake(buffer, pinfo)
    end

    -- according to the spec, first 4 bytes always represent packet size
    local packet_len = buffer(0, 4):uint()

    if (SecioState.listenerProposePacketId == pinfo.number) then
        pinfo.cols.info = "SECIO: Propose (listener)"
        parse_and_set_propose(buffer, tree)
    elseif (SecioState.dialerProposePacketId == pinfo.number) then
        pinfo.cols.info = "SECIO: Propose (dialer)"
        parse_and_set_propose(buffer, tree)
    elseif (SecioState.listenerExchangePacketId == pinfo.number) then
        pinfo.cols.info = "SECIO Exchange (listener)"
        parse_and_set_exchange(buffer, tree)
    elseif (SecioState.dialerExchangePacketId == pinfo.number) then
        pinfo.cols.info = "SECIO Exchange (dialer)"
        parse_and_set_exchange(buffer, tree)
    elseif (SecioState.handshaked) then
        -- encrypted packets

        if (next(SecioState.cryptoParams) == nil) then
            SecioState:init_crypto_params(pinfo)
        end

        pinfo.cols.info = "SECIO Body"
        local plain_text = ""
        local hmac_size = SecioState.listenerHMACSize

        -- if see this packet for the first time, we need to decrypt it
        if not pinfo.visited then
            -- [4 bytes len][ cipher_text ][ H(cipher_text) ]
            if (is_same_src_address(SecioState.listener, pinfo)) then
                plain_text = SecioState.listenerMsgDecryptor(buffer:raw(4, packet_len - SecioState.listenerHMACSize))
            else
                plain_text = SecioState.dialerMsgDecryptor(buffer:raw(4, packet_len - SecioState.dialerHMACSize))
                hmac_size = SecioState.dialerHMACSize
            end

            SecioState.decryptedPayloads[pinfo.number] = plain_text
        else
            plain_text = SecioState.decryptedPayloads[pinfo.number]
        end

        local offset = 0
        subtree:add(buffer(offset, 4), string.format("SECIO packet size: 0x%X bytes", packet_len))
        offset = offset + 4

        plain_text = Struct.tohex(tostring(plain_text))
        local mplexTree = subtree:add(buffer(offset, packet_len - hmac_size),
            string.format("cipher text: plain text is (0x%X bytes) %s", #plain_text, plain_text)
        )
        offset = offset + packet_len - hmac_size

        subtree:add(buffer(offset, -1), string.format("HMAC (0x%X bytes)", hmac_size))

        pinfo.private["plain_text"] = plain_text
        Dissector.get("mplex"):call(buffer, pinfo, mplexTree)
    end
end

return secio_proto
