-- prevent wireshark loading this file as a plugin
if not _G['secio_dissector'] then return end

local config = require("config")
local utils = require("secio_misc")
local pb = require ("pb")

local local_hmac_size = utils:hashSize(config.local_hmac_type)
local remote_hmac_size = utils:hashSize(config.remote_hmac_type)
local localMsgDecryptor = utils:makeMsgDecryptor(config.local_cipher_type, config.local_key, config.local_iv)
local remoteMsgDecryptor = utils:makeMsgDecryptor(config.remote_cipher_type, config.remote_key, config.remote_iv)

secio_proto = Proto("secio", "SECIO protocol")

local fields = secio_proto.fields

-- fields related to Propose packets type
fields.propose = ProtoField.bytes ("Propose", "propose")
fields.rand = ProtoField.bytes ("Propose.rand", "rand")
fields.pubkey = ProtoField.bytes ("Propose.pubkey", "pubkey")
fields.exchanges = ProtoField.string ("Propose.exchanges", "exchanges")
fields.ciphers = ProtoField.string ("Propose.ciphers", "ciphers")
fields.hashes = ProtoField.string ("Propose.hashes", "hashes")

-- fields related to Exchange packets type
fields.exchange = ProtoField.bytes ("Exchange", "exchange")
fields.epubkey = ProtoField.string ("Exchange.epubkey", "epubkey")
fields.signature = ProtoField.string ("Exchange.signature", "signature")

-- since the dissector function could be invoked many times, we need to save some info
-- to avoid parsing and decrypting on each invocation
local localProposeFrameNumber = -1
local remoteProposeFrameNumber = -1
local localExchangeFrameNumber = -1
local remoteExchangeFrameNumber = -1
local decrypted_msgs = {}

function secio_proto.dissector (buffer, pinfo, tree)
    -- the message should be at least 16 symbols
    if buffer:len() < 16 then
        return
    end

    local subtree = tree:add(secio_proto, "SECIO protocol")
    pinfo.cols.protocol = "SECIO"

    -- according to the spec, there is always 4 bytes for packet size
    local cipher_txt_size = buffer(0, 4):uint()

    if (localProposeFrameNumber == -1 or remoteProposeFrameNumber == -1) or
            (pinfo.number == localProposeFrameNumber or pinfo.number == remoteProposeFrameNumber) then

        pinfo.cols.info = "SECIO Propose"

        if not pinfo.visited and (localProposeFrameNumber == -1) then
            localProposeFrameNumber = pinfo.number
        elseif not pinfo.visited and (remoteProposeFrameNumber == -1) then
            remoteProposeFrameNumber = pinfo.number
        end

        subtree:add(buffer(0, 4), string.format("Propose message size 0x%x bytes", cipher_txt_size))
        local branch = subtree:add("Propose", fields.propose)

        local propose = assert(pb.decode("Propose", buffer:raw(4, cipher_txt_size)))
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
    elseif (localExchangeFrameNumber == -1 or remoteExchangeFrameNumber == -1)
            or (pinfo.number == localExchangeFrameNumber or pinfo.number == remoteExchangeFrameNumber) then

        pinfo.cols.info = "SECIO Exchange"

        if not pinfo.visited and (localExchangeFrameNumber == -1) then
            print("local Exchange packet seen")
            localExchangeFrameNumber = pinfo.number
        elseif not pinfo.visited and (remoteExchangeFrameNumber == -1) then
            print("remote Exchange packet seen")
            remoteExchangeFrameNumber = pinfo.number
        end

        subtree:add(buffer(0, 4), string.format("Exchange message size 0x%x bytes", cipher_txt_size))
        local branch = subtree:add("Exchange", fields.exchange)

        local exchange = assert(pb.decode("Exchange", buffer:raw(4, cipher_txt_size)))
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
    else
        pinfo.cols.info = "SECIO Body"
        local plain_text = ""
        local hmac_size = local_hmac_size

        -- if seen this packet for the first time, we need to decrypt it
        if not pinfo.visited then
            -- [4 bytes len][ cipher_text ][ H(cipher_text) ]
            -- CTR mode AES
            if (config.src_port == pinfo.src_port) then
                plain_text = localMsgDecryptor(buffer:raw(4, cipher_txt_size - local_hmac_size))
            else
                plain_text = remoteMsgDecryptor(buffer:raw(4, cipher_txt_size - remote_hmac_size))
                hmac_size = remote_hmac_size
            end

            decrypted_msgs[pinfo.number] = plain_text
        else
            plain_text = decrypted_msgs[pinfo.number]
        end

        local offset = 0
        subtree:add(buffer(offset, 4), string.format("MPLEX packet size: 0x%X bytes", cipher_txt_size))
        offset = offset + 4

        local mplexTree = subtree:add(buffer(offset, cipher_txt_size - hmac_size),
            string.format("cipher text: plain text is (0x%X bytes) %s",
                #plain_text, Struct.tohex(tostring(plain_text)))
        )
        offset = offset + cipher_txt_size - hmac_size

        subtree:add(buffer(offset, hmac_size), string.format("HMAC (0x%X bytes)", hmac_size))

        Dissector.get("mplex"):call(buffer(4, cipher_txt_size - hmac_size):tvb(), pinfo, mplexTree)
    end
end

return secio_proto
