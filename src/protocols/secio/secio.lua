-- prevent wireshark loading this file as a plugin
if not _G['secio_dissector'] then return end

require("openssl_ffi")
local ffi = require("ffi")
local C = ffi.C
ffi.load("ssl")

local pb = require ("pb")
require("proto")

-- returns lamdba that can decrypt SECIO messages based on the provided cipher settings
local function makeMsgDecryptor(cipher_type, key, iv)
    -- returns lamdba that can decrypt raw cipher text based on the provided parameters
    local function makeDecryptor(cipher_type, key, iv)
        -- initialize the cipher context
        local ctx = C.EVP_CIPHER_CTX_new()
        assert(ctx ~= nil)

        -- set up the cipher type
        if "AES-128" == cipher_type then
            -- EVP_DecryptInit_ex returns 1 if succeed and 0 otherwise
            assert(1 == C.EVP_DecryptInit_ex(ctx, C.EVP_aes_128_ctr(), nil, key, iv))
        elseif "AES-256" == cipher_type then
            -- EVP_DecryptInit_ex returns 1 if succeed and 0 otherwise
            assert(1 == C.EVP_DecryptInit_ex(ctx, C.EVP_aes_256_ctr(), nil, key, iv))
        else
            error('Unsupported ciphertype: ' .. cipher_type .. ". At now, only AES-128,AES-256 are supported")
        end

        -- return lamdba that can decrypt supplied cipher text
        return function(cipher_text)
            if not cipher_text then
                print("EVP_CIPHER_CTX_free")
                C.EVP_CIPHER_CTX_free(ctx)
                return
            end

            local cipher_text_len = #cipher_text
            local plain_text = ffi.new("unsigned char[?]", cipher_text_len)
            local ffi_len = ffi.new 'int[1]'
            assert(1 == C.EVP_DecryptUpdate(ctx, plain_text, ffi_len, cipher_text, cipher_text_len))
            return ffi.string(plain_text, ffi_len[0])
        end
    end

    local decryptor = makeDecryptor(cipher_type, key, iv)

    -- return lamdba that can decrypt supplied message
    return function (msg)
        --print("enc len " .. #msg)
        return decryptor(msg)
    end
end

local Config = require("config")
-- TODO: improve determining the hash sizes
local local_hmac_size = 32
local remote_hmac_size = 32
local localMsgDecryptor = makeMsgDecryptor(Config.local_ct, Config.local_key, Config.local_iv)
local remoteMsgDecryptor = makeMsgDecryptor(Config.remote_ct, Config.remote_key, Config.remote_iv)

SECIO = Proto("secio", "SECIO protocol")

-- fields related to Propose packets type
SECIO.fields.propose = ProtoField.bytes("Propose", "propose")
SECIO.fields.rand = ProtoField.bytes("Propose.rand", "rand")
SECIO.fields.pubkey = ProtoField.bytes("Propose.pubkey", "pubkey")
SECIO.fields.exchanges = ProtoField.string("Propose.exchanges", "exchanges")
SECIO.fields.ciphers = ProtoField.string("Propose.ciphers", "ciphers")
SECIO.fields.hashes = ProtoField.string("Propose.hashes", "hashes")

-- fields related to Exchange packets type
SECIO.fields.exchange = ProtoField.bytes("Exchange", "exchange")
SECIO.fields.epubkey = ProtoField.string("Exchange.epubkey", "epubkey")
SECIO.fields.signature = ProtoField.string("Exchange.signature", "signature")

-- since the dissector function could be invoked many times, we need to save some info
-- to avoid parsing and decrypting on each invocation
local localProposeFrameNumber = -1
local remoteProposeFrameNumber = -1
local localExchangeFrameNumber = -1
local remoteExchangeFrameNumber = -1
local decrypted_msgs = {}

function SECIO.dissector (buffer, pinfo, tree)
    -- TODO: implement multistream dissector
    -- the message should be at least 16 symbols ("./secio/ 1.0.0.")
    if buffer:len() < 16 then
        local subtree = tree:add(SECIO, "SECIO protocol")
        subtree:add(buffer(0, buffer:len()), "body")
        return
    end

    -- according to the spec, there is always 4 bytes for packet size
    local cipher_txt_size = buffer(0, 4):uint()

    -- checks that message not beginning with the "./mu" string
    -- TODO: need to be refactored
    if (cipher_txt_size == 0x132f6d75) then
        -- skip the first messages with the description of protocol versions:
        -- 00000000  13 2f 6d 75 6c 74 69 73  74 72 65 61 6d 2f 31 2e   ./multis tream/1.
        -- 00000010  30 2e 30 0a 0d 2f 73 65  63 69 6f 2f 31 2e 30 2e   0.0../se cio/1.0.
        -- 00000020  30 0a                                              0.
        -- TODO: in the future we need to care about these fields
        return
    end

    -- checks that message not beginning with the "./se" string
    -- TODO: need to be refactored
    if (cipher_txt_size == 0x0d2f7365) then
        -- skip the first messages with the description of protocol versions:
        -- 00000014  0d 2f 73 65 63 69 6f 2f  31 2e 30 2e 30 0a         ./secio/ 1.0.0.
        -- TODO: in the future we need to care about these fields
        return
    end

    local subtree = tree:add(SECIO, "SECIO protocol")

    pinfo.cols.protocol = "SECIO"

    if (localProposeFrameNumber == -1 or remoteProposeFrameNumber == -1) or
            (pinfo.number == localProposeFrameNumber or pinfo.number == remoteProposeFrameNumber) then

        pinfo.cols.info = "SECIO Propose"

        if not pinfo.visited and (localProposeFrameNumber == -1) then
            print("local Propose packet seen")
            localProposeFrameNumber = pinfo.number
        elseif not pinfo.visited and (remoteProposeFrameNumber == -1) then
            print("remote Propose packet seen")
            remoteProposeFrameNumber = pinfo.number
        end

        subtree:add(buffer(0, 4), string.format("Propose message size 0x%x bytes", cipher_txt_size))
        local branch = subtree:add("Propose", SECIO.fields.propose)

        local propose = assert(pb.decode("Propose", buffer:raw(4, cipher_txt_size)))
        local offset = 4

        -- check for fields presence and add them to the tree
        if (propose.rand ~= nil) then
            branch:add(SECIO.fields.rand, buffer(offset, propose.rand:len() + 3))
            offset = offset + propose.rand:len() + 3
        end

        if (propose.pubkey ~= nil) then
            branch:add(SECIO.fields.pubkey, buffer(offset, propose.pubkey:len() + 4))
            offset = offset + propose.pubkey:len() + 4
        end

        if (propose.exchanges ~= nil) then
            branch:add(SECIO.fields.exchanges, buffer(offset, propose.exchanges:len()))
            offset = offset + propose.exchanges:len()
        end

        if (propose.ciphers ~= nil) then
            branch:add(SECIO.fields.ciphers, buffer(offset + 2, propose.ciphers:len()))
            offset = offset + propose.ciphers:len()
        end

        if (propose.hashes ~= nil) then
            branch:add(SECIO.fields.hashes, buffer(offset + 4, propose.hashes:len()))
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
        local branch = subtree:add("Exchange", SECIO.fields.exchange)

        local exchange = assert(pb.decode("Exchange", buffer:raw(4, cipher_txt_size)))
        offset = 4

        -- check for fields presence and add them to the tree
        if (exchange.epubkey ~= nil) then
            branch:add(SECIO.fields.epubkey, buffer(offset, exchange.epubkey:len() + 2))
            offset = offset + exchange.epubkey:len() + 2
        end

        if (exchange.signature ~= nil) then
            branch:add(SECIO.fields.signature, buffer(offset, exchange.signature:len() + 2))
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
            if (Config.src_port == pinfo.src_port) then
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

tcp_table = DissectorTable.get ("tcp.port")
tcp_table:add(Config.src_port, SECIO)
tcp_table:add(Config.dst_port, SECIO)
