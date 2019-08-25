local pb = require ("pb")
local protoc = require ("protoc")
local csv = require("csv")
local base64 = require ("base64")
local ffi = require ("ffi")
local C = ffi.C
local ssl = ffi.load "ssl"

local bor = bit.bor
local band = bit.band
local lshift = bit.lshift
local rshift = bit.rshift

-- https://stackoverflow.com/questions/35557928/ffi-encryption-decryption-with-luajit
ffi.cdef [[
  typedef struct evp_cipher_st EVP_CIPHER;
  typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
  typedef struct engine_st ENGINE;

  EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
  int EVP_CIPHER_CTX_reset(EVP_CIPHER_CTX *ctx);
  void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx);

  int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
         ENGINE *impl, const unsigned char *key, const unsigned char *iv);
  int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
         int *outl, const unsigned char *in, int inl);
  int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out,
         int *outl);

  int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
         ENGINE *impl, const unsigned char *key, const unsigned char *iv);
  int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
         int *outl, const unsigned char *in, int inl);
  int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);


  const EVP_CIPHER *EVP_aes_128_ctr(void);
  const EVP_CIPHER *EVP_aes_256_ctr(void);
]]

assert(protoc:load [[
    message Propose {
        optional bytes rand = 1;
        optional bytes pubkey = 2;
        optional string exchanges = 3;
        optional string ciphers = 4;
        optional string hashes = 5;
    }

    message Exchange {
        optional bytes epubkey = 1;
        optional bytes signature = 2;
    } ]])

local key_file_path = os.getenv("LIBP2P_SECIO_KEYLOG")
assert(secret == nil, "Environment variable LIBP2P_SECIO_KEYLOG must be set")

print("Using " .. key_file_path .. " as the key log file")

local key_file = csv.open(key_file_path)

local last_src = ""
local last_dst = ""
local last_local_key = ""
local last_local_iv = ""
local last_local_mac = ""
local last_local_ct = ""
local last_remote_key = ""
local last_remote_iv = ""
local last_remote_mac = ""
local last_remote_ct = ""

for fields in key_file:lines() do
    -- TODO: improve the "algo"
    for i, v in ipairs(fields) do
        if i == 1 then
            last_src = v
        elseif i == 2 then
            last_dst = v
        elseif i == 3 then
            last_local_key = v
        elseif i == 4 then
            last_local_iv = v
        elseif i == 5 then
            last_local_mac = v
        elseif i == 6 then
            last_local_ct = v
        elseif i == 7 then
            last_remote_key = v
        elseif i == 8 then
            last_remote_iv = v
        elseif i == 9 then
            last_remote_mac = v
        elseif i == 10 then
            last_remote_ct = v
        end
    end
end

print(last_src .. ' will be used as the src ip:port')
print(last_dst .. ' will be used as the dst ip:port')
print(last_local_key .. ' will be used as the local key')
print(last_remote_key .. ' will be used as the remote key')

local local_key = base64.decode(last_local_key)
local local_iv = base64.decode(last_local_iv)
local local_mac = base64.decode(last_local_mac)
local local_ct = last_local_ct
local remote_key = base64.decode(last_remote_key)
local remote_iv = base64.decode(last_remote_iv)
local remote_mac = base64.decode(last_remote_mac)
local remote_ct = last_remote_ct

local src_port = string.format("%d", string.match(last_src, ":(%d+)"))
local dst_port = string.format("%d", string.match(last_dst, ":(%d+)"))

print(src_port .. " will be used as the src port")
print(dst_port .. " will be used as the dst port")

MPLEX = Proto ("mplex", "MPLEX protocol")

function MPLEX.dissector (buffer, pinfo, tree)
    pinfo.cols.protocol = "MPLEX"
    pinfo.cols.info = "MPLEX Body"

    local tt = band(buffer(0, 1):uint(), 0xFF)
    print("stream_id " .. rshift(tt, 3))
    print("flags " .. band(tt, 0x7))

end

-- returns lamdba that can decrypt SECIO messages based on the provided cipher settings
local function makeMsgDecryptor(cipher_type, key, iv)
    -- returns lamdba that can decrypt raw cipher text based on the provided parameters
    local function makeDecryptor(cipher_type, key, iv)
        -- initialize the cipher context
        local ctx = C.EVP_CIPHER_CTX_new()
        assert(ctx ~= nil)

        -- set up the cipher type
        if "AES-128" == cipher_type then
            -- EVP_DecryptInit_ex returns 1 if succed and 0 otherwise
            assert(1 == C.EVP_DecryptInit_ex(ctx, C.EVP_aes_128_ctr(), nil, key, iv))
        elseif "AES-256" == cipher_type then
            -- EVP_DecryptInit_ex returns 1 if succed and 0 otherwise
            assert(1 == C.EVP_EncryptInit_ex(ctx, C.EVP_aes_256_ctr(), nil, key, iv))
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

-- TODO: improve determiniting the hash sizes
local local_hash_size = local_mac:len()
local remote_hash_size = remote_mac:len()
local localMsgDecryptor = makeMsgDecryptor(local_ct, local_key, local_iv)
local remoteMsgDecryptor = makeMsgDecryptor(remote_ct, remote_key, remote_iv)

SECIO = Proto ("secio", "SECIO protocol")

local fields = SECIO.fields
fields.propose = ProtoField.bytes ("Propose", "propose")
fields.rand = ProtoField.bytes ("Propose.rand", "rand")
fields.pubkey = ProtoField.bytes ("Propose.pubkey", "pubkey")
fields.exchanges = ProtoField.string ("Propose.exchanges", "exchanges")
fields.ciphers = ProtoField.string ("Propose.ciphers", "ciphers")
fields.hashes = ProtoField.string ("Propose.hashes", "hashes")

fields.exchange = ProtoField.bytes ("Exchange", "exchange")
fields.epubkey = ProtoField.string ("Exchange.epubkey", "epubkey")
fields.signature = ProtoField.string ("Exchange.signature", "signature")

local localProposeFrameNumber = -1
local remoteProposeFrameNumber = -1
local localExchangeFrameNumber = -1
local remoteExchangeFrameNumber = -1

local decrypted_msgs = {}

function SECIO.dissector (buffer, pinfo, tree)
    local offset = 0

    -- the message should be at least 16 symbols ("./secio/ 1.0.0.")
    if buffer:len() < 16 then
        local subtree = tree:add(SECIO, "SECIO protocol")
        subtree:add(buffer(0, buffer:len()), "body")
        return
    end

    local cipher_txt_size = buffer(0, 4):uint()

    if (cipher_txt_size == 0x132f6d75) then
        -- skip the first messages with the description of protocol versions:
        -- 00000000  13 2f 6d 75 6c 74 69 73  74 72 65 61 6d 2f 31 2e   ./multis tream/1.
        -- 00000010  30 2e 30 0a 0d 2f 73 65  63 69 6f 2f 31 2e 30 2e   0.0../se cio/1.0.
        -- 00000020  30 0a                                              0.
        -- TODO: in the future we need to care about these fields
        return
    end

    if (cipher_txt_size == 0x0d2f7365) then
        -- skip the first messages with the description of protocol versions:
        -- 00000014  0d 2f 73 65 63 69 6f 2f  31 2e 30 2e 30 0a         ./secio/ 1.0.0.
        -- TODO: in the future we need to care about these fields
        return
    end

    local subtree = tree:add(SECIO, "SECIO protocol")

    pinfo.cols.protocol = "SECIO"
    -- check that for Propose packets
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
        local branch = subtree:add("Propose", fields.propose)

        local propose = assert(pb.decode("Propose", buffer:raw(4, cipher_txt_size)))
        offset = 4

        if (propose.rand ~= nil) then
            branch:add(fields.rand, buffer(offset, propose.rand:len() + 3))
            offset = offset + propose.rand:len() + 3
        end

        if (propose.pubkey ~= nil) then
            branch:add(fields.pubkey, buffer(offset, propose.pubkey:len() + 3))
            offset = offset + propose.pubkey:len() + 3
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
        offset = 4

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
        local hash_size = local_hash_size
        if not pinfo.visited then
            -- if seen this packet for the first time, we need to decrypt it
            if (src_port == pinfo.src_port) then
                plain_text = localMsgDecryptor(buffer:raw(4, cipher_txt_size - local_hash_size))
            else
                plain_text = remoteMsgDecryptor(buffer:raw(4, cipher_txt_size - remote_hash_size))
                hash_size = remote_hash_size
            end

            decrypted_msgs[pinfo.number] = plain_text
        else
            plain_text = decrypted_msgs[pinfo.number]
        end

        subtree:add(buffer(0, 4), string.format("cipher text size: 0x%x bytes", cipher_txt_size))
        subtree:add(buffer(4, cipher_txt_size - hash_size), string.format("cipher test: decrypted: %s", Struct.tohex(tostring(plain_text))) )

        Dissector.get("mplex"):call(buffer(4, cipher_txt_size - hash_size):tvb(), pinfo, tree)
    end
end

tcp_table = DissectorTable.get ("tcp.port")
tcp_table:add(src_port, SECIO)
tcp_table:add(dst_port, SECIO)
