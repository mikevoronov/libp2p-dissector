local libp2p_dissector_version = "0.1.1"

-- latest development release of Wireshark supports plugin version information
if set_plugin_info then
    local libp2p_dissector_info = {
        version   = libp2p_dissector_version,
        author    = "Mike Voronov",
        email     = "michail.vms@gmail.com",
        details   = "This is a plugin for Wireshark, to dissect SECIO protocol messages.",
        repository = "https://github.com/michaelvoronov/secio-dissector",
        help      = [[
    HOW TO RUN THIS SCRIPT:
    Either copy this folder into your "Personal Plugins" directory or load it from the command line.
    ]]
    }
    set_plugin_info(libp2p_dissector_info)
end

-- enable loading of our modules
_G['secio_dissector'] = {}

local key_file_path = os.getenv("LIBP2P_SECIO_KEYLOG")
assert(secret == nil, "Environment variable LIBP2P_SECIO_KEYLOG must be set")
print("Using " .. key_file_path .. " as the key log file")

local Config = require("config")
Config:load_config(key_file_path)

-- help wireshark find other modules
package.prepend_path("protocols")
package.prepend_path("protocols/multistream")
package.prepend_path("protocols/secio")
package.prepend_path("protocols/mplex")