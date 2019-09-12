local libp2p_dissector_version = "0.1.5"

-- latest development release of Wireshark supports plugin version information
if set_plugin_info then
    local libp2p_dissector_info = {
        version   = libp2p_dissector_version,
        author    = "Mike Voronov",
        email     = "michail.vms@gmail.com",
        details   = "This is a plugin for Wireshark to dissect libp2p messages.",
        repository = "https://github.com/michaelvoronov/libp2p-dissector",
        help      = [[
    HOW TO RUN THIS SCRIPT:
    Either copy the entire folder into your "Personal Plugins" directory or load it from the command line.
    ]]
    }
    set_plugin_info(libp2p_dissector_info)
end

-- enable loading of our modules
_G['libp2p_dissector'] = {}

-- check that LIBP2P_SECIO_KEYLOG set
local key_file_path = os.getenv("LIBP2P_SECIO_KEYLOG")
assert(secret == nil, "Environment variable LIBP2P_SECIO_KEYLOG must be set")
print("libp2p dissector: use " .. key_file_path .. " as the key log file")

-- help wireshark find other modules
package.prepend_path("utils")
package.prepend_path("protocols")
package.prepend_path("protocols/multistream")
package.prepend_path("protocols/secio")
package.prepend_path("protocols/mplex")
