local libp2p_dissector_version = "0.1.2"

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

if not gui_enabled() then
    -- this plugin intended to run only in the GUI mode
    return
end

local function dissect()
    local function handle_path(key_file_path)

        --local key_file_path = os.getenv("LIBP2P_SECIO_KEYLOG")
        --assert(secret == nil, "Environment variable LIBP2P_SECIO_KEYLOG must be set")
        print("Using " .. key_file_path .. " as the key log file")

        -- enable loading of other modules
        _G['secio_dissector'] = {}

        local Config = require("config")
        Config:load_config(key_file_path)

        -- enable other modules
        package.prepend_path("protocols")
        package.prepend_path("protocols/multistream")
        package.prepend_path("protocols/secio")
        package.prepend_path("protocols/mplex")

        -- register dissectors
        require("multistream")
        require("mplex")
        require("secio")

        -- reanalyze packets
        reload()
    end

    new_dialog("Enter path to the key file", handle_path, "path")
end

local function about_handler()
    cs_about_win = TextWindow.new("About libp2p dissector")
    cs_about_win:append(string.format("Plugin for Wireshark, version %s\n", libp2p_dissector_version))
    cs_about_win:append("Developed by Mike Voronov\n")
    cs_about_win:append("\n")
    cs_about_win:append("This Wireshark plugin allows you to dissect libp2p packets. ")
    cs_about_win:append("At now, multistream 1.0.0, secio and mplex protocols are supported. ")
end

register_menu("Libp2p dissector/Dissect", dissect, MENU_TOOLS_UNSORTED)
register_menu("Libp2p dissector/About", about_handler, MENU_TOOLS_UNSORTED)
