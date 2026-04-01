#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::ffi::{c_int, c_void, CStr, CString};
use std::ptr::null;
use std::sync::Mutex;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

const MODULE: &str = "openvpn-totp";

#[unsafe(no_mangle)]
unsafe extern "C" fn openvpn_plugin_open_v2(
    type_mask: *mut ::std::os::raw::c_uint,
    argv: *mut *const ::std::os::raw::c_char,
    envp: *mut *const ::std::os::raw::c_char,
    return_list: *mut *mut openvpn_plugin_string_list,
) -> openvpn_plugin_handle_t {
    panic!("openvpn_plugin_open_v2 not implemented");
}
#[unsafe(no_mangle)]
unsafe extern "C" fn openvpn_plugin_func_v2(
    handle: openvpn_plugin_handle_t,
    type_: ::std::os::raw::c_int,
    argv: *mut *const ::std::os::raw::c_char,
    envp: *mut *const ::std::os::raw::c_char,
    per_client_context: *mut ::std::os::raw::c_void,
    return_list: *mut *mut openvpn_plugin_string_list,
) -> ::std::os::raw::c_int {
    panic!("openvpn_plugin_func_v2 not implemented");
}

#[derive(Debug)]
struct State {
    plugin_vlog_func: plugin_vlog_t
}

impl State {
    const fn new() -> Self {
        State { plugin_vlog_func: None }
    }
}

static GLOBSTATE: Mutex<State> = Mutex::new(State::new());

struct PluginContext {

}

#[unsafe(no_mangle)]
unsafe extern "C" fn openvpn_plugin_open_v3(
    version: ::std::os::raw::c_int,
    arguments: *const openvpn_plugin_args_open_in,
    retptr: *mut openvpn_plugin_args_open_return,
) -> ::std::os::raw::c_int {
    if (version < OPENVPN_PLUGIN_STRUCTVER_MIN) {
        println!("{}: this plugin is incompatible with the running version of OpenVPN\n", MODULE);
        return OPENVPN_PLUGIN_FUNC_ERROR as c_int
    }

    GLOBSTATE.lock().unwrap().plugin_vlog_func = (*(*arguments).callbacks).plugin_vlog;

    // TODO What happens with lifetimes here?
    let context = &PluginContext{};

    (*retptr).type_mask = OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY as c_int;
    (*retptr).handle = context as *const PluginContext as openvpn_plugin_handle_t;

    return OPENVPN_PLUGIN_FUNC_SUCCESS as c_int;
}

#[unsafe(no_mangle)]
unsafe extern "C" fn openvpn_plugin_func_v3(
    version: ::std::os::raw::c_int,
    arguments: *const openvpn_plugin_args_func_in,
    retptr: *mut openvpn_plugin_args_func_return,
) -> ::std::os::raw::c_int {
    if (version < OPENVPN_PLUGIN_STRUCTVER_MIN) {
        println!("{}: this plugin is incompatible with the running version of OpenVPN\n", MODULE);
        return OPENVPN_PLUGIN_FUNC_ERROR as c_int
    }

    let context : &PluginContext = &*((*arguments).handle as *const PluginContext);
    let envp = (*arguments).envp;

    let mut i = 0;

    while let value =  envp.add(i) && !(*value).is_null() {
        let entry = CStr::from_ptr(*value);

        let c_str = CString::new(MODULE).unwrap();
        let ptr = c_str.as_ptr();
        GLOBSTATE.lock().unwrap().plugin_vlog_func.unwrap()(openvpn_plugin_log_flags_t_PLOG_WARN, ptr, c"ENV %s".as_ptr(), TODO);
        i += 1;
    }


    // TODO DO stuff

    return OPENVPN_PLUGIN_FUNC_SUCCESS as c_int;
}

#[unsafe(no_mangle)]
unsafe extern "C" fn openvpn_plugin_close_v1(handle: openvpn_plugin_handle_t) {
    let context : &PluginContext = &*(handle as *const PluginContext);
    // TODO Cleanup
}

const OPENVPN_PLUGIN_VERSION_MIN: std::os::raw::c_int = 3;
const OPENVPN_PLUGIN_STRUCTVER_MIN: std::os::raw::c_int = 5;

#[unsafe(no_mangle)]
unsafe extern "C" fn openvpn_plugin_min_version_required_v1() -> ::std::os::raw::c_int {
    return OPENVPN_PLUGIN_VERSION_MIN;
}