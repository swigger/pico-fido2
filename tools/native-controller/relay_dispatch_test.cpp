// The real HID, APDU and CBOR dispatchers run against observable local handlers
// and transport fixtures. No credential files, USB hardware or network are used.
#include "tusb.h"
#include <cstring>
#include <mbedtls/ecp.h>
extern "C" {
#include "apdu.h"
#include "file.h"
#include "usb.h"
#include "remote_presence.h"
#include "hid/ctap_hid.h"
#include "../../pico-fido/src/fido/ctap.h"
#include "../../pico-fido/src/fido/management.h"
void hid_init(void);
void tud_hid_set_report_cb(uint8_t, uint8_t, hid_report_type_t, const uint8_t *, uint16_t);
uint16_t tud_hid_get_report_cb(uint8_t, uint8_t, hid_report_type_t, uint8_t *, uint16_t);
void tud_hid_report_complete_cb(uint8_t, const uint8_t *, uint16_t);
int driver_write_hid(uint8_t, const uint8_t *, uint16_t);
int cbor_parse(uint8_t, const uint8_t *, size_t);
extern uint8_t cbor_cmd;
extern const uint8_t *cbor_data;
extern size_t cbor_len;
extern uint8_t *rdata_gr, *chain_ptr;
extern uint16_t rdata_bk;
extern uint8_t chain_buf[2038];
extern bool is_chaining;
}
#include <array>
#include <cstdio>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
void check(bool value, const char *message) { if (!value) throw std::runtime_error(message); }
bool local = true, workerBusy = false;
bool completeDuringSubmit = false;
unsigned initializations = 0, selections = 0, handlers = 0, resets = 0, forwarded = 0;
unsigned continuations = 0, featureGets = 0, featureSets = 0;
unsigned flashWrites = 0;
std::array<uint8_t,2048> flash{};
uint8_t lastForwardCommand = 0, lastHandler = 0;
int forwardResult = 0;
const uint8_t *lastForwardData = nullptr;
size_t lastForwardLength = 0;
std::vector<uint8_t> sent, continuation;
void *(*scheduled)(void *) = nullptr;
uint32_t event = 0, ticks = 100;
int localHandler(uint8_t tag) {
    ++handlers; lastHandler = tag; res_APDU[0] = tag; res_APDU_size = 1; return 0;
}
void send(uint8_t command, const std::vector<uint8_t> &payload) {
    check(payload.size() <= 57, "single-frame fixture too large");
    CTAPHID_FRAME frame{}; frame.cid = command == CTAPHID_INIT ? CID_BROADCAST : 0x01000000;
    frame.init.cmd = command; frame.init.bcntl = static_cast<uint8_t>(payload.size());
    memcpy(frame.init.data, payload.data(), payload.size()); sent.clear(); scheduled = nullptr; event = 0;
    tud_hid_set_report_cb(ITF_HID_CTAP, 0, HID_REPORT_TYPE_OUTPUT, reinterpret_cast<const uint8_t *>(&frame), 64);
    if (!sent.empty()) tud_hid_report_complete_cb(ITF_HID_CTAP, sent.data(), static_cast<uint16_t>(sent.size()));
}
void hidIsolation() {
    for (bool allowed : {false, true}) {
        local = allowed;
        auto before = initializations; send(CTAPHID_INIT, {1,2,3,4,5,6,7,8});
        check(initializations == before + (allowed ? 1 : 0), "relay/fault HID INIT initialized local FIDO storage");
        check(sent.size() == 64, "missing INIT response");
        auto response = reinterpret_cast<const CTAPHID_FRAME *>(sent.data());
        auto init = reinterpret_cast<const CTAPHID_INIT_RESP *>(response->init.data);
        check(((init->capFlags & 0x08) == 0) == allowed, "wrong NMSG mode capability");
        check(init->nonce[0] == 1 && init->nonce[7] == 8 && init->cid == 0x01000000, "INIT response changed");
        for (uint8_t cmd : {uint8_t(CTAPHID_MSG), uint8_t(CTAPHID_OTP), uint8_t(CTAPHID_CBOR), uint8_t(0xc0), uint8_t(CTAP_VENDOR_CBOR), uint8_t(0xc2)}) {
            before = selections; auto oldHandlers = handlers;
            send(cmd, cmd == CTAPHID_MSG || cmd == CTAPHID_OTP ? std::vector<uint8_t>{0,1,0,0,0} : std::vector<uint8_t>{CTAP_GET_INFO});
            check(selections == before + (allowed ? 1 : 0), "relay/fault HID selected a local applet");
            check(handlers == oldHandlers && scheduled && event == EV_CMD_AVAILABLE, "HID bypassed the worker");
            if (cmd == CTAPHID_CBOR || cmd == 0xc0 || cmd == CTAP_VENDOR_CBOR || cmd == 0xc2) {
                auto oldForwarded = forwarded;
                auto rc = cbor_parse(cbor_cmd, cbor_data, cbor_len);
                check(rc == (allowed && cmd == 0xc0 ? CTAP1_ERR_INVALID_CMD : 0) &&
                      forwarded == oldForwarded + (allowed ? 0 : 1), "HID CBOR dispatch boundary");
            } else {
                auto rc = process_apdu();
                check(rc == (allowed ? 0x9000 : 0x6985), "HID APDU dispatch boundary");
            }
        }
    }
    local = false;
    auto before = handlers + selections + initializations;
    for (uint8_t cmd : {uint8_t(CTAPHID_PING), uint8_t(CTAPHID_UUID), uint8_t(CTAPHID_VERSION), uint8_t(CTAPHID_ADMIN)}) {
        send(cmd, {0x80}); check(handlers + selections + initializations == before, "metadata command touched credentials");
    }
    std::array<uint8_t,63> feature{};
    check(tud_hid_get_report_cb(ITF_HID_REMOTE, 16, HID_REPORT_TYPE_FEATURE, feature.data(), 63) == 63 && featureGets == 1,
        "relay provisioning feature GET unavailable");
    check(tud_hid_get_report_cb(ITF_HID_REMOTE, 16, HID_REPORT_TYPE_INPUT, feature.data(), 63) == 0 && featureGets == 1,
        "wrong feature GET type accepted");
    tud_hid_set_report_cb(ITF_HID_REMOTE, 19, HID_REPORT_TYPE_FEATURE, feature.data(), 63);
    tud_hid_set_report_cb(ITF_HID_REMOTE, 19, HID_REPORT_TYPE_OUTPUT, feature.data(), 63);
    check(featureSets == 1 && handlers + selections + initializations == before, "provisioning feature SET reached local app");
}
void hidEarlyCompletion() {
    // On ESP32 the higher-priority TinyUSB task may complete a transfer before
    // tud_hid_n_report returns to the application task. The next transfer must
    // remain possible after that completion (including periodic keepalives).
    std::array<uint8_t,64> packet{};
    packet[4] = CTAPHID_KEEPALIVE; packet[6] = 1; packet[7] = 1;
    completeDuringSubmit = true;
    for (unsigned i = 0; i < 50; ++i)
        check(driver_write_hid(ITF_HID_CTAP, packet.data(), packet.size()) == 64,
            "early USB completion left HID permanently pending");
    completeDuringSubmit = false;
}
void apduIsolation() {
    std::array<uint8_t,128> response{};
    std::array<uint8_t,16> request{};
    // A GET RESPONSE must pass the mode gate before accessing a saved response,
    // even when a prior local exchange left continuation/chaining state behind.
    for (unsigned index = 0; index < 256; ++index) {
        unsigned ins = (index + 0xc0) & 0xff;
        local = false; response.fill(0xa5); request = {0,static_cast<uint8_t>(ins),0,0,4};
        apdu.rdata = response.data(); apdu.rlen = 12; rdata_gr = response.data() + 4; rdata_bk = 0xb6b7;
        is_chaining = true; memset(chain_buf, 0x5a, sizeof(chain_buf)); chain_ptr = chain_buf + 8;
        auto before = continuations; auto oldHandlers = handlers + selections;
        check(apdu_process(ITF_SC_CCID, request.data(), 5) == 1, "blocked GET RESPONSE bypassed worker gate");
        check(continuations == before, "blocked APDU exposed a saved continuation");
        check(process_apdu() == 0x6985 && apdu.rlen == 0, "blocked APDU did not return conditions-not-satisfied");
        check(handlers + selections == oldHandlers && !is_chaining && chain_ptr == chain_buf && rdata_bk == 0 && rdata_gr == apdu.rdata,
            "blocked APDU retained continuation/chaining state or selected an applet");
        for (auto b : chain_buf) check(b == 0, "blocked APDU retained chained bytes");
        apdu_finish(); check(apdu_next() == 2 && response[0] == 0x69 && response[1] == 0x85, "blocked APDU returned old payload bytes");
    }
    // A relay boot has no previous continuation pointer at all.
    rdata_gr = nullptr; apdu.rdata = response.data(); request = {0,0xc0,0,0,0};
    check(apdu_process(ITF_SC_CCID, request.data(), 5) == 1 && process_apdu() == 0x6985, "initial GET RESPONSE not rejected");
    check(apdu_process(ITF_SC_CCID, nullptr, 0) == 1 && process_apdu() == 0x6985, "blocked malformed APDU was parsed");
    // Recheck after scheduling: a later runtime storage fault must also block.
    local = true; request = {0,1,0,0,0}; check(apdu_process(ITF_SC_CCID, request.data(), 5) == 1, "local APDU not scheduled");
    local = false; auto before = handlers; check(process_apdu() == 0x6985 && handlers == before, "worker ignored late fault");
    // The normal local continuation path remains usable.
    local = true; response.fill(0x35); apdu.rdata = response.data(); apdu.rlen = 6;
    rdata_gr = response.data(); rdata_bk = 0x4243; request = {0,0xc0,0,0,8}; before = continuations;
    check(apdu_process(ITF_SC_CCID, request.data(), 5) == 0 && continuations == before + 1 && continuation.size() == 8,
        "local GET RESPONSE regressed");
    check(continuation[0] == 0x42 && continuation[1] == 0x43 && apdu.rlen == 0, "local continuation bytes changed");
    request = {0,0xa4,4,0,1,0x22}; check(apdu_process(ITF_SC_CCID, request.data(), 6) == 1, "local SELECT parse");
    before = selections; check(process_apdu() == 0x9000 && selections == before + 1, "local SELECT regressed");
}
void cborIsolation() {
    std::array<uint8_t,2048> response{}; apdu.rdata = response.data() + 1;
    for (auto result : {0, 0x7f, 0x2e, 0x30}) {
        local = false; forwardResult = result;
        auto before = handlers + selections + resets;
        for (unsigned operation = 0; operation < 256; ++operation) {
            uint8_t request[] = {static_cast<uint8_t>(operation), 0xa0};
            auto oldForwarded = forwarded;
            check(cbor_parse(CTAPHID_CBOR, request, sizeof(request)) == result && forwarded == oldForwarded + 1,
                "CBOR operation failed to route through relay/fault handler");
            check(lastForwardCommand == CTAPHID_CBOR && lastForwardData == request && lastForwardLength == sizeof(request), "relay request changed");
            check(handlers + selections + resets == before && apdu.rlen == (result ? 0 : 3), "relay error fell back to local handler");
        }
        for (uint8_t cmd : {uint8_t(0xc0), uint8_t(CTAP_VENDOR_CBOR), uint8_t(0xc2), uint8_t(0xff), uint8_t(CTAPHID_CBOR)}) {
            check(cbor_parse(cmd, nullptr, 0) == result && lastForwardCommand == cmd && !lastForwardLength &&
                  handlers + selections + resets == before, "empty/vendor command reached local handler");
        }
    }
    local = true; forwardResult = 0;
    for (uint8_t operation : {uint8_t(CTAP_MAKE_CREDENTIAL),uint8_t(CTAP_GET_INFO),uint8_t(CTAP_RESET),uint8_t(CTAP_CLIENT_PIN),
            uint8_t(CTAP_GET_ASSERTION),uint8_t(CTAP_GET_NEXT_ASSERTION),uint8_t(CTAP_SELECTION),uint8_t(CTAP_CREDENTIAL_MGMT),
            uint8_t(0x41),uint8_t(CTAP_CONFIG),uint8_t(CTAP_LARGE_BLOBS)}) {
        auto before = handlers; auto oldForwarded = forwarded;
        check(cbor_parse(CTAPHID_CBOR, &operation, 1) == 0 && handlers == before + 1 && forwarded == oldForwarded,
            "local CBOR handler compatibility regressed");
        check(lastHandler == (operation == 0x41 ? CTAP_CREDENTIAL_MGMT : operation), "wrong local handler");
    }
    check(cbor_parse(CTAPHID_CBOR, nullptr, 0) == CTAP1_ERR_INVALID_LEN, "local empty request changed");
}
void flashScanIsolation() {
    for (bool allowed : {false,true}) for (uint8_t marker : {uint8_t(0xff),uint8_t(0xef)}) {
        local = allowed; flash.fill(marker); ef_phy->data = nullptr; flashWrites = 0;
        auto before = flash; scan_flash();
        check(flashWrites == (allowed ? 2u : 0u), "relay/fault scan initialized dormant flash directories");
        if (!allowed) check(flash == before, "read-only scan changed flash bytes");
        else check(flash != before, "local first-use initialization regressed");
    }
    // A normal existing PHY record must still be discoverable in relay mode;
    // preserving the USB settings does not require writing credential storage.
    for (bool allowed : {false,true}) {
        local = allowed; flash.fill(0); ef_phy->data = nullptr; flashWrites = 0;
        uintptr_t base = 0x180; memcpy(flash.data()+0x300, &base, sizeof(base));
        uint16_t fid = EF_PHY, size = 3;
        memcpy(flash.data()+base+2*sizeof(uintptr_t), &fid, sizeof(fid));
        memcpy(flash.data()+base+2*sizeof(uintptr_t)+2, &size, sizeof(size));
        memcpy(flash.data()+base+2*sizeof(uintptr_t)+4, "PHY", 3);
        auto before = flash; scan_flash();
        check(!flashWrites && flash == before && file_get_size(ef_phy) == 3 && !memcmp(file_get_data(ef_phy), "PHY", 3),
            "existing flash/USB metadata scan regressed");
    }
}
}

extern "C" {
struct apdu apdu{};
file_t file_entries[1]{};
const file_t *file_last=file_entries+1, *MF=file_entries;
extern const uintptr_t start_rom_pool=0x100, end_rom_pool=0x300, start_data_pool=0x500, end_data_pool=0x700;
uintptr_t last_base=0;
uint32_t num_files=0;
uint8_t *flash_read(uintptr_t addr) { check(addr < flash.size(), "flash address out of range"); return flash.data()+addr; }
uintptr_t flash_read_uintptr(uintptr_t addr) { uintptr_t v; memcpy(&v,flash_read(addr),sizeof(v)); return v; }
uint16_t flash_read_uint16(uintptr_t addr) { uint16_t v; memcpy(&v,flash_read(addr),sizeof(v)); return v; }
uint8_t flash_read_uint8(uintptr_t addr) { return *flash_read(addr); }
int flash_program_block(uintptr_t addr,const uint8_t *data,size_t length) {
    check(addr + length <= flash.size(), "flash write out of range"); ++flashWrites; memcpy(flash_read(addr),data,length); return PICOKEY_OK;
}
int flash_write_data_to_file(file_t *,const uint8_t *,uint16_t) { check(false,"unexpected credential write"); return -1; }
int flash_clear_file(file_t *) { check(false,"unexpected credential deletion"); return -1; }
void low_flash_available(void) { check(false,"unexpected flash flush"); }
app_t fixtureApp{}; app_t *current_app = &fixtureApp;
test_serial_t pico_serial{};
extern const uint8_t fido_aid[] = {1,0xf1}, u2f_aid[] = {1,0xf2}, oath_aid[] = {1,0xf3};
uint8_t ITF_HID_CTAP=0, ITF_HID_KB=1, ITF_HID_REMOTE=2, ITF_HID_TOTAL=3, ITF_HID=0, ITF_REMOTE=2, ITF_KEYBOARD=1;
uint8_t ITF_SC_CCID=3, ITF_SC_WCID=4;
queue_t usb_to_card_q{}, card_to_usb_q{};
uint16_t finished_data_size=0;
uint32_t timeout=0;
bool cancel_button=false;
bool remote_device_local_allowed(void) { return local; }
uint8_t remote_device_keepalive(void) { return 1; }
bool remote_presence_pairing(void) { return false; }
void remote_presence_clear(void) {}
uint16_t remote_presence_get(uint8_t report, uint8_t *b, uint16_t length) {
    check(report == 16 && length == 63, "feature GET fixture"); ++featureGets; memset(b, 0, length); return length;
}
void remote_presence_set(uint8_t report, const uint8_t *, uint16_t length) { check(report == 19 && length == 63, "feature SET fixture"); ++featureSets; }
int remote_device_cbor(uint8_t cmd, const uint8_t *data, size_t length, uint8_t *out, size_t capacity, uint16_t *outLength) {
    ++forwarded; lastForwardCommand=cmd; lastForwardData=data; lastForwardLength=length;
    check(capacity == CTAP_MAX_CBOR_PAYLOAD, "relay response capacity changed");
    *outLength = forwardResult ? 0 : 3; if (!forwardResult) memcpy(out, "\xa1\x01\xf5", 3); return forwardResult;
}
void init_fido(void) { ++initializations; }
int selectedApdu(void) { ++handlers; return set_res_sw(0x90,0); }
int select_app(const uint8_t *, size_t) { ++selections; fixtureApp.process_apdu = selectedApdu; current_app = &fixtureApp; return PICOKEY_OK; }
bool cap_supported(uint16_t) { return true; }
int mbedtls_curve_to_fido(mbedtls_ecp_group_id) { check(false, "dispatch test unexpectedly invoked local COSE generation"); return 0; }
void reset_gna_state(void) { ++resets; }
int cbor_reset(void) { return localHandler(CTAP_RESET); }
int cbor_get_info(void) { return localHandler(CTAP_GET_INFO); }
int cbor_make_credential(const uint8_t *,size_t) { return localHandler(CTAP_MAKE_CREDENTIAL); }
int cbor_client_pin(const uint8_t *,size_t) { return localHandler(CTAP_CLIENT_PIN); }
int cbor_get_assertion(const uint8_t *,size_t,bool) { return localHandler(CTAP_GET_ASSERTION); }
int cbor_get_next_assertion(const uint8_t *,size_t) { return localHandler(CTAP_GET_NEXT_ASSERTION); }
int cbor_selection(void) { return localHandler(CTAP_SELECTION); }
int cbor_cred_mgmt(const uint8_t *,size_t) { return localHandler(CTAP_CREDENTIAL_MGMT); }
int cbor_config(const uint8_t *,size_t) { return localHandler(CTAP_CONFIG); }
int cbor_vendor(const uint8_t *,size_t) { return localHandler(CTAP_VENDOR_CBOR); }
int cbor_large_blobs(const uint8_t *,size_t) { return localHandler(CTAP_LARGE_BLOBS); }
int cmd_read_config(void) { localHandler(0xc2); return 0x9000; }
uint32_t board_millis(void) { return ++ticks; }
void sleep_ms(unsigned ms) { ticks += ms; }
void vTaskDelay(unsigned ms) { ticks += ms; }
void queue_remove_blocking(queue_t *, uint32_t *value) { *value = EV_EXIT; }
void queue_add_blocking(queue_t *, const uint32_t *) {}
void led_set_mode(unsigned) {}
bool is_req_button_pending(void) { return false; }
bool is_busy(void) { return workerBusy; }
void card_start(uint8_t, void *(*func)(void *)) { scheduled=func; }
void card_exit(void) {}
int card_status(uint8_t) { return 1; }
void card_init_core1(void) {}
void usb_send_event(uint32_t value) { event=value; }
void usb_set_timeout_counter(uint8_t, uint32_t) {}
void timeout_stop(void) {}
void driver_exec_finished_cont_ccid(uint8_t, uint16_t length, uint16_t offset) {
    ++continuations; continuation.assign(apdu.rdata + offset, apdu.rdata + offset + length);
}
void tud_init(unsigned) {}
bool tud_hid_ready(void) { return true; }
bool tud_suspended(void) { return false; }
void tud_remote_wakeup(void) {}
bool tud_hid_n_keyboard_report(uint8_t,uint8_t,uint8_t,const uint8_t *) { return true; }
bool tud_hid_n_report(uint8_t itf,uint8_t,const void *data,uint16_t length) {
    auto p = static_cast<const uint8_t *>(data); sent.assign(p,p+length);
    if (completeDuringSubmit) tud_hid_report_complete_cb(itf, sent.data(), length);
    return true;
}
}
int main(int argc, char **argv) {
    try {
        hid_init(); fixtureApp.process_apdu=selectedApdu;
        if (argc == 2 && std::string(argv[1]) == "--apdu") apduIsolation();
        else if (argc == 2 && std::string(argv[1]) == "--flash") flashScanIsolation();
        else { hidIsolation(); apduIsolation(); cborIsolation(); flashScanIsolation(); hidEarlyCompletion(); }
        puts("Actual HID/APDU/CBOR mode isolation and local compatibility passed."); return 0;
    } catch (const std::exception &e) { fprintf(stderr,"Dispatch test: %s\n",e.what()); return 1; }
}
