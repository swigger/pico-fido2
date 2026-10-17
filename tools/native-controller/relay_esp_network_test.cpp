#include "relay_server.h"
#include "relay_transport.h"
extern "C" {
#include "../../src/fido2/relay_network.h"
}
#include "relay-network-stubs/pico_keys.h"
#include "relay-network-stubs/esp_wifi.h"
#include "relay-network-stubs/esp_pm.h"
#include "relay-network-stubs/esp_netif.h"
#include "relay-network-stubs/nvs.h"
#include "relay-network-stubs/lwip/sockets.h"
#include "relay-network-stubs/lwip/dns.h"
#include <intrin.h>
#include <atomic>
#include <cerrno>
#include <cstdio>
#include <future>
#include <thread>
#include <algorithm>
#include <unordered_set>
#include <mutex>
#include <fstream>

namespace {
void check(bool ok,const char *message) { if (!ok) throw std::runtime_error(message); }
using V=ctap::Value;
std::unique_ptr<Key> controller, deviceKey;
esp_event_handler_t wifiHandler=nullptr, ipHandler=nullptr;
esp_netif_t station{};
std::atomic_bool mounted{true}, suspended{false}, waiting{false};
bool trusted=true, wrongDevice=false, wifiFail=false, wifiStall=false, dnsFail=false, dnsDelay=false;
bool partialSend=false, receiveFail=false, fragments=false;
bool tcpipFail=false, tcpipDelay=false, wifiInitFail=false;
bool noDelayFail=false;
bool noApFirst=false, mockAssociated=false, nvsUnavailable=false, nvsWriteFail=false;
unsigned wifiDisconnects=0, preferenceWrites=0;
Bytes preferenceBlob;
std::filesystem::path preferencePath;
std::vector<std::string> wifiAttempts;
unsigned noDelaySockets=0;
std::string trigger, ssid, addressMode;
unsigned stalledProfiles=1, wifiInitializations=0;
unsigned wifiConnects=0, connects=0, applicationConnections=0, maxKeepalive=0;
uint32_t clockOffset=0;
auto started=std::chrono::steady_clock::now();
struct FD { SOCKET socket=INVALID_SOCKET; bool application=false, broken=false; };
std::array<FD,16> descriptors{};
struct DnsPending { std::string name; dns_found_callback callback; void *arg; };
std::vector<DnsPending> delayed;
std::vector<std::pair<void (*)(void *),void *>> queuedDns;
std::unordered_set<void *> dnsAllocations;
unsigned discoveryFrames = 0;
bool stalledWifi() { return wifiStall && static_cast<unsigned>(std::stoul(ssid.substr(10)))<stalledProfiles; }
relay::Deadline deadline() { return std::chrono::steady_clock::now()+std::chrono::seconds(5); }
SOCKET native(int fd) { check(fd>=0 && static_cast<size_t>(fd)<descriptors.size() && descriptors[fd].socket!=INVALID_SOCKET,"invalid client socket"); return descriptors[fd].socket; }
int socketResult(int rc) {
    if (rc==SOCKET_ERROR) { errno=WSAGetLastError()==WSAEWOULDBLOCK ? EAGAIN : EIO; return -1; } return rc;
}
Bytes registration() {
    V algorithms; algorithms.type=V::Array;
    algorithms.items={V::map({V::string("type"),V::string("public-key"),V::string("alg"),V::integer(-7)})};
    auto payload=ctap::encode(V::map({V::integer(1),V::blob(Bytes(32,0x51)),
        V::integer(2),V::map({V::string("id"),V::string("esp-adapter.invalid")}),
        V::integer(3),V::map({V::string("id"),V::blob({1}),V::string("name"),V::string("synthetic")}),
        V::integer(4),algorithms}));
    payload.insert(payload.begin(),1); return payload;
}
relay_config_t settings(uint16_t port,unsigned count=1,const std::string &hostname="localhost") {
    relay_config_t c{}; c.mode=RELAY_MODE_RELAY; c.network_count=static_cast<uint8_t>(count);
    for (unsigned i=0;i<count;++i) {
        auto &n=c.networks[i]; auto name="synthetic-"+std::to_string(i);
        n.ssid_length=static_cast<uint8_t>(name.size()); memcpy(n.ssid,name.data(),name.size());
        const std::string password="test-only-password"; n.password_length=static_cast<uint8_t>(password.size()); memcpy(n.password,password.data(),password.size());
        n.host_length=static_cast<uint8_t>(hostname.size()); memcpy(n.host,hostname.data(),hostname.size()); n.port=port;
    }
    return c;
}
struct Answer { int code; Bytes bytes; };
Answer transact(const relay_config_t &c,const Bytes &request,size_t capacity=RELAY_CTAP_MAX) {
    Bytes response(capacity,0xa5); uint16_t length=0xffff;
    auto code=relay_network_exchange(&c,request.data(),request.size(),response.data(),response.size(),&length);
    check(length<=response.size() && relay_network_keepalive()==1,"response length/keepalive not reset");
    if (code) {
        check(length==0 && std::all_of(response.begin(),response.end(),[](auto b){return b==0;}),"error retained response bytes");
    }
    response.resize(length);
    check(std::none_of(descriptors.begin(),descriptors.end(),[](auto &fd){return fd.socket!=INVALID_SOCKET;}),"socket leaked");
    if (!dnsDelay && !tcpipDelay) check(dnsAllocations.empty(),"DNS allocation leaked");
    return {code,response};
}
struct Fixture {
    std::filesystem::path directory;
    std::unique_ptr<relay::Vault> vault;
    std::unique_ptr<relay::Server> server;
    std::atomic_bool stop{false};
    std::atomic_int approvals{0}, sessions{0};
    std::future<void> running;
    uint16_t port=0;
    std::string mode;
    explicit Fixture(std::string kind):mode(std::move(kind)) {
        auto random=randomBytes(12); directory=std::filesystem::temp_directory_path()/("pf2-esp-network-"+hex(random.data(),random.size()));
        relay::Vault::create(directory/L"vault.dpapi"); vault=std::make_unique<relay::Vault>(directory/L"vault.dpapi");
        server=std::make_unique<relay::Server>(*vault,*controller,[](const std::string &serial) {
            return serial==pico_serial_str ? deviceKey->pub() : Bytes{};
        },[&](const auto &approval,const auto &operation) {
            ++approvals;
            if (mode=="pending") {
                waiting=true;
                while (!operation.canceled()) std::this_thread::sleep_for(std::chrono::milliseconds(2));
                waiting=false; return relay::Decision{};
            }
            return relay::Decision{mode!="deny",approval.accounts.empty()?Bytes{}:approval.accounts.front().credentialId};
        });
        std::promise<uint16_t> ready; auto future=ready.get_future();
        running=std::async(std::launch::async,[&,promise=std::move(ready)]() mutable {
            server->run(addressMode.rfind("ipv6",0)==0?"::1":"127.0.0.1",0,[&]{return stop.load();},[&](auto p){promise.set_value(p);},{},[&]{++sessions;});
        });
        port=future.get();
    }
    ~Fixture() {
        stop=true; if (running.valid()) running.wait(); server.reset(); vault.reset();
        std::error_code error;
        for (const auto &entry:std::filesystem::directory_iterator(directory,error)) std::filesystem::remove(entry.path(),error);
        std::filesystem::remove(directory,error);
    }
};
struct Scripted {
    relay::Identity identity=relay::Identity::issue(*controller);
    relay::Socket listener=relay::Socket::listen("127.0.0.1",0);
    std::atomic_bool stop{false}; std::future<void> running;
    std::atomic_bool requestSeen{false}, headerSent{false};
    explicit Scripted(std::string mode) {
        running=std::async(std::launch::async,[this,mode] {
            try {
                auto canceled=[&]{return stop.load();}; auto socket=listener.accept(deadline(),canceled);
                relay::Tls tls(socket,identity); tls.handshake(deadline(),canceled);
                uint8_t nonce[32]={1},challengeWire[RELAY_REQUEST_CHALLENGE_SIZE]; check(relay_request_challenge(nonce,challengeWire),"script challenge");
                tls.write(challengeWire,sizeof(challengeWire),deadline(),canceled);
                uint8_t header[RELAY_REQUEST_HEADER_SIZE]; tls.read(header,sizeof(header),deadline(),canceled);
                relay_request_header_t request{}; check(relay_request_decode(header,sizeof(header),&request),"script request");
                Bytes payload(request.length); tls.read(payload.data(),payload.size(),deadline(),canceled); requestSeen=true;
                if (mode == "stall") { while (!stop) std::this_thread::sleep_for(std::chrono::milliseconds(2)); return; }
                auto digest=hash(payload); relay_frame_header_t frame{};
                memcpy(frame.request_id,request.request_id,16); memcpy(frame.request_hash,digest.data(),32);
                auto frameBytes=[&](relay_frame_type_t type,const Bytes &body) {
                    frame.type=type; frame.length=static_cast<uint16_t>(body.size()); uint8_t bytes[RELAY_FRAME_HEADER_SIZE];
                    check(relay_frame_encode(&frame,bytes),"script frame encoding"); tls.write(bytes,sizeof(bytes),deadline(),canceled); headerSent=true;
                    if (!body.empty()) tls.write(body.data(),body.size(),deadline(),canceled);
                };
                if (mode=="wrong-binding") frame.request_hash[0]^=1;
                if (mode=="discovery-invalid" || mode=="discovery-wrong-binding") {
                    Bytes hints(RELAY_DISCOVERY_SIZE); hints[0]=1; hints[16]=1; hints[24]=mode=="discovery-invalid"?2:1;
                    if (mode=="discovery-wrong-binding") frame.request_hash[0]^=1;
                    frameBytes(RELAY_FRAME_DISCOVERY,hints); return;
                }
                if (mode=="invalid-keepalive") { frameBytes(RELAY_FRAME_KEEPALIVE,{9}); return; }
                if (mode=="cancel-frame") { frameBytes(RELAY_FRAME_CANCEL,{}); return; }
                if (mode=="truncated") {
                    frame.type=RELAY_FRAME_RESPONSE; frame.length=20; uint8_t bytes[RELAY_FRAME_HEADER_SIZE];
                    check(relay_frame_encode(&frame,bytes),"truncated frame"); tls.write(bytes,sizeof(bytes),deadline(),canceled); headerSent=true;
                    tls.write("\0abc",4,deadline(),canceled); return;
                }
                if (mode=="keepalive") { frameBytes(RELAY_FRAME_KEEPALIVE,{2}); frameBytes(RELAY_FRAME_KEEPALIVE,{1}); }
                frameBytes(RELAY_FRAME_RESPONSE,mode=="error-with-body"?Bytes{0x27,0xa0}:Bytes{0,0xa1,1,0xf5});
            } catch (const std::exception &) { if (requestSeen && mode=="keepalive") throw; }
        });
    }
    ~Scripted() { stop=true; if (running.valid()) running.wait(); }
};
void run(const std::string &name) {
    controller=Key::generate(); deviceKey=Key::generate();
    if (name.rfind("memory-",0)==0) {
        auto c=settings(9,2); dnsFail=true; // No socket access; success means Wi-Fi + address, not a running service.
        noApFirst=name=="memory-seed" || name=="memory-unavailable" || name=="memory-write-fail";
        nvsUnavailable=name=="memory-unavailable"; nvsWriteFail=name=="memory-write-fail";
        if (name=="memory-changed") c.networks[0].port=10;
        check(transact(c,{4}).code==0x30,"memory fixture should stop at DNS");
        bool second=noApFirst || name=="memory-reuse";
        check(wifiAttempts.back()==(second?"synthetic-1":"synthetic-0"),"persisted Wi-Fi preference not applied/invalidated");
        if (name=="memory-reuse") check(wifiAttempts.size()==1 && preferenceWrites==0,"reboot retried old profile or rewrote unchanged preference");
        auto joins=wifiConnects, writes=preferenceWrites;
        for (int i=0;i<5;++i) check(transact(c,{4}).code==0x30,"offline service result changed");
        check(wifiConnects==joins && wifiDisconnects==0 && preferenceWrites==writes,"offline service churned Wi-Fi or flash");
        return;
    }
    if (name=="wifi-stable" || name=="wifi-ap-lost" || name=="wifi-no-ap" || name=="wifi-dhcp-late" || name=="wifi-background-join" || name=="wifi-late-failure") {
        Fixture fixture("allow"); auto c=settings(fixture.port,2);
        if (name=="wifi-no-ap") {
            noApFirst=true; auto start=board_millis();
            check(transact(c,{4}).code==0 && board_millis()-start<3000,"missing AP did not fail over promptly");
            check(wifiConnects==2 && wifiDisconnects==0,"missing AP required disconnect or wrong attempt count"); return;
        }
        if (name=="wifi-background-join") {
            wifiStall=true; relay_network_refresh(&c);
            check(wifiConnects==1 && wifiDisconnects==0,"background deadline restarted pending join");
            check(transact(c,{4}).code==0 && wifiConnects==2 && wifiDisconnects==1 && clockOffset<=9000,"foreground did not resume/bound stalled background join"); return;
        }
        if (name=="wifi-late-failure") {
            wifiStall=true; relay_network_refresh(&c);
            check(wifiConnects==1 && wifiDisconnects==0,"background interrupted initial join");
            wifi_event_sta_disconnected_t event{201}; wifiHandler(nullptr,WIFI_EVENT,WIFI_EVENT_STA_DISCONNECTED,&event);
            wifiStall=false;
            check(transact(c,{4}).code==0 && wifiAttempts.back()=="synthetic-1" && wifiConnects==2,"late AP failure retried missing network"); return;
        }
        if (name=="wifi-dhcp-late") {
            addressMode="link-local-only";
            check(transact(c,{4}).code==0x30,"address-less station reached server");
            check(wifiConnects==1 && wifiDisconnects==0,"DHCP delay disconnected associated Wi-Fi");
            addressMode.clear(); ipHandler(nullptr,IP_EVENT,IP_EVENT_STA_GOT_IP,nullptr);
            check(transact(c,{4}).code==0 && wifiConnects==1 && wifiDisconnects==0,"late DHCP did not reuse association"); return;
        }
        check(transact(c,{4}).code==0,"initial stable Wi-Fi connection");
        if (name=="wifi-ap-lost") {
            mockAssociated=false; wifi_event_sta_disconnected_t event{201}; wifiHandler(nullptr,WIFI_EVENT,WIFI_EVENT_STA_DISCONNECTED,&event);
            noApFirst=true;
            check(transact(c,{4}).code==0 && wifiAttempts.back()=="synthetic-1" && wifiConnects==3 && wifiDisconnects==0,
                "genuine AP loss did not reconnect/fail over");
            check(preferenceWrites==2,"new successful AP was not remembered"); return;
        }
        // Repeated DNS, TCP setup and TLS trust failures must stay on this AP.
        for (int i=0;i<3;++i) {
            dnsFail=true; check(transact(c,{4}).code==0x30,"DNS failure"); dnsFail=false;
            noDelayFail=true; check(transact(c,{4}).code==0x30,"TCP setup failure"); noDelayFail=false;
            trusted=false; check(transact(c,{4}).code==0x30,"TLS trust failure"); trusted=true;
            relay_network_refresh(&c); check(transact(c,{4}).code==0,"service recovery");
        }
        check(wifiConnects==1 && wifiDisconnects==0 && preferenceWrites==1,"stable association or preference churned"); return;
    }
    if (name=="background-preempt") {
        Scripted slow("stall"); Fixture foreground("allow");
        auto backgroundSettings=settings(slow.listener.port()); auto foregroundSettings=settings(foreground.port);
        auto refresh=std::async(std::launch::async,[&] { relay_network_refresh(&backgroundSettings); });
        auto until=std::chrono::steady_clock::now()+std::chrono::seconds(3);
        while (!slow.requestSeen && std::chrono::steady_clock::now()<until) sleepMs(2);
        check(slow.requestSeen,"background prefetch did not start");
        auto started=std::chrono::steady_clock::now();
        auto answer=transact(foregroundSettings,{4}); refresh.get();
        check(answer.code==0 && std::chrono::steady_clock::now()-started<std::chrono::seconds(2),"foreground blocked on background discovery");
        return;
    }
    if (name.rfind("frame-",0)==0) {
        auto mode=name.substr(6); Scripted server(mode);
        auto c=settings(server.listener.port(),2);
        auto result=transact(c,{4},mode=="small-buffer"?1:RELAY_CTAP_MAX);
        server.stop=true; server.running.get();
        bool success=mode=="keepalive";
        check(result.code==(success?0:0x30) && connects==1u,"script response/retry boundary");
        if (success) check(result.bytes==Bytes({0xa1,1,0xf5}) && maxKeepalive==2,"keepalive/response result");
        check(server.requestSeen && server.headerSent,"scripted rejection did not reach its intended response boundary");
        if (name.rfind("frame-discovery-",0)==0) check(discoveryFrames==0,"unvalidated metadata reached cache");
        return;
    }
    bool pending=name=="cancel" || name=="detach" || name=="suspend" || name=="timeout";
    addressMode=name;
    Fixture fixture(pending?"pending":name=="deny"?"deny":"allow");
    auto c=settings(fixture.port,name=="ten-profiles"?10:(name=="failover" || name=="wifi-timeout" || name=="partial-send")?2:1,
                    name=="ipv6-literal"?"::1":"localhost");
    if (name=="wrong-device-key") wrongDevice=true;
    if (name=="revoked") trusted=false;
    if (name=="dns-failure") dnsFail=true;
    if (name=="dns-late") dnsDelay=true;
    if (name=="dns-queued") tcpipDelay=true;
    if (name=="tcpip-failure") tcpipFail=true;
    if (name=="wifi-init-failure") wifiInitFail=true;
    if (name=="nodelay-failure") noDelayFail=true;
    if (name=="wifi-failure") wifiFail=true;
    if (name=="wifi-timeout") wifiStall=true;
    if (name=="ten-profiles") { wifiStall=true; stalledProfiles=9; }
    if (name=="partial-send") partialSend=true;
    if (name=="read-failure") receiveFail=true;
    if (name=="fragmented") fragments=true;
    if (name=="wraparound") clockOffset=0xfffffff0u;
    if (name=="failover") { auto unused=relay::Socket::listen("127.0.0.1",0); c.networks[0].port=unused.port(); }
    if (pending) trigger=name;
    auto request=pending || name=="deny" || name=="register"?registration():Bytes{4};
    if (name=="selection-probe") {
        auto registrationRequest=registration();
        auto params=ctap::decode(Bytes(registrationRequest.begin()+1, registrationRequest.end()));
        params.items.push_back(V::integer(8)); params.items.push_back(V::blob({}));
        request=ctap::encode(params); request.insert(request.begin(),1);
    }
    if (name=="pin-retries") request={6,0xa2,1,1,2,1};
    auto result=transact(c,request);
    if (name=="get-info") check(noDelaySockets==1 && discoveryFrames==2,"authenticated discovery metadata missing");
    if (name=="nodelay-failure") check(connects==0,"network continued after latency setup failure");
    uint8_t diagnostic[4]{}; relay_network_diagnostics(diagnostic);
    if (name=="get-info") check(diagnostic[0]==9 && diagnostic[2]==7 && diagnostic[3]==1,"network diagnostics missed completed IPv4 session");
    if (name=="wifi-init-failure") check(diagnostic[0]==1 && diagnostic[2]==0,"network diagnostic initialization stage");
    if (name=="dns-failure") check(diagnostic[0]==4,"network diagnostic DNS/TCP stage");
    bool good=name=="get-info" || name=="register" || name=="fragmented" || name=="wifi-timeout" || name=="wraparound" ||
        name=="ten-profiles" || name=="pin-retries" || name.rfind("ipv6",0)==0;
    check(result.code==(good?0:name=="selection-probe"?0x35:pending && name!="timeout"?0x2d:name=="deny"?0x27:0x30),"unexpected ESP exchange result");
    if (good) {
        auto decoded=ctap::decode(result.bytes); check(decoded.type==V::Map,"ESP response is not the original CBOR map");
        if (name=="register") check(decoded.at(2).bytes.size()>=87,"registration response lost authenticator data");
        else if (name=="pin-retries") check(decoded.at(3).number==8,"PIN retry metadata response");
        else check(decoded.at(1).type==V::Array,"GetInfo response lost versions");
    }
    if (name=="register") check(fixture.approvals==1 && fixture.vault->accounts().size()==1,"registration consent/commit");
    else check(fixture.vault->accounts().empty(),"failed/metadata operation mutated vault");
    if (name=="selection-probe" || name=="pin-retries" || name=="get-info")
        check(fixture.approvals==0 && maxKeepalive==1,"automatic/metadata request advertised remote user-presence wait");
    if (pending) check(maxKeepalive==2,"pending approval never advertised remote wait");
    if (name=="partial-send") check(connects==1 && applicationConnections==1 && fixture.approvals==0,"partial request retried or approved");
    if (name=="failover") {
        check(connects==1 && wifiConnects==1 && wifiDisconnects==0,"unreachable service switched Wi-Fi");
        dnsFail=true; // A later endpoint failure must reuse the same association as well.
        check(transact(c,{4}).code==0x30 && wifiConnects==1 && wifiDisconnects==0,"offline service retry reconnected Wi-Fi");
    }
    if (name=="wifi-timeout") check(wifiConnects==2 && connects==1 && clockOffset<=9000,"Wi-Fi timeout did not promptly try second profile");
    if (name=="ten-profiles") check(wifiConnects==10 && connects==1,"ten-profile rotation failed");
    if (name=="link-local-only") check(!connects,"link-local address incorrectly established reachability");
    if (name=="revoked") check(!applicationConnections,"request sent to a server not issued by a paired controller");
    if (name=="dns-late") {
        check(!delayed.empty() && !connects,"delayed DNS did not time out");
        dnsDelay=false; auto jobs=std::move(delayed); delayed.clear();
        for (auto &job:jobs) {
            check(dnsAllocations.count(job.arg)==1,"DNS job freed before late callback");
            ip_addr_t address{}; ipaddr_aton("127.0.0.1",&address); job.callback(job.name.c_str(),&address,job.arg);
        }
        check(dnsAllocations.empty(),"late DNS callback did not release allocation");
    }
    if (name=="dns-queued") {
        check(!queuedDns.empty() && !connects,"queued DNS did not time out"); tcpipDelay=false;
        for (auto &job:queuedDns) { check(dnsAllocations.count(job.second)==1,"DNS job freed before task callback"); job.first(job.second); }
        queuedDns.clear(); check(dnsAllocations.empty(),"queued DNS completion did not release allocation");
    }
    if (name=="wifi-init-failure") {
        wifiInitFail=false; check(transact(c,{4}).code==0x30 && wifiInitializations==1,"partial driver initialization retried without reboot");
    }
    if (pending || name=="partial-send" || name=="dns-late" || name=="dns-queued" || name=="read-failure") {
        mounted=true; suspended=false; test_atomic_store8(&cancel_button,0); partialSend=false; receiveFail=false; trigger.clear();
        auto recovered=transact(c,{4}); check(recovered.code==0,"subsequent independent request did not recover");
    }
}
DWORD child(const std::string &name,const std::filesystem::path &snapshot={}) {
    wchar_t executable[32768]{}; check(GetModuleFileNameW(nullptr,executable,32768)!=0,"test executable path");
    auto command=L"\""+std::wstring(executable)+L"\" --case "+widen(name);
    if (!snapshot.empty()) command+=L" --nvs \""+snapshot.wstring()+L"\"";
    STARTUPINFOW start{}; start.cb=sizeof(start); PROCESS_INFORMATION process{};
    check(CreateProcessW(executable,command.data(),nullptr,nullptr,FALSE,CREATE_NO_WINDOW,nullptr,nullptr,&start,&process),"test child launch");
    CloseHandle(process.hThread); auto waited=WaitForSingleObject(process.hProcess,15000); DWORD code=STILL_ACTIVE;
    bool exited=GetExitCodeProcess(process.hProcess,&code)!=FALSE; CloseHandle(process.hProcess);
    if (waited!=WAIT_OBJECT_0 || !exited || code==STILL_ACTIVE) throw std::runtime_error("test child did not exit: "+name);
    return code;
}
}

extern "C" {
void *xSemaphoreCreateMutex(void) { static std::timed_mutex mutex; return &mutex; }
int xSemaphoreTake(void *mutex, unsigned ticks) { return static_cast<std::timed_mutex *>(mutex)->try_lock_for(std::chrono::milliseconds(ticks * 10)) ? 1 : 0; }
int xSemaphoreGive(void *mutex) { static_cast<std::timed_mutex *>(mutex)->unlock(); return 1; }
int xTaskCreate(void (*)(void *), const char *, unsigned, void *, unsigned, void *) { return 1; }
void relay_firmware_discovery(const uint8_t metadata[25]) {
    check(metadata[24] <= 1, "invalid authenticated discovery hint"); ++discoveryFrames;
}
bool cancel_button=false;
const char pico_serial_str[17]="0123456789ABCDEF";
const char *IP_EVENT="ip", *WIFI_EVENT="wifi";
uint8_t test_atomic_load8(const void *p) { return static_cast<uint8_t>(_InterlockedCompareExchange8(reinterpret_cast<volatile char *>(const_cast<void *>(p)),0,0)); }
void test_atomic_store8(void *p,uint8_t value) { _InterlockedExchange8(reinterpret_cast<volatile char *>(p),static_cast<char>(value)); }
int test_atomic_decrement(int *p) { return static_cast<int>(_InterlockedDecrement(reinterpret_cast<volatile long *>(p))); }
uint32_t board_millis(void) {
    maxKeepalive=std::max<unsigned>(maxKeepalive,relay_network_keepalive());
    if (waiting && relay_network_keepalive()==2 && !trigger.empty()) {
        auto reason=std::move(trigger); trigger.clear();
        if (reason=="cancel") test_atomic_store8(&cancel_button,1);
        else if (reason=="detach") mounted=false;
        else if (reason=="suspend") suspended=true;
        else if (reason=="timeout") clockOffset+=RELAY_OPERATION_TIMEOUT_MS;
    }
    return clockOffset+static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-started).count());
}
void vTaskDelay(unsigned ticks) { check(ticks > 0, "zero-tick busy loop"); unsigned ms = ticks * 10; if (stalledWifi() || addressMode=="link-local-only" || dnsDelay || tcpipDelay) clockOffset+=1000; else sleepMs(ms); }
bool tud_mounted(void) { return mounted; }
bool tud_suspended(void) { return suspended; }
void picok_random_fill(void *buffer,size_t length) { auto b=randomBytes(length); memcpy(buffer,b.data(),length); }
bool remote_presence_device_sign(const uint8_t digest[32],uint8_t signature[64]) {
    auto other=Key::generate(); const Key &signer=wrongDevice?*other:*deviceKey;
    auto sig=signer.signDigest(Bytes(digest,digest+32)); memcpy(signature,sig.data(),64); return true;
}
bool remote_presence_verify_any(const uint8_t digest[32],const uint8_t signature[64]) {
    return trusted && crypto::verifyP256(controller->pub(),Bytes(digest,digest+32),Bytes(signature,signature+64));
}
int test_settimeofday(const struct test_timeval *time,const void *) {
    (void)time; check(false,"relay network must not set the device clock"); return -1;
}
esp_err_t esp_netif_init(void) { return ESP_OK; }
esp_err_t esp_event_loop_create_default(void) { return ESP_OK; }
esp_netif_t *esp_netif_create_default_wifi_sta(void) { return &station; }
esp_err_t esp_event_handler_register(esp_event_base_t base,int32_t,esp_event_handler_t handler,void *) {
    if (base==IP_EVENT) ipHandler=handler; else if (base==WIFI_EVENT) wifiHandler=handler; else check(false,"event base"); return ESP_OK;
}
esp_err_t esp_wifi_init(const wifi_init_config_t *c) { check(c && c->nvs_enable==0,"Wi-Fi NVS writes enabled"); ++wifiInitializations; return wifiInitFail?-1:ESP_OK; }
esp_err_t esp_wifi_set_storage(int value) { check(value==WIFI_STORAGE_RAM,"persistent Wi-Fi credentials"); return ESP_OK; }
esp_err_t esp_wifi_set_mode(int value) { check(value==WIFI_MODE_STA,"Wi-Fi mode"); return ESP_OK; }
esp_err_t esp_wifi_start(void) { return ESP_OK; }
esp_err_t esp_wifi_set_ps(int mode) {
    check(mode==WIFI_PS_MIN_MODEM,"Wi-Fi modem sleep disabled"); return ESP_OK;
}
esp_err_t esp_pm_configure(const esp_pm_config_t *pm) { check(pm && pm->min_freq_mhz==80 && pm->max_freq_mhz==160 && !pm->light_sleep_enable,"unsafe USB power policy"); return ESP_OK; }
esp_err_t esp_wifi_disconnect(void) {
    check(!mockAssociated,"firmware actively disconnected an associated AP"); ++wifiDisconnects;
    if (wifiHandler) wifiHandler(nullptr,WIFI_EVENT,WIFI_EVENT_STA_DISCONNECTED,nullptr); return ESP_OK;
}
esp_err_t esp_wifi_sta_get_ap_info(wifi_ap_record_t *) { return mockAssociated?ESP_OK:ESP_ERR_WIFI_NOT_CONNECT; }
esp_err_t esp_wifi_set_config(int,const wifi_config_t *c) { ssid.assign(reinterpret_cast<const char *>(c->sta.ssid)); return ESP_OK; }
esp_err_t esp_wifi_connect(void) {
    check(!mockAssociated,"firmware restarted a connected station");
    ++wifiConnects; wifiAttempts.push_back(ssid); if (wifiFail) return -1;
    if (noApFirst && ssid=="synthetic-0") {
        wifi_event_sta_disconnected_t event{201}; wifiHandler(nullptr,WIFI_EVENT,WIFI_EVENT_STA_DISCONNECTED,&event); return ESP_OK;
    }
    if (stalledWifi()) return ESP_OK;
    mockAssociated=true;
    wifiHandler(nullptr,WIFI_EVENT,WIFI_EVENT_STA_CONNECTED,nullptr);
    if (addressMode=="link-local-only") return ESP_OK;
    if (addressMode.rfind("ipv6",0)==0) {
        ip_event_got_ip6_t event{}; event.ip6_info.ip.addr[0]=1; ipHandler(nullptr,IP_EVENT,IP_EVENT_GOT_IP6,&event);
    } else ipHandler(nullptr,IP_EVENT,IP_EVENT_STA_GOT_IP,nullptr);
    return ESP_OK;
}
esp_err_t nvs_open(const char *name,int mode,nvs_handle_t *handle) {
    check(!strcmp(name,"fido_net") && mode==NVS_READWRITE,"unexpected preference namespace"); *handle=1; return nvsUnavailable?ESP_FAIL:ESP_OK;
}
esp_err_t nvs_get_blob(nvs_handle_t handle,const char *key,void *out,size_t *length) {
    check(handle==1 && !strcmp(key,"last_wifi_v1"),"unexpected preference key");
    if (!preferencePath.empty()) { std::ifstream f(preferencePath,std::ios::binary); preferenceBlob=Bytes(std::istreambuf_iterator<char>(f),{}); }
    if (preferenceBlob.empty()) return ESP_ERR_NVS_NOT_FOUND;
    if (*length<preferenceBlob.size()) return ESP_ERR_NVS_INVALID_LENGTH;
    memcpy(out,preferenceBlob.data(),preferenceBlob.size()); *length=preferenceBlob.size(); return ESP_OK;
}
esp_err_t nvs_set_blob(nvs_handle_t handle,const char *key,const void *data,size_t length) {
    check(handle==1 && !strcmp(key,"last_wifi_v1") && length==44,"unexpected preference write"); ++preferenceWrites;
    if (nvsWriteFail) return ESP_FAIL;
    preferenceBlob=Bytes((const uint8_t *)data,(const uint8_t *)data+length); return ESP_OK;
}
esp_err_t nvs_commit(nvs_handle_t handle) {
    check(handle==1,"unexpected preference commit");
    if (!preferencePath.empty()) { std::ofstream f(preferencePath,std::ios::binary|std::ios::trunc); f.write((const char *)preferenceBlob.data(),preferenceBlob.size()); check(f.good(),"fixture snapshot write"); }
    return ESP_OK;
}
esp_err_t esp_netif_create_ip6_linklocal(esp_netif_t *) {
    ip_event_got_ip6_t event{}; ipHandler(nullptr,IP_EVENT,IP_EVENT_GOT_IP6,&event); return ESP_OK;
}
esp_ip6_addr_type_t esp_netif_ip6_get_addr_type(const test_ip6_t *ip) { return ip->addr[0]?ESP_IP6_ADDR_IS_GLOBAL:ESP_IP6_ADDR_IS_LINK_LOCAL; }
int ipaddr_aton(const char *host,ip_addr_t *address) {
    if (InetPtonA(AF_INET,host,&address->v4.addr)==1) { address->family=4; return 1; }
    if (InetPtonA(AF_INET6,host,address->v6.addr)==1) { address->family=6; return 1; } return 0;
}
err_t dns_gethostbyname_addrtype(const char *host,ip_addr_t *address,dns_found_callback callback,void *arg,int type) {
    if (dnsFail) return -1;
    if (dnsDelay) { delayed.push_back({host,callback,arg}); return ERR_INPROGRESS; }
    check(std::string(host)=="localhost" || std::string(host)=="mismatch.invalid","non-fixture DNS lookup");
    bool ipv6=addressMode.rfind("ipv6",0)==0;
    check(type==(ipv6?LWIP_DNS_ADDRTYPE_IPV6_IPV4:LWIP_DNS_ADDRTYPE_IPV4_IPV6),"DNS family preference");
    ipaddr_aton(ipv6?"::1":"127.0.0.1",address); return ERR_OK;
}
err_t tcpip_callback(void (*function)(void *),void *arg) {
    if (tcpipFail) return -1; if (tcpipDelay) { queuedDns.push_back({function,arg}); return ERR_OK; }
    function(arg); return ERR_OK;
}
void *test_dns_calloc(size_t count,size_t size) { auto p=std::calloc(count,size); if (p) check(dnsAllocations.insert(p).second,"duplicate DNS allocation"); return p; }
void test_dns_free(void *pointer) { check(dnsAllocations.erase(pointer)==1,"invalid DNS free"); std::free(pointer); }
int test_socket(int family,int type,int protocol) {
    auto socket=::socket(family,type,protocol); if (socket==INVALID_SOCKET) return -1;
    for (size_t i=0;i<descriptors.size();++i) if (descriptors[i].socket==INVALID_SOCKET) { descriptors[i]={socket,false,false}; return static_cast<int>(i); }
    closesocket(socket); check(false,"too many client sockets"); return -1;
}
int fcntl(int fd,int,int) { u_long nonblocking=1; return ioctlsocket(native(fd),FIONBIO,&nonblocking)==0?0:-1; }
int test_connect(int fd,const struct sockaddr *address,int length) {
    check((address->sa_family==AF_INET && reinterpret_cast<const sockaddr_in *>(address)->sin_addr.s_addr==htonl(INADDR_LOOPBACK)) ||
          (address->sa_family==AF_INET6 && IN6_IS_ADDR_LOOPBACK(&reinterpret_cast<const sockaddr_in6 *>(address)->sin6_addr)),"non-loopback connection refused by fixture");
    ++connects; auto rc=::connect(native(fd),address,length);
    if (rc==SOCKET_ERROR) { errno=WSAGetLastError()==WSAEWOULDBLOCK?EINPROGRESS:EIO; return -1; } return rc;
}
int test_close(int fd) { auto rc=closesocket(native(fd)); descriptors[fd]={}; return rc; }
int test_send(int fd,const void *data,size_t length,int flags) {
    auto &entry=descriptors[fd]; auto p=static_cast<const uint8_t *>(data);
    const std::string password="test-only-password"; check(std::search(p,p+length,password.begin(),password.end())==p+length,"plaintext Wi-Fi password on raw transport");
    if (!entry.application && length>=5 && p[0]==23) { entry.application=true; ++applicationConnections; }
    if (partialSend && entry.application) {
        if (entry.broken) { errno=EIO; return -1; } entry.broken=true; length=std::min<size_t>(length,5);
    }
    if (fragments) length=std::min<size_t>(length,13);
    return socketResult(::send(native(fd),static_cast<const char *>(data),static_cast<int>(length),flags));
}
int test_recv(int fd,void *data,size_t length,int flags) {
    if (receiveFail && descriptors[fd].application) { errno=EIO; return -1; }
    if (fragments) length=std::min<size_t>(length,7);
    return socketResult(::recv(native(fd),static_cast<char *>(data),static_cast<int>(length),flags));
}
int test_getsockopt(int fd,int level,int option,void *value,int *length) { return socketResult(::getsockopt(native(fd),level,option,static_cast<char *>(value),length)); }
int test_setsockopt(int fd,int level,int option,const void *value,int length) {
    check(level==IPPROTO_TCP && option==TCP_NODELAY && length==sizeof(int) && *static_cast<const int *>(value)==1,"invalid low-latency socket option");
    if (noDelayFail) return -1;
    ++noDelaySockets; return socketResult(::setsockopt(native(fd),level,option,static_cast<const char *>(value),length));
}
int test_select(int count,fd_set *read,fd_set *write,fd_set *error,const struct test_timeval *timeout) {
    struct timeval nativeTimeout{static_cast<long>(timeout->tv_sec),timeout->tv_usec};
    return socketResult(::select(count,read,write,error,&nativeTimeout));
}
void test_fd_set(int fd,fd_set *set) { FD_SET(native(fd),set); }
}
int wmain(int argc,wchar_t **argv) {
    try {
        if ((argc==3 || argc==5) && wcscmp(argv[1],L"--case")==0) {
            if (argc==5) { check(wcscmp(argv[3],L"--nvs")==0,"invalid fixture arguments"); preferencePath=argv[4]; }
            relay_network_init(); run(utf8(argv[2])); return 0;
        }
        const std::vector<std::string> cases={"get-info","selection-probe","pin-retries","register","deny","wrong-device-key","revoked",
            "wifi-failure","wifi-timeout","wifi-init-failure","nodelay-failure","ten-profiles","dns-failure","dns-late","dns-queued","tcpip-failure",
            "ipv6-dns","ipv6-literal","link-local-only","failover","fragmented","wraparound","partial-send","read-failure",
            "cancel","detach","suspend","timeout","frame-wrong-binding","frame-invalid-keepalive","frame-cancel-frame",
            "frame-truncated","frame-error-with-body","frame-small-buffer","frame-keepalive",
            "frame-discovery-invalid","frame-discovery-wrong-binding","background-preempt",
            "wifi-stable","wifi-ap-lost","wifi-no-ap","wifi-dhcp-late","wifi-background-join","wifi-late-failure","memory-unavailable","memory-write-fail"};
        for (const auto &name:cases) if (child(name)!=0) throw std::runtime_error("failed scenario: "+name);
        auto nonce=randomBytes(12); auto snapshot=std::filesystem::temp_directory_path()/("pf2-wifi-preference-"+hex(nonce.data(),nonce.size())+".bin");
        for (const auto &name:{"memory-seed","memory-reuse","memory-changed"}) check(child(name,snapshot)==0,"cold-boot preference regression");
        { std::ofstream f(snapshot,std::ios::binary|std::ios::trunc); f<<"corrupt"; }
        check(child("memory-corrupt",snapshot)==0,"corrupt preference blocked connection"); std::filesystem::remove(snapshot);
        printf("Actual ESP network worker: %zu isolated real-TLS loopback scenarios passed.\n",cases.size()); return 0;
    } catch (const std::exception &e) { fprintf(stderr,"ESP network test: %s\n",e.what()); return 1; }
}
