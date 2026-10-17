#include "relay_control.h"
#include "device_restart.h"
#include <cstring>
#include <cstdio>
static void check(bool ok) { if (!ok) throw std::runtime_error("restart protocol regression"); }
static std::unique_ptr<Key> key;
static bool authorized = true;
static bool randomNonce(uint8_t n[32]) { auto b = randomBytes(32); memcpy(n, b.data(), 32); return true; }
static bool verify(const uint8_t id[16], const uint8_t *m, size_t n, const uint8_t sig[64]) {
    return authorized && !memcmp(id, key->id().data(), 16) && crypto::verifyP256(key->pub(), hash(Bytes(m,m+n)), Bytes(sig,sig+64));
}
int main() {
    try {
        key = Key::generate(); const char serial[] = "0123456789abcdef";
        device_restart_t s{}; uint32_t now = UINT32_MAX - 2000;
        auto init = [&] { device_restart_init(&s, (const uint8_t *)serial, randomNonce, verify); };
        std::vector<std::pair<uint8_t,Bytes>> captured;
        RelayControl host(serial, [&](uint8_t report) {
            Report r{};
            if (report == 16) { memcpy(r.data(),"PRL1",4); r[10]=1; r[11]=1; memcpy(r.data()+50,"MGT1",4); r[54]=1; }
            else device_restart_get(&s,r.data());
            return r;
        }, [&](uint8_t report, const Bytes &b) { captured.emplace_back(report,b); device_restart_set(&s, report,b.data(),now,false); });
        host.wait = [&] { ++now; };
        init(); host.reboot(*key); check(s.phase == DEVICE_RESTART_ACCEPTED);
        check(!device_restart_poll(&s, now+499,false)); check(device_restart_poll(&s,now+500,false));
        check(!device_restart_poll(&s,now+1000,false));
        auto saved = captured;
        // Reboot/new challenge and replays cannot reuse a captured signature.
        init(); for (const auto &p:saved) device_restart_set(&s,p.first,p.second.data(),now,false);
        check(s.phase == DEVICE_RESTART_FAILED && s.result == DEVICE_RESTART_AUTH);
        for (int mutation : {0,1,2,3,4,5}) {
            init(); device_restart_set(&s,22,saved[0].second.data(),now,false);
            // Sign the actual fresh challenge, then independently tamper with its scope or transport.
            uint8_t message[128]; auto id=key->id(); auto n=device_restart_message(&s,id.data(),message);
            auto signature=key->sign(Bytes(message,message+n));
            if (mutation==0) s.serial[0]^=1;
            if (mutation==1) s.nonce[0]^=1;
            if (mutation==2) signature[0]^=1;
            if (mutation==3) now+=10000;
            if (mutation==4) authorized=false;
            for (uint8_t half=0;half<2;++half) {
                Bytes b(63); b[0]=half; memcpy(b.data()+1,s.transaction,16); memcpy(b.data()+17,signature.data()+half*32,32);
                if (mutation==5 && half==0) b[0]=1;
                device_restart_set(&s,23,b.data(),now,false);
            }
            auto finish=saved.back().second; device_restart_set(&s,22,finish.data(),now,false);
            check(s.phase != DEVICE_RESTART_ACCEPTED); authorized=true;
        }
        puts("PASS: signed restart, delayed single execution, fresh nonce, replay/scope/expiry/revocation/fragment rejection"); return 0;
    } catch (const std::exception &e) { fprintf(stderr,"FAIL: %s\n",e.what()); return 1; }
}
