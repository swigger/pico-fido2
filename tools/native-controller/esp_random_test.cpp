#include "platform.h"
#include "pico_random.h"
#include "esp-rng-stubs/bootloader_random.h"
#include "esp-rng-stubs/esp_random.h"
#include "esp-rng-stubs/freertos/semphr.h"
extern "C" {
#include "random.h"
void *hwrng_task(void);
}
#include <array>
#include <algorithm>
#include <mutex>
#include <thread>
#include <set>
#include <vector>
#include <cstdio>
#include <cstdlib>

static bool sar;
static unsigned enables, disables, entropyCalls, seedBytes;
static std::mutex rngMutex;
static void check(bool ok, const char *message) { if (!ok) { fprintf(stderr, "%s\n", message); abort(); } }
extern "C" {
void bootloader_random_enable(void) { check(!sar, "SAR already on"); sar = true; ++enables; }
void bootloader_random_disable(void) { check(sar, "SAR already off"); sar = false; ++disables; }
void esp_fill_random(void *buffer, size_t length) {
    check(sar, "raw RNG used without active entropy source"); ++entropyCalls; seedBytes += static_cast<unsigned>(length);
    platform::randomFill(buffer, length);
}
SemaphoreHandle_t xSemaphoreCreateMutex(void) { return &rngMutex; }
int xSemaphoreTake(SemaphoreHandle_t h, unsigned) { static_cast<std::mutex *>(h)->lock(); return 1; }
int xSemaphoreGive(SemaphoreHandle_t h) { static_cast<std::mutex *>(h)->unlock(); return 1; }
}
int main() {
    random_init();
    check(!sar && enables == 1 && disables == 1 && seedBytes >= 32, "boot seed/source shutdown failed");
    auto originalCalls = entropyCalls;
    picok_random_init(); // Does not touch SAR a second time.
    check(hwrng_task() == nullptr, "ESP idle RNG work remains");
    std::array<unsigned char, 16> shortA{}, shortB{};
    check(random_gen(nullptr, shortA.data(), shortA.size()) == 0 && random_gen(nullptr, shortB.data(), shortB.size()) == 0 && shortA != shortB,
        "partial legacy requests repeated RNG bytes");
    auto small = random_bytes_get(16); std::copy_n(small, 16, shortA.begin()); random_bytes_free(small);
    check(std::all_of(small, small + 16, [](auto x) { return x == 0; }), "legacy RNG buffer not wiped");
    small = random_bytes_get(16); check(!std::equal(shortA.begin(), shortA.end(), small), "legacy buffered RNG output repeated"); random_bytes_free(small);
    check(random_bytes_get(1025) == nullptr, "legacy RNG capacity ignored");
    std::mutex outputMutex;
    std::set<std::array<unsigned char, 32>> samples;
    std::vector<std::thread> workers;
    for (int i = 0; i < 4; ++i) workers.emplace_back([&] {
        for (int n = 0; n < 1500; ++n) {
            std::array<unsigned char, 32> sample{}; random_gen(nullptr, sample.data(), sample.size());
            check(sample != std::array<unsigned char, 32>{}, "zero RNG fallback");
            std::lock_guard<std::mutex> lock(outputMutex); check(samples.insert(sample).second, "duplicate concurrent RNG output");
        }
    });
    for (auto &worker : workers) worker.join();
    std::array<unsigned char, 8192> large{}; picok_random_fill(large.data(), large.size());
    picok_random_fill(nullptr, 0);
    check(enables == 1 && disables == 1 && !sar && entropyCalls == originalCalls, "sleeping RF entropy or SAR used after startup");
    puts("PASS: real CTR-DRBG boot seed, SAR release, 6000 concurrent requests beyond default reseed interval, large output");
}
