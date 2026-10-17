#pragma once
#include "core.h"
namespace relay {
struct CloudProfileFields {
    std::string nameSpace, root, coordinator;
    std::filesystem::path ca, certificate, privateKey;
};
struct WebDavProfile : CloudProfileFields {
    std::string url, user; std::wstring password;
    std::filesystem::path providerCa;
    ~WebDavProfile();
};
struct OAuthProfile : CloudProfileFields {
    std::string provider, clientId, scopeOrRegion; std::wstring clientSecret;
    ~OAuthProfile();
};
struct ProfileMaintenance {
    std::string action, clientId;
    std::wstring secret, clientSecret;
    CloudProfileFields coordinator;
    std::filesystem::path providerCa;
    ~ProfileMaintenance();
};
Bytes webDavProfileSetup(const WebDavProfile &profile);
Bytes oauthProfileSetup(const OAuthProfile &profile);
Bytes profileMaintenancePatch(const ProfileMaintenance &patch);
}
