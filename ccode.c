#include <windows.h>
#include <lm.h>
#include <stdio.h>
#include <string.h>
#include <wincrypt.h>

#pragma comment(lib, "Netapi32.lib")
#pragma comment(lib, "Advapi32.lib")

int check_hostname(const char* allowed_hostname) {
    char hostname[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(hostname);
    if (GetComputerNameA(hostname, &size)) {
        // Compare with allowed hostname
        if (strcmp(hostname, allowed_hostname) == 0) {
            return 1; // match
        }
    }
    return 0; // no match
}

int check_volume_serial(DWORD allowed_serial) {
    DWORD serial = 0;
    if (GetVolumeInformationA("C:\\", NULL, 0, &serial, NULL, NULL, NULL, 0)) {
        if (serial == allowed_serial) {
            return 1; // match
        }
    }
    return 0; // no match
}

int check_domain(const wchar_t* allowed_domain) {
    LPWSTR domainName = NULL;
    NETSETUP_JOIN_STATUS status;
    if (NetGetJoinInformation(NULL, &domainName, &status) == NERR_Success) {
        if (status == NetSetupDomainName && wcscmp(domainName, allowed_domain) == 0) {
            NetApiBufferFree(domainName);
            return 1; // match
        }
        NetApiBufferFree(domainName);
    }
    return 0; // no match
}

int hash_hostname_to_key(BYTE* out_hash, DWORD* out_len) {
    char hostname[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(hostname);
    if (!GetComputerNameA(hostname, &size)) return 0;

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    int result = 0;

    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            if (CryptHashData(hHash, (BYTE*)hostname, strlen(hostname), 0)) {
                if (CryptGetHashParam(hHash, HP_HASHVAL, out_hash, out_len, 0)) {
                    result = 1; // success
                }
            }
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }
    return result;
}

int main() {
    // === CONFIGURATION SECTION ===
    const char* allowed_hostname = "AUTHORIZED-HOST";
    DWORD allowed_serial = 0x9EDF5639; // Use 'vol C:' to find this
    const wchar_t* allowed_domain = L"AUTHORIZED-DOMAIN";

    BYTE hash[32];
    DWORD hashLen = sizeof(hash);

    // === GUARDRAIL CHECKS ===
    if (!check_hostname(allowed_hostname)) {
        printf("[!] Hostname mismatch, exiting.\n");
        return 0;
    }

    if (!check_volume_serial(allowed_serial)) {
        printf("[!] Volume serial number mismatch, exiting.\n");
        return 0;
    }

    if (!check_domain(allowed_domain)) {
        printf("[!] Domain mismatch, exiting.\n");
        return 0;
    }

    if (!hash_hostname_to_key(hash, &hashLen)) {
        printf("[!] Failed to generate hostname-derived key, exiting.\n");
        return 0;
    }

    // === PAYLOAD WOULD EXECUTE HERE ===
    printf("[+] Guardrails passed! Proceeding with payload execution.\n");
    // Example: decrypt_payload_with_key(hash);
    return 0;
}
