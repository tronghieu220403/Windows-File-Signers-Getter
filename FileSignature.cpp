#include "FileSignature.h"

FileSignature::FileSignature(const std::wstring& file_path)
    : file_path_(file_path), file_handle_(INVALID_HANDLE_VALUE), embedded_trusted_(0), catalog_trusted_(0)
{
    // Constructor
}

FileSignature::~FileSignature()
{
    Reset();
}

void FileSignature::Reset()
{
    CloseFile();
    ResetState();
}

void FileSignature::ResetState()
{
    embedded_signers_.clear();
    catalog_signers_.clear();
    embedded_trusted_ = 0;
    catalog_trusted_ = 0;
}

void FileSignature::OpenFile()
{
    if (file_handle_ == INVALID_HANDLE_VALUE)
    {
        file_handle_ = CreateFile(file_path_.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    }
}

void FileSignature::CloseFile()
{
    if (file_handle_ != INVALID_HANDLE_VALUE)
    {
        CloseHandle(file_handle_);
        file_handle_ = INVALID_HANDLE_VALUE;
    }
}

bool FileSignature::IsSigned()
{
    if (embedded_trusted_ == 0)
    {
        GetNameOfEmbeddedSigners();
    }
    if (catalog_trusted_ == 0)
    {
        GetNameOfCatalogSigners();
    }
    return (embedded_trusted_ == 2 || catalog_trusted_ == 2);
}

std::vector<std::wstring> FileSignature::GetNameOfEmbeddedSigners()
{
    if (embedded_trusted_ != 0)
    {
        return embedded_signers_;
    }

    OpenFile();
    if (file_handle_ == INVALID_HANDLE_VALUE)
    {
        embedded_trusted_ = 1;
        return embedded_signers_;
    }

    // Reset file pointer to the beginning
    SetFilePointer(file_handle_, 0, nullptr, FILE_BEGIN);

    // Your existing code for getting embedded signers
    DWORD result = ERROR_SUCCESS;
    bool wintrust_called = false;
    GUID generic_action_id = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA wintrust_data = {};
    WINTRUST_FILE_INFO file_info = {};
    WINTRUST_SIGNATURE_SETTINGS signature_settings = {};

    wintrust_data.cbStruct = sizeof(WINTRUST_DATA);
    wintrust_data.dwStateAction = WTD_STATEACTION_VERIFY;
    wintrust_data.dwUIChoice = WTD_UI_NONE;
    wintrust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
    wintrust_data.dwUnionChoice = WTD_CHOICE_FILE;

    file_info.cbStruct = sizeof(WINTRUST_FILE_INFO);
    file_info.pcwszFilePath = file_path_.c_str();
    file_info.hFile = file_handle_;
    wintrust_data.pFile = &file_info;

    signature_settings.cbStruct = sizeof(WINTRUST_SIGNATURE_SETTINGS);
    signature_settings.dwFlags = WSS_GET_SECONDARY_SIG_COUNT | WSS_VERIFY_SPECIFIC;
    signature_settings.dwIndex = 0;
    wintrust_data.pSignatureSettings = &signature_settings;

    result = WinVerifyTrust(nullptr, &generic_action_id, &wintrust_data);
    wintrust_called = true;
    if (result == ERROR_SUCCESS)
    {
        for (DWORD i = 0; i <= wintrust_data.pSignatureSettings->cSecondarySigs; ++i) {
            wintrust_data.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(nullptr, &generic_action_id, &wintrust_data);

            wintrust_data.hWVTStateData = nullptr;
            wintrust_data.dwStateAction = WTD_STATEACTION_VERIFY;
            wintrust_data.pSignatureSettings->dwIndex = i;
            result = WinVerifyTrust(nullptr, &generic_action_id, &wintrust_data);

            if (result == ERROR_SUCCESS) {
                CRYPT_PROVIDER_DATA* p_crypt_prov_data = WTHelperProvDataFromStateData(wintrust_data.hWVTStateData);
                CRYPT_PROVIDER_SGNR* p_signer = WTHelperGetProvSignerFromChain(p_crypt_prov_data, 0, FALSE, 0);
                CRYPT_PROVIDER_CERT* p_cert = WTHelperGetProvCertFromChain(p_signer, 0);

                if (p_cert) {
                    int length = CertGetNameStringW(p_cert->pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, nullptr, 0);
                    if (length > 0) {
                        std::vector<wchar_t> buffer(length);
                        if (CertGetNameStringW(p_cert->pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, buffer.data(), length)) {
                            embedded_signers_.emplace_back(buffer.data());
                        }
                    }
                }
            }
            else {
                break;
            }
        }
        embedded_trusted_ = 2;
    }
    else
    {
        embedded_trusted_ = 1;
    }

    if (wintrust_called) {
        wintrust_data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(nullptr, &generic_action_id, &wintrust_data);
    }

    return embedded_signers_;
}

std::vector<std::wstring> FileSignature::GetNameOfCatalogSigners()
{
    if (catalog_trusted_ != 0)
    {
        return catalog_signers_;
    }

    OpenFile();
    if (file_handle_ == INVALID_HANDLE_VALUE)
    {
        catalog_trusted_ = 1;
        return catalog_signers_;
    }

    // Reset file pointer to the beginning
    SetFilePointer(file_handle_, 0, nullptr, FILE_BEGIN);

    HCATADMIN h_cat_admin = nullptr;
    HCATINFO h_cat_info = nullptr;
    DWORD result = NULL;

    // Create catalog admin context
    if (!CryptCATAdminAcquireContext2(&h_cat_admin, nullptr, NULL, nullptr, 0)) {
        catalog_trusted_ = 1;
        return catalog_signers_;
    }

    // Calculate the file hash
    BYTE hash[1024];
    DWORD hash_size = sizeof(hash);
    if (!CryptCATAdminCalcHashFromFileHandle2(h_cat_admin, file_handle_, &hash_size, hash, 0)) {
        CryptCATAdminReleaseContext(h_cat_admin, 0);
        catalog_trusted_ = 1;
        return catalog_signers_;
    }

    // Find the catalog file containing the hash
    h_cat_info = CryptCATAdminEnumCatalogFromHash(h_cat_admin, hash, hash_size, 0, nullptr);
    if (!h_cat_info) {
        CryptCATAdminReleaseContext(h_cat_admin, 0);
        catalog_trusted_ = 1;
        return catalog_signers_;
    }

    // Verify the catalog file signature
    CATALOG_INFO catalog_info = { 0 };
    catalog_info.cbStruct = sizeof(catalog_info);
    if (CryptCATCatalogInfoFromContext(h_cat_info, &catalog_info, 0))
    {
        WINTRUST_DATA wintrust_data = { 0 };
        WINTRUST_CATALOG_INFO wintrust_catalog_info = { 0 };

        wintrust_data.cbStruct = sizeof(wintrust_data);
        wintrust_data.dwStateAction = WTD_STATEACTION_VERIFY;
        wintrust_data.dwUIChoice = WTD_UI_NONE;
        wintrust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
        wintrust_data.dwUnionChoice = WTD_CHOICE_CATALOG;
        wintrust_data.pCatalog = &wintrust_catalog_info;

        wintrust_catalog_info.cbStruct = sizeof(wintrust_catalog_info);
        wintrust_catalog_info.pcwszCatalogFilePath = catalog_info.wszCatalogFile;
        wintrust_catalog_info.pcwszMemberFilePath = file_path_.c_str();
        wintrust_catalog_info.pcwszMemberTag = std::filesystem::path(file_path_).filename().c_str();
        wintrust_catalog_info.pbCalculatedFileHash = hash;
        wintrust_catalog_info.cbCalculatedFileHash = hash_size;

        WINTRUST_SIGNATURE_SETTINGS signature_settings = {};
        signature_settings.cbStruct = sizeof(WINTRUST_SIGNATURE_SETTINGS);
        signature_settings.dwFlags = WSS_GET_SECONDARY_SIG_COUNT | WSS_VERIFY_SPECIFIC;
        signature_settings.dwIndex = 0;
        wintrust_data.pSignatureSettings = &signature_settings;

        GUID generic_action_id = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        result = WinVerifyTrust(nullptr, &generic_action_id, &wintrust_data);
        auto wintrust_called = true;
        if (result == ERROR_SUCCESS)
        {
            for (DWORD i = 0; i <= wintrust_data.pSignatureSettings->cSecondarySigs; ++i) {
                wintrust_data.dwStateAction = WTD_STATEACTION_CLOSE;
                WinVerifyTrust(nullptr, &generic_action_id, &wintrust_data);

                wintrust_data.hWVTStateData = nullptr;
                wintrust_data.dwStateAction = WTD_STATEACTION_VERIFY;
                wintrust_data.pSignatureSettings->dwIndex = i;
                result = WinVerifyTrust(nullptr, &generic_action_id, &wintrust_data);

                if (result == ERROR_SUCCESS) {
                    CRYPT_PROVIDER_DATA* p_crypt_prov_data = WTHelperProvDataFromStateData(wintrust_data.hWVTStateData);
                    CRYPT_PROVIDER_SGNR* p_signer = WTHelperGetProvSignerFromChain(p_crypt_prov_data, 0, FALSE, 0);
                    CRYPT_PROVIDER_CERT* p_cert = WTHelperGetProvCertFromChain(p_signer, 0);

                    if (p_cert) {
                        int length = CertGetNameStringW(p_cert->pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, nullptr, 0);
                        if (length > 0) {
                            std::vector<wchar_t> buffer(length);
                            if (CertGetNameStringW(p_cert->pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, buffer.data(), length)) {
                                catalog_signers_.emplace_back(buffer.data());
                            }
                        }
                    }
                }
                else {
                    break;
                }
            }
            catalog_trusted_ = 2;
        }
        else
        {
            catalog_trusted_ = 1;
        }

        if (wintrust_called) {
            wintrust_data.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(nullptr, &generic_action_id, &wintrust_data);
        }
    }

    // Release resources
    if (h_cat_info) CryptCATAdminReleaseCatalogContext(h_cat_admin, h_cat_info, 0);
    if (h_cat_admin) CryptCATAdminReleaseContext(h_cat_admin, 0);

    return catalog_signers_;
}