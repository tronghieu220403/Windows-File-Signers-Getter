#ifndef FILESIGNATURE_H
#define FILESIGNATURE_H

#include <windows.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <iostream>
#include <mscat.h>
#include <filesystem>
#include <vector>
#include <string>
#include <atlstr.h>
#include <chrono>

using namespace std;
namespace fs = std::filesystem;

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

class FileSignature
{
private:
    std::wstring file_path_;
    HANDLE file_handle_;
    std::vector<std::wstring> embedded_signers_;
    std::vector<std::wstring> catalog_signers_;
    DWORD embedded_trusted_; // 0: Unknown, 1: No, 2: Yes
    DWORD catalog_trusted_;  // 0: Unknown, 1: No, 2: Yes

    void OpenFile();
    void CloseFile();
    void ResetState();

public:
    FileSignature(const std::wstring& file_path);
    ~FileSignature();

    void Reset();
    bool IsSigned();
    std::vector<std::wstring> GetNameOfEmbeddedSigners();
    std::vector<std::wstring> GetNameOfCatalogSigners();
};

#endif // FILESIGNATURE_H