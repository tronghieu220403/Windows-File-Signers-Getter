#include <iostream>
#include "FileSignature.h"

int wmain(int argc, wchar_t* argv[])
{
    std::vector<std::wstring> file_paths = {
        L"C:\\Program Files\\Internet Explorer\\iexplore.exe",
        L"C:\\Program Files\\Internet Explorer\\ExtExport.exe",
        L"C:\\Windows\\System32\\cmd.exe",
    };

    for (const auto& file_path : file_paths)
    {
        std::wcout << L"File " << file_path << std::endl;
        FileSignature file_signature(file_path);

        if (file_signature.IsSigned())
        {
            std::wcout << L"File is trusted." << std::endl;
        }
        else
        {
            std::wcout << L"File is NOT trusted." << std::endl;
        }

        std::wcout << L"Embedded Signers:" << std::endl;
        for (const auto& signer : file_signature.GetNameOfEmbeddedSigners())
        {
            std::wcout << L"  " << signer << std::endl;
        }

        std::wcout << L"Catalog Signers:" << std::endl;
        for (const auto& signer : file_signature.GetNameOfCatalogSigners())
        {
            std::wcout << L"  " << signer << std::endl;
        }
    }

    return 0;
}