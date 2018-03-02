#include <tchar.h>
#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <conio.h>
#pragma comment (lib, "advapi32")
#define ENCRYPT_ALGORITHM CALG_RC4

int _tmain(int argc, _TCHAR* argv[])
{
    if(argc < 3)
    {
        _tprintf(TEXT("Usage: Kix-Decrypt.exe sourceFile destinationFile "));
        return 1;
    }

    HANDLE hSourceFile = INVALID_HANDLE_VALUE;
    HANDLE hDestinationFile = INVALID_HANDLE_VALUE;
    LPCTSTR pszSourceFile = argv[1];
    LPTSTR pszDestination = argv[2];
    PBYTE pbBuffer = NULL;
    PBYTE pbBufferPasswd = NULL;
    PBYTE auxPointer = NULL;
    DWORD dwCount;
    HCRYPTPROV hCryptProv = NULL;
    HCRYPTKEY hKey = NULL;
    HCRYPTHASH hHash = NULL;
    DWORD dwFileSize;
    DWORD counter;

    hSourceFile = CreateFile(
        pszSourceFile,
        FILE_READ_DATA,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if(INVALID_HANDLE_VALUE != hSourceFile)
    {
        _tprintf(
            TEXT("The source file: %s is open. \n"),
            pszSourceFile);
    }
    else
    {
        MyHandleError(
            TEXT("Error opening source file!\n"),
            GetLastError());
        goto Exit_MyDecryptFile;
    }

    hDestinationFile = CreateFile(
        pszDestination,
        FILE_WRITE_DATA,
        FILE_SHARE_READ,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if(INVALID_HANDLE_VALUE != hDestinationFile)
    {
         _tprintf(
             TEXT("The destination file: %s is open. \n"),
             pszDestination);
    }
    else
    {
        MyHandleError(
            TEXT("Error opening destination file!\n"),
            GetLastError());
        goto Exit_MyDecryptFile;
    }

    if(!(pbBufferPasswd = (PBYTE)malloc(22)))
    {
       MyHandleError(TEXT("Out of memory!\n"), E_OUTOFMEMORY);
       goto Exit_MyDecryptFile;
    }

    if(!ReadFile(
            hSourceFile,
            pbBufferPasswd,
            22,
            &dwCount,
            NULL))
        {
            MyHandleError(
                TEXT("Error reading from source file!\n"),
                GetLastError());
            goto Exit_MyDecryptFile;
        }

    if(CryptAcquireContext(
            &hCryptProv,
            NULL,
            MS_DEF_PROV,
            1,
            0))
        {
            _tprintf(
                TEXT("A cryptographic provider has been acquired. \n"));
        }
    else
        {
            MyHandleError(
                TEXT("Error during CryptAcquireContext!\n"),
                GetLastError());
            goto Exit_MyDecryptFile;
        }

    if(!CryptCreateHash(
               hCryptProv,
               CALG_MD5,
               0,
               0,
               &hHash))
        {
            MyHandleError(
                TEXT("Error during CryptCreateHash!\n"),
                GetLastError());
            goto Exit_MyDecryptFile;
        }

    printf("The retrived key is:");
    for(counter=6; counter < 22; counter++)
        {
            printf("%x",pbBufferPasswd[counter]);
        }

    if(!CryptHashData(
               hHash,
               &pbBufferPasswd[6],
               16,
               0))
        {
            MyHandleError(
                TEXT("Error during CryptHashData!\n"),
                GetLastError());
            goto Exit_MyDecryptFile;
        }

    if(!CryptDeriveKey(
              hCryptProv,
              ENCRYPT_ALGORITHM,
              hHash,
              0,
              &hKey))
        {
            MyHandleError(
                TEXT("Error during CryptDeriveKey!\n"),
                GetLastError()) ;
            goto Exit_MyDecryptFile;
        }

        dwFileSize = GetFileSize(hSourceFile,NULL);

    if(!(pbBuffer = (PBYTE)malloc(dwFileSize)))
        {
            MyHandleError(TEXT("Out of memory!\n"), E_OUTOFMEMORY);
            goto Exit_MyDecryptFile;
        }


    if(!ReadFile(
            hSourceFile,
            pbBuffer,
            dwFileSize,
            &dwCount,
            NULL))
        {
            MyHandleError(
                TEXT("Error reading from source file!\n"),
                GetLastError());
            goto Exit_MyDecryptFile;
        }

    if(!(auxPointer = (PBYTE)malloc(dwFileSize-22)))
        {
            MyHandleError(TEXT("Out of memory!\n"), E_OUTOFMEMORY);
            goto Exit_MyDecryptFile;
        }

        memcpy(auxPointer, pbBuffer, dwFileSize-22);
        printf("\nDecrypting file: %s \n",pszSourceFile);
        dwCount = dwFileSize-22;

    if(!CryptDecrypt(
              hKey,
              0,
              1,
              0,
              auxPointer,
              &dwCount))
        {
            MyHandleError(
                TEXT("Error during CryptDecrypt!\n"),
                GetLastError());
            goto Exit_MyDecryptFile;
        }

    printf("Writing the decrypted data to the destination file: %s \n",pszDestination);
    if(!WriteFile(
            hDestinationFile,
            auxPointer,
            dwCount,
            &dwCount,
            NULL))
        {
            MyHandleError(
                TEXT("Error writing ciphertext.\n"),
                GetLastError());
            goto Exit_MyDecryptFile;
        }

        printf("Done!");

Exit_MyDecryptFile:
    if(hSourceFile)
    {
        CloseHandle(hSourceFile);
    }
}

void MyHandleError(LPTSTR psz, int nErrorNumber)
{
    _ftprintf(stderr, TEXT("Error. \n"));
    _ftprintf(stderr, TEXT("%s\n"), psz);
    _ftprintf(stderr, TEXT("Number:%x.\n"), nErrorNumber);
}
