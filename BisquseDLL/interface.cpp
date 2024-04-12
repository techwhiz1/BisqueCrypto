#include "BisqueCrypto.h"
#include <memory>
#include <zlib.h>


/*
	return: pointer to a MD159 ("inst" used in all functions below)
*/
extern "C" __declspec(dllexport)
void* __cdecl CreateFromKey(const char* key)
{
	auto pInst = new MD159();
	pInst->InitializeKey(key, strlen(key));
	return static_cast<void*>(pInst);
}

/*
	-- Encrypt in MD159 & Encode in RBase64

	data: pointer to data to encrypt
	length: size of data to encrypt
	return: encrypted data output buffer
*/
extern "C" __declspec(dllexport)
void* __cdecl Encrypt(void* inst, const char* data, int length)
{
	if (length)
	{
		// encrypt MD159
		std::vector<uint8> buffer;
		((MD159*)inst)->Encrypt((const uint8*)data, length, buffer);

		// encode R-Base64
		std::string encoded = RB64Encode(buffer.data(), buffer.size());
		void* buffOut = malloc(encoded.size() + 2);
		if (buffOut)
			strcpy_s((char*)buffOut, encoded.size() + 1, encoded.c_str());

		return buffOut;
	}
	return 0;
}

/*
	-- Decode RBase64 & Decrypt MD159 --

	data: data to decrypt
	out: ref to a output pointer buffer to decrypted data

	return: size of decrypted data
*/
extern "C" __declspec(dllexport)
int __cdecl Decrypt(void* inst, const char* data, char*& out)
{
	if (strlen(data))
	{
		// decode R-Base64
		auto decoded = RB64Decode(data);

		// decrypt MD159
		std::vector<uint8> decrypted;
		((MD159*)inst)->Decrypt((const uint8*)decoded.data(), decoded.size(), decrypted);

		int decSz = decrypted.size();
		void* buffOut = malloc(decSz + 2);
		if (buffOut) {
			memcpy(buffOut, decrypted.data(), decSz);
			((uint8*)buffOut)[decSz] = 0x00;
		}

		out = (char*)buffOut;
		return decSz;
	}
	return 0;
}


extern "C" __declspec(dllexport)
int __cdecl DecryptNTY(void* inst, const char* data, uint32 size, char*& out, bool isCompressed)
{
	if (size >= 16)
	{
		MD159& ctx = *(MD159*)inst;

		// decrypt MD144
		uint32 fileDataBlockSz = bswap32(*(uint32*)(data + 4));
		std::vector<uint8> decrypted;
		ctx.DecryptMD144(((const uint8*)data) + 16, fileDataBlockSz, decrypted);

		uint8* pDecBuf = decrypted.data();
		uint32 decBufSz = decrypted.size();

		// decompression inflate
		std::vector<uint8> outVector;

		if (isCompressed)
		{
			z_stream inflateStr = {};
			inflateStr.zalloc = 0;
			inflateStr.zfree = 0;
			inflateStr.next_in = (uint8_t*)pDecBuf;
			inflateStr.avail_in = (uint32)decBufSz;
			int err = inflateInit_(&inflateStr, ZLIB_VERSION, (int)sizeof(inflateStr));

			inflateStr.avail_in = decBufSz;
			inflateStr.next_in = pDecBuf;

			uint8 decompressStack[2048];
			for (;;)
			{
				inflateStr.next_out = (Bytef*)decompressStack;
				inflateStr.avail_out = (uint32)sizeof(decompressStack);

				int ret = inflate(&inflateStr, Z_NO_FLUSH);

				uint32 szDecompress = sizeof(decompressStack) - inflateStr.avail_out;
				if (szDecompress == 0)
					break;

				outVector.insert(outVector.end(), decompressStack, decompressStack + szDecompress);

				if (ret == Z_STREAM_END)
					break;
			}

			err = inflateEnd(&inflateStr);
		}
		else
			outVector = std::move(decrypted);


		int decSz = outVector.size();
		void* buffOut = malloc(decSz + 2);
		if (buffOut) {
			memcpy(buffOut, outVector.data(), decSz);
			((uint8*)buffOut)[decSz] = 0x00;
		}

		out = (char*)buffOut;
		return decSz;
	}
	return 0;
}



/*
	Doit être utiliser pour libérer une instance MD159
	lorsqu'elle n'est plus nécessaire.
*/
extern "C" __declspec(dllexport)
void __cdecl ReleaseInst(void* inst) {
	if (inst)
		delete ((MD159*)inst);
}

/*
	Doit être utiliser pour libérer:
		- Du retour de l'appel à Encrypt
		- De la variable "out" de l'appel à Decrypt
*/
extern "C" __declspec(dllexport)
void __cdecl ReleaseBuffer(void* buffer) {
	if (buffer)
		free(buffer);
}


BOOL __stdcall DllMain(HINSTANCE hModule, DWORD dwReason, LPVOID lpReserved)
{
	if (dwReason == DLL_PROCESS_ATTACH)
	{ }
	else if (dwReason == DLL_PROCESS_DETACH)
	{ }
	return TRUE;
}
