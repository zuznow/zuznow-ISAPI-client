/*++

Copyright (c) 2000 Microsoft Corporation.  All rights reserved.

--*/

/*
*
*  This filter is a flavor of the filter IIS uses for compression.
* (Original filter written by David Treadwell on July 1997.)
*
* ISA and IIS let you accumulate Requests chunks into a complete
* Request.
* The following filter is an example to a filter that collects the
* response chunks and then allows you to change them depending on the
* complete response.

* This filter works with 2 notifications.
* In Send Raw Data it collects the response's chunks, sends 0 bytes
* instead of them (i.e. sends nothing).

* Then, when all the chunks of this response passed Send Raw Data
* notification, ISA thinks the complete response was sent. So
* it calls End Of Request Notification. End Of Request Notification
* will be the place where we will send the complete response.
*
*/

#include "stdafx.h"
#include <windows.h>
#include <httpfilt.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <cstdio>
#include <fstream> 
#include "base64.h";
#include "RegExp.h";
#include "zlib/zlib.h"
#include <time.h>
#include <map>
#include <sstream> 
#include "md5.h"

#include "WinHttpClient.h";


map<string, string> gConfig;

static DWORD OnSendRawData(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_RAW_DATA pRawData);
static DWORD OnEndOfRequest(PHTTP_FILTER_CONTEXT pfc);
static void DisableNotifications(PHTTP_FILTER_CONTEXT pfc, DWORD   flags);
static int strnstr(const char *string, const char *strCharSet, int n);


#define DEFAULT_BUFFER_SIZE		1024
#define MAX_BUFFER_SIZE			4096
#define SKIP_FILTER_HEADER		"X-Skip-Mobile:"

#define DISABLE_NOTIFY_FLAGS SF_NOTIFY_END_OF_REQUEST | SF_NOTIFY_SEND_RAW_DATA | SF_NOTIFY_SEND_RESPONSE

typedef struct _HTTP_FILTER_ZUZ_DATA
{

	bool	useFilter;
	LPVOID	pZuzContext;
	clock_t	BeginTime;
	string	host;
	string	url;
	string method;
	string	userAgent;
	string	charset;
	bool	isAjax;
	bool	isSsl;

	

} HTTP_FILTER_ZUZ_DATA, *PHTTP_FILTER_ZUZ_DATA;


BOOL WINAPI TerminateFilter(DWORD dwFlags)
{
	UNREFERENCED_PARAMETER(dwFlags);
	return TRUE;
}

string& trim_right_inplace(string& s, const string& delimiters = " \f\n\r\t\v")
{
	return s.erase(s.find_last_not_of(delimiters) + 1);
}

string& trim_left_inplace(string& s, const string& delimiters = " \f\n\r\t\v")
{
	return s.erase(0, s.find_first_not_of(delimiters));
}

string& trim(std::string& s, const string& delimiters = " \f\n\r\t\v")
{
	return trim_left_inplace(trim_right_inplace(s, delimiters), delimiters);
}


string md5(string data)
{
	unsigned char md5res[16];
	string md5str;
	md5str.reserve(32);
	MD5_CTX md5Ctx;
	MD5_Init(&md5Ctx);
	MD5_Update(&md5Ctx, data.c_str(), data.length());
	MD5_Final(md5res, &md5Ctx);
	const char DEC2HEX[16 + 1] = "0123456789abcdef";
	for (int i = 0; i < 16; ++i)
	{
		md5str += DEC2HEX[md5res[i] >> 4];
		md5str += DEC2HEX[md5res[i] & 0x0F];

		return md5str;
	}
}



void readConf()
{
	ifstream inFile;

	const unsigned long maxDir = DEFAULT_BUFFER_SIZE;
	char  currentDir[DEFAULT_BUFFER_SIZE];

	HMODULE hm = NULL;

	if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
		GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
		(LPCSTR)&GetFilterVersion,
		&hm))
	{
		int ret = GetLastError();
		fprintf(stderr, "GetModuleHandle returned %d\n", ret);
	}
	GetModuleFileNameA(hm, currentDir, maxDir);

	//renove file name end extetion
	int end = strnlen(currentDir, maxDir);
	char * p = currentDir + end - 1;
	while (p != currentDir && *p != '\\')
	{
		*p-- = 0;

	}





	string confFile = currentDir;
	confFile += "conf.txt";
	inFile.open(confFile);
	if (gConfig.size())
	{
		gConfig.empty();
	}
	string line;
	while (getline(inFile, line))
	{
		trim(line);
		if (line.length())
		{
			stringstream ss(line);
			string key, val;
			getline(ss, key, '=');
			getline(ss, val, '=');
			trim(key);
			trim(val);
			if (key.length())
			{
				gConfig[key] = val;

			}
		}


	}

}

BOOL WINAPI GetFilterVersion(PHTTP_FILTER_VERSION pVer)
{
	if (pVer == NULL)
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	pVer->dwFilterVersion = HTTP_FILTER_REVISION;

	pVer->dwFlags = SF_NOTIFY_ORDER_HIGH | SF_NOTIFY_SECURE_PORT | SF_NOTIFY_NONSECURE_PORT
		| SF_NOTIFY_END_OF_REQUEST | SF_NOTIFY_SEND_RAW_DATA | SF_NOTIFY_SEND_RESPONSE | SF_NOTIFY_PREPROC_HEADERS;

	readConf();
	return TRUE;
}

int i = 0;
//DWORD headersBuffSize = 0;
//char headersBuff[2048];




wstring str2Wstr(string str)
{

	wstring buffer;
	/* Calculate buffer size */
	int result = MultiByteToWideChar(CP_UTF8, NULL, str.c_str(), str.length(), NULL, 0);
	if (result > 0)
	{
		/* Allocate buffer to hold Unicode form of above string */
		buffer.resize(result);

		/* Convert str to Unicode and store in buffer */
		result = MultiByteToWideChar(CP_UTF8, NULL, str.c_str(), str.length(), &buffer[0], result);
	}

	return buffer;
}

// Only alphanum is safe.
const char SAFE[256] =
{
	/*      0 1 2 3  4 5 6 7  8 9 A B  C D E F */
	/* 0 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	/* 1 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	/* 2 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	/* 3 */ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0,

	/* 4 */ 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	/* 5 */ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
	/* 6 */ 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
	/* 7 */ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,

	/* 8 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	/* 9 */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	/* A */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	/* B */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,

	/* C */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	/* D */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	/* E */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	/* F */ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

std::string UriEncode(const std::string & sSrc)
{
	const char DEC2HEX[16 + 1] = "0123456789ABCDEF";
	const unsigned char * pSrc = (const unsigned char *)sSrc.c_str();
	const int SRC_LEN = sSrc.length();
	unsigned char * const pStart = new unsigned char[SRC_LEN * 3];
	unsigned char * pEnd = pStart;
	const unsigned char * const SRC_END = pSrc + SRC_LEN;

	for (; pSrc < SRC_END; ++pSrc)
	{
		if (SAFE[*pSrc] || *pSrc == '"')
			*pEnd++ = *pSrc;
		else
		{
			// escape this char
			*pEnd++ = '%';
			*pEnd++ = DEC2HEX[*pSrc >> 4];
			*pEnd++ = DEC2HEX[*pSrc & 0x0F];
		}
	}

	std::string sResult((char *)pStart, (char *)pEnd);
	delete[] pStart;
	return sResult;
}



bool setPost(WinHttpClient &client, string post)
{
	wchar_t szSize[50] = L"";
	swprintf_s(szSize, L"%d", post.size());
	wstring headers = L"Content-Length: ";
	headers += szSize;
	headers += L"\r\nContent-Type: application/x-www-form-urlencoded\r\n";
	client.SetAdditionalDataToSend((BYTE *)post.c_str(), post.size());
	client.SetAdditionalRequestHeaders(headers);
	return true;


}



static DWORD Mobilize(PHTTP_FILTER_CONTEXT pfc)
{

	time_t time = clock();
	wstring APIServer = str2Wstr(gConfig["api_server"]);
	string domainId = gConfig["domain_id"];
	string APIKye = gConfig["api_key"];
	string cacheType = gConfig["cache_type"];
	string cacheTtl = gConfig["cache_ttl"];
	bool chacheSsl = (gConfig["cache_ssl"] == "true");
	string isAjax;
	string charset = gConfig["charset"].empty() ?  "UTF-8" : gConfig["charset"];
	bool forceSsl = (gConfig["http2https"] == "true");

	map<string, string> params;

	

	wstring apiUrl = APIServer + L"mobilize.php";
	WinHttpClient ApiClient(apiUrl);

	PHTTP_FILTER_ZUZ_DATA pZuzD = (PHTTP_FILTER_ZUZ_DATA)pfc->pFilterContext;
	PHTTP_FILTER_RAW_DATA pRawData = (PHTTP_FILTER_RAW_DATA)pZuzD->pZuzContext;
	string userAgent = pZuzD->userAgent;

	params["domain_id"] = domainId;
	params["key"] = APIKye;

	params["user_agent"] = userAgent;


	string reqUrl = pZuzD->isSsl | forceSsl ? "https://" : "http://";
	reqUrl += pZuzD->host + pZuzD->url;
	params["url"] = reqUrl;


	string rowData = (char*)pRawData->pvInData;
	int pos = rowData.find("\r\n\r\n");
	string headers = rowData.substr(0,pos+2);
	
	string stime = to_string((float)(time - pZuzD->BeginTime) / CLOCKS_PER_SEC);
	string backendTime = "X-Zuznow-backendTime:" + stime + "\r\n\r\n";
	headers += backendTime;
	
	//Content-Encoding
	bool srcGziped = false;
	int startPos = rowData.find("Content-Encoding:")+17;
	if (startPos != -1)
	{
		int endtPos = rowData.find("\r\n", startPos);
		string Content_Encoding = rowData.substr(startPos, endtPos - startPos);
		trim(Content_Encoding);
		if (Content_Encoding == "gzip")
		{
			srcGziped = true;
		}
	}
	

	if (!pZuzD->charset.empty())
	{
		charset = pZuzD->charset;
	}
	params["charset"] = charset;

	if (pZuzD->isAjax)
	{
		params["ajax"] = "true";
	}

	char *data = (char*)pRawData->pvInData +pos+4;

	unsigned long nDataSize = pRawData->cbInData-pos-4;

	std::string base64 = "";
	if (!srcGziped)
	{
		unsigned long nCompressedDataSize = compressBound(nDataSize) + 20;
		unsigned char * pCompressedData = new unsigned char[nCompressedDataSize];

		int nResult = compress(pCompressedData, &nCompressedDataSize, (BYTE *)data, nDataSize);
		base64 = base64_encode(pCompressedData, nCompressedDataSize);
		//data is now nice and safe in base64 string
		delete[] pCompressedData;
	}
	else
	{
		base64 = base64_encode((BYTE *)data, nDataSize);
	}

	
	params["data"] = base64;

	

	if (cacheType == "anonymous" && pZuzD->method == "GET" )
	{
		params["cache_key"] = md5(reqUrl);
	}
	if (cacheType == "personalized")
	{
		params["cache_key"] = md5(data);
	}
	string post = "";
	map<string, string>::iterator it;
	for (it = params.begin(); it != params.end(); it++)
	{
		post += "&" + it->first + "=" + UriEncode(it->second);
	}


	setPost(ApiClient, post);

	bool sucess = false;
	int errNum = 0;
	ApiClient.SendHttpRequest(L"POST", true);
	wstring status = ApiClient.GetResponseStatusCode();

	const BYTE *httpResponseRow;
	DWORD httpResponseRowSize;


	WinHttpClient CacheClient(L"");
	if (status == L"200")
	{
		httpResponseRow = ApiClient.GetRawResponseContent();
		httpResponseRowSize = ApiClient.GetRawResponseReceivedContentLength();
		sucess = true;
	}
	else if (status == L"302")
	{

		wstring cacheUrl = ApiClient.GetResponseLocation();
		string urlParams = "&key=" + APIKye + "&domain_id=" + domainId + "&cache_ttl=" + cacheTtl + "&user_agent=" + UriEncode(userAgent) + "&charset=" + UriEncode(charset);
		wstring wUrlParams = str2Wstr(urlParams);
		cacheUrl += wUrlParams;
		CacheClient.UpdateUrl(cacheUrl);
		wstring apiHGeaders = ApiClient.GetResponseHeader();
		wstring 	regExp = L"X-LBZUZ:\\b*{.+?}\\n";
		vector<wstring> result;
		if (ParseRegExp(regExp, false, 1, apiHGeaders, result) && result.size() > 0)
		{
			CacheClient.SetAdditionalRequestHeaders(L"X-LBZUZ:"+result[0]);
			CacheClient.SetAdditionalRequestCookies(L"LBZUZ=" + result[0] + L"; ");

		}
		CacheClient.SendHttpRequest();

		wstring status = CacheClient.GetResponseStatusCode();
		int count = 60;
		if (!gConfig["timeout"].empty())
		{
			count = stoi(gConfig["timeout"]) *4;
		}
		while (status != L"" && status != L"200" && count)
		{
			--count;
			Sleep(250);
			CacheClient.SendHttpRequest();
			status = CacheClient.GetResponseStatusCode();

		}

		if (status == L"200")
		{
			httpResponseRow = CacheClient.GetRawResponseContent();
			httpResponseRowSize = CacheClient.GetRawResponseReceivedContentLength();
			sucess = true;
		}
		else if (status == L"404")
		{
			errNum = 2;
		}
		else
		{
			errNum = 3;
		}

	}
	else
	{
		errNum = 1;
	}


	if (sucess)
	{
		
		if (srcGziped)
		{
			unsigned long nCompressedDataSize = compressBound(httpResponseRowSize) + 20;
			unsigned char * pCompressedData = new unsigned char[nCompressedDataSize];

			int nResult = compress(pCompressedData, &nCompressedDataSize, (BYTE *)httpResponseRow, nCompressedDataSize);
			
			//set new Content-Length
			int posSart = headers.find("Content-Length:");
			if (posSart != -1)
			{
				int posEnd = headers.find("\r\n", posSart);
				string sLength = to_string(nCompressedDataSize);
				string content_Length = "\r\n";
				content_Length = "Content-Length: " + sLength;
				headers.replace(posSart, posEnd - posSart, content_Length);
			}
			DWORD headersSize = headers.size();
			pfc->WriteClient(pfc, (LPVOID)headers.c_str(), &headersSize, 0);

			DWORD ret;
			if (pfc->WriteClient(pfc, (LPVOID)pCompressedData, &nCompressedDataSize, 0))
			{
				ret = SF_STATUS_REQ_NEXT_NOTIFICATION;
			}
			else
			{
				ret = SF_STATUS_REQ_ERROR;
			}

			delete[] pCompressedData;
		}
		else
		{
			//set new Content-Length
			int posSart = headers.find("Content-Length:");
			if (posSart != -1)
			{
				int posEnd = headers.find("\r\n", posSart);
				string sLength = to_string(httpResponseRowSize);
				string content_Length = "\r\n";
				content_Length = "Content-Length: " + sLength;
				headers.replace(posSart, posEnd - posSart, content_Length);
			}
			DWORD headersSize = headers.size();
			pfc->WriteClient(pfc, (LPVOID)headers.c_str(), &headersSize, 0);

			DWORD ret;
			if (pfc->WriteClient(pfc, (LPVOID)httpResponseRow, &httpResponseRowSize, 0))
			{
				return true;
			}
			else
			{
				return false;
			}
		}

	}
	else
	{
		
		/*
		* if we had an error we return the original response 
		* and set an error in response header (we dont whant to tuch the respose body!)
		*/
		DWORD ret;

		unsigned long nDataSize = pRawData->cbInData;

		string errorHeader = "X-Zuznow-error:" + to_string(errNum) + "\r\n\r\n";
		headers.replace(headers.length() - 2, 2, errorHeader);

		DWORD headersSize = headers.size();
		pfc->WriteClient(pfc, (LPVOID)headers.c_str(), &headersSize, 0);

		if (pfc->WriteClient(pfc, (LPVOID)data, &nDataSize, 0))
		{
			return true;
		}

		else
		{
			return false;
		}
	}
	return false;



}

static DWORD SendMyRespose(PHTTP_FILTER_CONTEXT pfc)
{

	if (NULL == pfc)
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		return SF_STATUS_REQ_ERROR;
	}

	/*
	* Block the following SEND_RESPONSE and END_OF_REQUEST notifications for
	* this request. ( WriteClient() bellow will generate them.)
	*
	*/
	DisableNotifications(pfc, SF_NOTIFY_END_OF_REQUEST | SF_NOTIFY_SEND_RAW_DATA);



	bool Mobilized = Mobilize(pfc);

	/*
	* Empty Request data to make it ready for next response
	* in case the connection is kept alive
	*/
	pfc->pFilterContext = NULL;


	DWORD ret;
	if (Mobilized)
	{
		ret = SF_STATUS_REQ_NEXT_NOTIFICATION;
	}
	else
	{
		ret = SF_STATUS_REQ_ERROR;
	}
	return ret;
}


DWORD OnSendResponse(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_PREPROC_HEADERS pSR)
{
	DWORD                           dwRet = SF_STATUS_REQ_NEXT_NOTIFICATION;
	BOOL                            fRet = FALSE;
	CHAR                            pBuf[DEFAULT_BUFFER_SIZE];
	CHAR *                          pszBuf = pBuf;
	DWORD                           cbBuf = DEFAULT_BUFFER_SIZE;

	//chack if we realy need to do moblization and if not detach and dont even buffer the response
	if (pSR->HttpStatus != 200)
	{
		pfc->pFilterContext = NULL;
		DisableNotifications(pfc, DISABLE_NOTIFY_FLAGS);
		return dwRet;
	}


	fRet = pSR->GetHeader(pfc, "Content-Type:", pszBuf, &cbBuf);
	if (fRet)
	{
		if ((strnstr(pszBuf, "text/html", cbBuf) == -1) && (strnstr(pszBuf, "text/plain", cbBuf) == -1))
		{
			pfc->pFilterContext = NULL;
			DisableNotifications(pfc, DISABLE_NOTIFY_FLAGS);
			return dwRet;
		}
		int pos = strnstr(pszBuf, "charset=", cbBuf);
		if (pos != -1)
		{
			PHTTP_FILTER_ZUZ_DATA pZuzD = (PHTTP_FILTER_ZUZ_DATA)pfc->pFilterContext;
			if (pZuzD)
			{
				pZuzD->charset.assign(pszBuf + pos + 8);
			}
		}


	}

	cbBuf = DEFAULT_BUFFER_SIZE;

	PHTTP_FILTER_ZUZ_DATA pZuzD = (PHTTP_FILTER_ZUZ_DATA)pfc->pFilterContext;
	if (pZuzD)
	{
		//cheak for skip header
		fRet = pSR->GetHeader(pfc, SKIP_FILTER_HEADER, pszBuf, &cbBuf);
		if (fRet)
		{
			if (strnstr(pszBuf, "true", cbBuf) != -1)
			{
				pfc->pFilterContext = NULL;
				DisableNotifications(pfc, DISABLE_NOTIFY_FLAGS);
				return dwRet;
			}
		}
	}

	return dwRet;

}
DWORD OnPreprocHeaders(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_SEND_RESPONSE  pPPH)
{

	DWORD dwRet = SF_STATUS_REQ_NEXT_NOTIFICATION;
	BOOL fRet = FALSE;
	CHAR pBuf[DEFAULT_BUFFER_SIZE];
	CHAR * pszBuf = pBuf;
	DWORD cbBuf = DEFAULT_BUFFER_SIZE;

	BOOL useFilter = FALSE;

	clock_t start = clock();
	string  userAgentStr;

	SetLastError(NO_ERROR);
	//chack for mobtest=true
	fRet = pfc->GetServerVariable(pfc, "QUERY_STRING", pszBuf, &cbBuf);
	if (fRet)
	{
		if (strnstr(pszBuf, "mobtest=true", cbBuf) != -1)
		{
			pfc->AddResponseHeaders(pfc, "Set-Cookie: mobtest=true; path=/;\r\n", NULL);
			useFilter = true;
		}
	}
	else
	{
		if (GetLastError() == ERROR_INSUFFICIENT_BUFFER &&  cbBuf < MAX_BUFFER_SIZE)
		{
			pszBuf = new CHAR[cbBuf];
			if (pszBuf == NULL)
			{
				SetLastError(ERROR_NOT_ENOUGH_MEMORY);
				return SF_STATUS_REQ_ERROR;
			}
			if (strnstr(pszBuf, "mobtest=true", cbBuf) != -1)
			{
				pfc->AddResponseHeaders(pfc, "Set-Cookie: mobtest=true path=/;\r\n", NULL);
				useFilter = true;
			}
			if (pszBuf != pBuf)
			{
				delete pszBuf;
				pszBuf = pBuf;
			}
		}
	}

	if (useFilter)
	{
		goto finish;
	}

	cbBuf = DEFAULT_BUFFER_SIZE;
	fRet = pPPH->GetHeader(pfc, "Cookie:", pszBuf, &cbBuf);
	//cheak cookie
	if (fRet)
	{
		if (strnstr(pszBuf, "mobtest=true", cbBuf) != -1)
		{

			useFilter = true;
		}
	}
	else
	{
		if (GetLastError() == ERROR_INSUFFICIENT_BUFFER &&  cbBuf < MAX_BUFFER_SIZE)
		{
			pszBuf = new CHAR[cbBuf];
			if (pszBuf == NULL)
			{
				SetLastError(ERROR_NOT_ENOUGH_MEMORY);
				return SF_STATUS_REQ_ERROR;
			}
			fRet = pPPH->GetHeader(pfc, "Cookie:", pszBuf, &cbBuf);
			if (strnstr(pszBuf, "mobtest=true", cbBuf) != -1)
			{
				useFilter = true;
			}
			if (pszBuf != pBuf)
			{
				delete pszBuf;
				pszBuf = pBuf;
			}
		}
	}

	if (useFilter)
	{
		goto finish;
	}

	

finish:

	cbBuf = DEFAULT_BUFFER_SIZE;
	fRet = pPPH->GetHeader(pfc, "User-Agent:", pszBuf, &cbBuf);
	if (fRet)
	{
		if (strnstr(pszBuf, "iphone", cbBuf) != -1)
		{
			useFilter = true;
		}

		if (strnstr(pszBuf, "Android", cbBuf) != -1 && strnstr(pszBuf, "Mobile", cbBuf) != -1)
		{
			useFilter = true;
		}
		userAgentStr = pszBuf;

	}
	else
	{
		if (GetLastError() == ERROR_INSUFFICIENT_BUFFER &&  cbBuf < MAX_BUFFER_SIZE)
		{
			pszBuf = new CHAR[cbBuf];
			if (pszBuf == NULL)
			{
				SetLastError(ERROR_NOT_ENOUGH_MEMORY);
				return SF_STATUS_REQ_ERROR;
			}
			fRet = pPPH->GetHeader(pfc, "User-Agent:", pszBuf, &cbBuf);
			if (strnstr(pszBuf, "iphone", cbBuf) != -1)
			{
				useFilter = true;
			}

			if (strnstr(pszBuf, "Android", cbBuf) != -1 && strnstr(pszBuf, "Mobile", cbBuf) != -1)
			{
				useFilter = true;
			}

			userAgentStr = pszBuf;

			if (pszBuf != pBuf)
			{
				delete pszBuf;
				pszBuf = pBuf;
			}
		}
	}

	if (useFilter)
	{
		pfc->pFilterContext = (LPVOID)pfc->AllocMem(pfc, sizeof(HTTP_FILTER_ZUZ_DATA), 0);
		if (NULL == pfc->pFilterContext)
		{
			DisableNotifications(pfc, DISABLE_NOTIFY_FLAGS);
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			return SF_STATUS_REQ_ERROR;
		}

		PHTTP_FILTER_ZUZ_DATA pZuzD = (PHTTP_FILTER_ZUZ_DATA)pfc->pFilterContext;
		pZuzD->useFilter = useFilter;
		pZuzD->BeginTime = start;
		pZuzD->pZuzContext = NULL;
		pZuzD->userAgent = userAgentStr;
		pZuzD->isAjax = false;

		cbBuf = DEFAULT_BUFFER_SIZE;
		fRet = pPPH->GetHeader(pfc, "X-Requested-With:", pszBuf, &cbBuf);
		if (fRet)
		{
			if (strnstr(pszBuf, "xmlhttprequest", cbBuf) != -1)
			{
				pZuzD->isAjax = true;
			}
		}
		fRet = pPPH->GetHeader(pfc, "X-MicrosoftAjax:", pszBuf, &cbBuf);
		if (fRet)
		{
			pZuzD->isAjax = true;
		}

		cbBuf = DEFAULT_BUFFER_SIZE;
		fRet = pfc->GetServerVariable(pfc, "UNENCODED_URL", pszBuf, &cbBuf);
		if (fRet)
		{
			pZuzD->url = pszBuf;
		}
		else
		{
			if (GetLastError() == ERROR_INSUFFICIENT_BUFFER &&  cbBuf < MAX_BUFFER_SIZE)
			{
				pszBuf = new CHAR[cbBuf];
				if (pszBuf == NULL)
				{
					SetLastError(ERROR_NOT_ENOUGH_MEMORY);
					return SF_STATUS_REQ_ERROR;
				}

				pZuzD->url = pszBuf;

				if (pszBuf != pBuf)
				{
					delete pszBuf;
					pszBuf = pBuf;
				}
			}
		}

		cbBuf = DEFAULT_BUFFER_SIZE;
		fRet = pfc->GetServerVariable(pfc, "HTTP_HOST", pszBuf, &cbBuf);
		if (fRet)
		{
			pZuzD->host = pszBuf;
		}
		else
		{
			if (GetLastError() == ERROR_INSUFFICIENT_BUFFER &&  cbBuf < MAX_BUFFER_SIZE)
			{
				pszBuf = new CHAR[cbBuf];
				if (pszBuf == NULL)
				{
					SetLastError(ERROR_NOT_ENOUGH_MEMORY);
					return SF_STATUS_REQ_ERROR;
				}

				pZuzD->host = pszBuf;

				if (pszBuf != pBuf)
				{
					delete pszBuf;
					pszBuf = pBuf;
				}
			}
		}

		cbBuf = DEFAULT_BUFFER_SIZE;
		fRet = pfc->GetServerVariable(pfc, "REQUEST_METHOD", pszBuf, &cbBuf);
		if (fRet)
		{
			pZuzD->method = pszBuf;
		}
		else
		{
			if (GetLastError() == ERROR_INSUFFICIENT_BUFFER &&  cbBuf < MAX_BUFFER_SIZE)
			{
				pszBuf = new CHAR[cbBuf];
				if (pszBuf == NULL)
				{
					SetLastError(ERROR_NOT_ENOUGH_MEMORY);
					return SF_STATUS_REQ_ERROR;
				}

				pZuzD->method = pszBuf;

				if (pszBuf != pBuf)
				{
					delete pszBuf;
					pszBuf = pBuf;
				}
			}
		}

		cbBuf = DEFAULT_BUFFER_SIZE;
		fRet = pfc->GetServerVariable(pfc, "HTTPS", pszBuf, &cbBuf);
		if (fRet)
		{
			if (_stricmp(pszBuf, "on") == 0)
			{
				pZuzD->isSsl = true;
			}
			else
			{
				pZuzD->isSsl = false;
			}
		}
	}
	else
	{
		DisableNotifications(pfc, DISABLE_NOTIFY_FLAGS);
	}


	return dwRet;
}

DWORD WINAPI HttpFilterProc(
	PHTTP_FILTER_CONTEXT pfc,
	DWORD NotificationType,
	LPVOID pvNotification
	)
{

	DWORD dwRet = SF_STATUS_REQ_NEXT_NOTIFICATION;

	switch (NotificationType)
	{
	case SF_NOTIFY_PREPROC_HEADERS:
		dwRet = OnPreprocHeaders(pfc, (PHTTP_FILTER_PREPROC_HEADERS)pvNotification);
		break;
	case SF_NOTIFY_SEND_RAW_DATA:
		dwRet = OnSendRawData(pfc, (PHTTP_FILTER_RAW_DATA)pvNotification);
		break;
	case SF_NOTIFY_END_OF_REQUEST:
		//dwRet = OnEndOfRequest(pfc);
		dwRet = SendMyRespose(pfc);
		break;
	case	SF_NOTIFY_SEND_RESPONSE:
		dwRet = OnSendResponse(pfc, (PHTTP_FILTER_SEND_RESPONSE)pvNotification);
		break;
	default:
		// We cannot reach here, unless Web Filter support has a BAD ERROR.
		SetLastError(ERROR_INVALID_PARAMETER);
		dwRet = SF_STATUS_REQ_ERROR;
		break;
	}

	return dwRet;
}


/*
* OnSendRawData():
* During Send Raw Data Notification we do the following:
* 1) Append each chunk to an accumulation buffer (pRawData->cvInData).
* 2) Resize the Current chunk to 0 ( don't send anything.)
*/
static DWORD OnSendRawData(PHTTP_FILTER_CONTEXT pfc, PHTTP_FILTER_RAW_DATA pInRawData)
{

	DWORD dwReserved = 0;
	PHTTP_FILTER_ZUZ_DATA pZuzD = (PHTTP_FILTER_ZUZ_DATA)pfc->pFilterContext;

	/*
	* Called first time for this request - then allocate pRawData.
	*/
	if (NULL == pZuzD->pZuzContext)
	{

		pZuzD->pZuzContext = (LPVOID)pfc->AllocMem(pfc, sizeof(HTTP_FILTER_RAW_DATA), dwReserved);
		if (NULL == pfc->pFilterContext)
		{
			DisableNotifications(pfc, SF_NOTIFY_END_OF_REQUEST | SF_NOTIFY_SEND_RAW_DATA);
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			return SF_STATUS_REQ_ERROR;
		}

		PHTTP_FILTER_RAW_DATA pRawData = (PHTTP_FILTER_RAW_DATA)pZuzD->pZuzContext;

		pRawData->cbInBuffer = pInRawData->cbInBuffer;
		pRawData->pvInData = (LPVOID)pfc->AllocMem(pfc, pRawData->cbInBuffer, dwReserved);
		if (NULL == pRawData->pvInData)
		{
			DisableNotifications(pfc, DISABLE_NOTIFY_FLAGS);
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			return SF_STATUS_REQ_ERROR;
		}

		pRawData->cbInData = 0;
		pRawData->dwReserved = pInRawData->dwReserved;
		//memcpy((LPVOID)headersBuff, pInRawData->pvInData, pInRawData->cbInData);
		//headersBuffSize = pInRawData->cbInData;

		//pInRawData->cbInData = 0;
		//return SF_STATUS_REQ_NEXT_NOTIFICATION;
	}

	/*
	* Get the pRawData from the Request Context.
	*/
	PHTTP_FILTER_RAW_DATA pRawData = (PHTTP_FILTER_RAW_DATA)pZuzD->pZuzContext;

	/*
	* If Not enough buffer in pRawData -> increase buffer.
	*/
	if (pInRawData->cbInData + pRawData->cbInData > pRawData->cbInBuffer)
	{
		pRawData->cbInBuffer = pInRawData->cbInData + pRawData->cbInBuffer;
		LPBYTE lpBuffer = (LPBYTE)pfc->AllocMem(pfc, pRawData->cbInBuffer, dwReserved);
		if (NULL == lpBuffer)
		{
			DisableNotifications(pfc, DISABLE_NOTIFY_FLAGS);
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			return SF_STATUS_REQ_ERROR;
		}

		memcpy((LPVOID)lpBuffer, pRawData->pvInData, pRawData->cbInData);
		pRawData->pvInData = (void *)lpBuffer;

	}

	/*
	* Append InRawData ( new chunk )  to accumulation buffer.
	*/
	LPBYTE lpBuffer = (LPBYTE)pRawData->pvInData;
	memcpy((LPVOID)(&lpBuffer[pRawData->cbInData]), pInRawData->pvInData, pInRawData->cbInData);
	pRawData->cbInData = pRawData->cbInData + pInRawData->cbInData;

	/*
	* Mark current chunk as size 0 ( i.e. Don't send enything. )
	*/
	pInRawData->cbInData = 0;

	return SF_STATUS_REQ_NEXT_NOTIFICATION;
}




#define STRING_SIZE(str)    (sizeof(str) - 1)


/*
*
* Utility function to notify that a filter is not to be called
* to a notification throughout the lifetime of the current Request.
*
*/
static void DisableNotifications(PHTTP_FILTER_CONTEXT pfc, DWORD   flags)
{
	pfc->ServerSupportFunction(
		pfc,
		SF_REQ_DISABLE_NOTIFICATIONS,
		NULL,
		flags,
		0
		);
}

/*
* strnstr()
* finds first appearance of strCharSet in string ignoring
* letters case.
*/
static int strnstr(const char *string, const char *strCharSet, int n)
{
	int len = (strCharSet != NULL) ? ((int)strlen(strCharSet)) : 0;

	if (0 == n || 0 == len)
	{
		return -1;
	}

	int ret = -1;
	BOOLEAN found = FALSE;
	for (int I = 0; I <= n - len && !(found); I++)
	{
		int J = 0;
		for (; J < len; J++)
		{
			if (toupper(string[I + J]) != toupper(strCharSet[J]))
			{
				break; // Exit For(J)
			}
		}

		if (J == len)
		{
			found = TRUE;
			ret = I;
		}
	}

	return ret;
}

