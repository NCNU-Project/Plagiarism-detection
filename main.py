#!/bin/env python3
import re
import hashlib
from difflib import SequenceMatcher

def kgrams(content, k=4):
    """
    a generator to generate all pair of k-element array of content

    :param content: the list we want to return k-element list
    :param k: the k-element we want to return
    :return: return the k-element list
    """
    n = len(content)

    if(n < k):
        # padding the content to k token
        yield content
    else:
        for i in range(n - k + 1):
            yield content[i : i + k]

def winnowing_hash(content):
    """
    hash the content with sha1, and return the hash last 24bits of hash(transform to int)

    :param content: the string we want to hash
    :return: last 24bits of hash(transform to int)
    """

    hashed_content = hashlib.sha1(content.encode('utf-8'))

    # only take last 4 bits to comapre minimal when doing winnowing process
    hashed_content = hashed_content.hexdigest()[-6]
    # print(content, hashed_content)
    return int(hashed_content, 16)

def min_index(arr):
    """
    return the minimal value's index in input array

    :param arr: the array we want to find minimal value
    :return: the index of the minimal in the input array
    """

    min_idx = 0
    min_val = arr[0]

    for (key, val) in enumerate(arr):
        if val < min_val:
            min_idx = key
            min_val = val
    return min_idx

def winnowing(content, k=4, window_size=4):
    """
    find the minimal hash of each window, and return the input content's fingerprint

    :param content: the list we want to apply winnowing algorithm
    :param k: use k-gram
    :param window_size: the window size
    :return: the fingerprint's list we find
    """

    # generate k-element content's list
    contents = kgrams(content,k)
    hashes = list(map(lambda x: winnowing_hash(''.join(x)), contents))

    # cache the hash
    cache = dict(zip(hashes, map(lambda  x: ' '.join(x),kgrams(content, k))))

    print("cache hashes", cache)
    # generate window_size-element hashed list
    windows = kgrams(hashes, window_size)

    # get the fingerprints
    cur_min = prev_min = 0
    fingerprint_list = []
    for (idx, window_element) in enumerate(windows):
        cur_min = idx + min_index(window_element)
        if prev_min != cur_min:
            fingerprint_list.append(window_element[cur_min - idx])
            prev_min = cur_min

    # print the local minimum(fingerprint)
    print("\nprint the local minimum(fingerprint)")
    print(fingerprint_list, cache.keys())
    for fp in fingerprint_list:
        print(cache[fp])
    return fingerprint_list

def sanitize(content):
    """
    find the minimal hash of each window, and return the input content's fingerprint

    :param content: the list we want to sanitize with c++'s grammer
    :return: the sanitized list
    """

    datatypes = "ATOM BOOL BOOLEAN BYTE CHAR COLORREF DWORD DWORDLONG DWORD_PTR \
    DWORD32 DWORD64 FLOAT HACCEL HALF_PTR HANDLE HBITMAP HBRUSH \
    HCOLORSPACE HCONV HCONVLIST HCURSOR HDC HDDEDATA HDESK HDROP HDWP \
    HENHMETAFILE HFILE HFONT HGDIOBJ HGLOBAL HHOOK HICON HINSTANCE HKEY \
    HKL HLOCAL HMENU HMETAFILE HMODULE HMONITOR HPALETTE HPEN HRESULT \
    HRGN HRSRC HSZ HWINSTA HWND INT INT_PTR INT32 INT64 LANGID LCID LCTYPE \
    LGRPID LONG LONGLONG LONG_PTR LONG32 LONG64 LPARAM LPBOOL LPBYTE LPCOLORREF \
    LPCSTR LPCTSTR LPCVOID LPCWSTR LPDWORD LPHANDLE LPINT LPLONG LPSTR LPTSTR \
    LPVOID LPWORD LPWSTR LRESULT PBOOL PBOOLEAN PBYTE PCHAR PCSTR PCTSTR PCWSTR \
    PDWORDLONG PDWORD_PTR PDWORD32 PDWORD64 PFLOAT PHALF_PTR PHANDLE PHKEY PINT \
    PINT_PTR PINT32 PINT64 PLCID PLONG PLONGLONG PLONG_PTR PLONG32 PLONG64 POINTER_32 \
    POINTER_64 PSHORT PSIZE_T PSSIZE_T PSTR PTBYTE PTCHAR PTSTR PUCHAR PUHALF_PTR \
    PUINT PUINT_PTR PUINT32 PUINT64 PULONG PULONGLONG PULONG_PTR PULONG32 PULONG64 \
    PUSHORT PVOID PWCHAR PWORD PWSTR SC_HANDLE SC_LOCK SERVICE_STATUS_HANDLE SHORT \
    SIZE_T SSIZE_T TBYTE TCHAR UCHAR UHALF_PTR UINT UINT_PTR UINT32 UINT64 ULONG \
    ULONGLONG ULONG_PTR ULONG32 ULONG64 USHORT USN VOID WCHAR WORD WPARAM WPARAM WPARAM "
    types = "char bool short int __int32 __int64 __int8 __int16 long float double __wchar_t \
    clock_t _complex _dev_t _diskfree_t div_t ldiv_t _exception _EXCEPTION_POINTERS \
    FILE _finddata_t _finddatai64_t _wfinddata_t _wfinddatai64_t __finddata64_t \
    __wfinddata64_t _FPIEEE_RECORD fpos_t _HEAPINFO _HFILE lconv intptr_t \
    jmp_buf mbstate_t _off_t _onexit_t _PNH ptrdiff_t _purecall_handler \
    sig_atomic_t size_t _stat __stat64 _stati64 terminate_function \
    time_t __time64_t _timeb __timeb64 tm uintptr_t _utimbuf \
    va_list wchar_t wctrans_t wctype_t wint_t signed "
    match_type_pattern = '|'.join((datatypes + types).split())

    var_name_arr = []
    func_name_arr = []
    pair_cnt = 4
    for idx in range(len(content) - pair_cnt):
        if re.match(match_type_pattern, content[idx]) is not None:
            # it will be function or variable
            if content[idx + 2] == '=':
                var_name_arr.append(content[idx + 1])
            elif content[idx + 1] != 'main':
                func_name_arr.append(content[idx + 1])

    for idx in range(len(content)):
        if content[idx] in var_name_arr:
            content[idx] = 'V'
        elif content[idx] in func_name_arr:
            content[idx] = 'F'
    print("sanitize", content)
    return content

def _token(content):
    """
    tokenize the content of cpp code

    :param content: the list we want to token with cpp
    :return: the token list
    """

    datatypes = "ATOM BOOL BOOLEAN BYTE CHAR COLORREF DWORD DWORDLONG DWORD_PTR \
    DWORD32 DWORD64 FLOAT HACCEL HALF_PTR HANDLE HBITMAP HBRUSH \
    HCOLORSPACE HCONV HCONVLIST HCURSOR HDC HDDEDATA HDESK HDROP HDWP \
    HENHMETAFILE HFILE HFONT HGDIOBJ HGLOBAL HHOOK HICON HINSTANCE HKEY \
    HKL HLOCAL HMENU HMETAFILE HMODULE HMONITOR HPALETTE HPEN HRESULT \
    HRGN HRSRC HSZ HWINSTA HWND INT INT_PTR INT32 INT64 LANGID LCID LCTYPE \
    LGRPID LONG LONGLONG LONG_PTR LONG32 LONG64 LPARAM LPBOOL LPBYTE LPCOLORREF \
    LPCSTR LPCTSTR LPCVOID LPCWSTR LPDWORD LPHANDLE LPINT LPLONG LPSTR LPTSTR \
    LPVOID LPWORD LPWSTR LRESULT PBOOL PBOOLEAN PBYTE PCHAR PCSTR PCTSTR PCWSTR \
    PDWORDLONG PDWORD_PTR PDWORD32 PDWORD64 PFLOAT PHALF_PTR PHANDLE PHKEY PINT \
    PINT_PTR PINT32 PINT64 PLCID PLONG PLONGLONG PLONG_PTR PLONG32 PLONG64 POINTER_32 \
    POINTER_64 PSHORT PSIZE_T PSSIZE_T PSTR PTBYTE PTCHAR PTSTR PUCHAR PUHALF_PTR \
    PUINT PUINT_PTR PUINT32 PUINT64 PULONG PULONGLONG PULONG_PTR PULONG32 PULONG64 \
    PUSHORT PVOID PWCHAR PWORD PWSTR SC_HANDLE SC_LOCK SERVICE_STATUS_HANDLE SHORT \
    SIZE_T SSIZE_T TBYTE TCHAR UCHAR UHALF_PTR UINT UINT_PTR UINT32 UINT64 ULONG \
    ULONGLONG ULONG_PTR ULONG32 ULONG64 USHORT USN VOID WCHAR WORD WPARAM WPARAM WPARAM "
    types = "char bool short int __int32 __int64 __int8 __int16 long float double __wchar_t \
    clock_t _complex _dev_t _diskfree_t div_t ldiv_t _exception _EXCEPTION_POINTERS \
    FILE _finddata_t _finddatai64_t _wfinddata_t _wfinddatai64_t __finddata64_t \
    __wfinddata64_t _FPIEEE_RECORD fpos_t _HEAPINFO _HFILE lconv intptr_t \
    jmp_buf mbstate_t _off_t _onexit_t _PNH ptrdiff_t _purecall_handler \
    sig_atomic_t size_t _stat __stat64 _stati64 terminate_function \
    time_t __time64_t _timeb __timeb64 tm uintptr_t _utimbuf \
    va_list wchar_t wctrans_t wctype_t wint_t signed "

    keywords = "break case catch class const __finally __exception __try \
    const_cast continue private public protected __declspec \
    else enum explicit extern if for friend goto inline \
    mutable naked namespace new noinline noreturn nothrow \
    register reinterpret_cast return selectany \
    sizeof static static_cast struct switch template this \
    thread throw true false try typedef typeid typename union \
    using uuid virtual void volatile whcar_t while stdin "

    functions = "assert isalnum isalpha iscntrl isdigit isgraph islower isprint\
    ispunct isspace isupper isxdigit tolower toupper errno localeconv \
    setlocale acos asin atan atan2 ceil cos cosh exp fabs floor fmod \
    frexp ldexp log log10 modf pow sin sinh sqrt tan tanh jmp_buf \
    longjmp setjmp raise signal sig_atomic_t va_arg va_end va_start \
    clearerr fclose feof ferror fflush fgetc fgetpos fgets fopen \
    fprintf fputc fputs fread freopen fscanf fseek fsetpos ftell \
    fwrite getchar getch getc main gets perror printf putc putchar puts remove \
    cout cin \
    rename rewind scanf setbuf setvbuf sprintf sscanf tmpfile tmpnam \
    ungetc vfprintf vprintf vsprintf abort abs atexit atof atoi atol \
    bsearch calloc div exit free getenv labs ldiv malloc mblen mbstowcs \
    mbtowc qsort rand realloc srand strtod strtol strtoul system \
    wcstombs wctomb memchr memcmp memcpy memmove memset strcat strchr \
    strcmp strcoll strcpy strcspn strerror strlen strncat strncmp \
    strncpy strpbrk strrchr strspn strstr strtok strxfrm asctime \
    clock ctime difftime gmtime localtime mktime strftime time "

    # token that can be add without a space. eg: cin<<a, we want to token it as ['cin', '<<', 'a']
    pattern="\{ \} # \( \) , ; \" \' & << >> \+\+ -- "
    math="\+ - \* \/ == != = % < > "

    # all tokens
    tokens = (datatypes + types + keywords + functions + pattern + math)
    # delete some unnessary space charactors
    tokens = tokens.split()

    # generate the regex expression to token the content
    replacePatten = "({})| ".format('|'.join(tokens))
    # print(replacePatten)
    content = content.strip();


    # split by token and keep token in tokened content
    tokened_context = re.split(replacePatten, content)
    # filter the empty string in tokened_context
    tokened_context = list(filter(None , tokened_context))

    # tokened_context = ' '.join(tokened_context)
    # print(tokened_context)
    return tokened_context

def make(content, kgram = 4, window_size = 25):
    """
    tokenize the content of cpp code

    :param content: the Cpp code
    :param k: use k-gram
    :param window_size: the window size
    :return: the fingerprint list
    """

    content = re.sub(r'\n|\s+', ' ', content)
    # print("clean space and newline", content)
    # tokenize
    tokArr = _token(content)
    sanitized_tok_arr = sanitize(tokArr)
    local_minimum = winnowing(sanitized_tok_arr, kgram, window_size)
    return local_minimum


def main():
    kgram = 4
    window_size = 25
    code1 = """
#include<cstdio>
#include<cstring>
#include<algorithm>
using namespace std;
const int maxn=200010;
int n,q,p[maxn],cur,mid,l,r,fail[maxn],a[maxn],b[maxn],ans,nww;
char s[maxn],t[maxn],rev[maxn];
int main()
{
	scanf("%s",s+1);n=strlen(s+1);
	t[0]='@';for(int i=1;i<=n;i++)t[i]=s[i],b[i]=n+1;t[n+1]='#';
	q=n+1;mid=r=1;
	for(int i=1;i<=q;i++)
	{
		if(i<=r)p[i]=min(p[mid+mid-i],r-i+1);
		while(t[i-p[i]]==t[i+p[i]])p[i]++;
		if(i+p[i]-1>=r)r=i+p[i]-1,mid=i;
	}
	for(int i=1;i<=n;i++)rev[i]=s[n-i+1];
	for(int i=2,j=0;i<=n;i++)
	{
		while(j&&rev[i]!=rev[j+1])j=fail[j];
		if(rev[i]==rev[j+1])j++;
		fail[i]=j;
	}
	for(int i=1,j=0;i<=n;i++)
	{
		while(j&&s[i]!=rev[j+1])j=fail[j];
		if(s[i]==rev[j+1])j++;
		a[i]=j;if(b[j]==n+1)b[j]=i;
	}
	/*
	printf("%s\n",rev+1);
	for(int i=1;i<=n;i++)printf("%d ",fail[i]);printf("\n");
	for(int i=1;i<=n;i++)printf("%d ",a[i]);printf("\n");
	for(int i=1;i<=n;i++)printf("%d ",b[i]);printf("\n");
	*/
	for(int i=1;i<=n;i++)
	{
		l=0;r=n+1;
		while(l+1<r)
		{
			int mid=(l+r)>>1;
			if(i-p[i]+1>b[mid]&&i+p[i]-1<n-mid+1)l=mid;
			else r=mid;
		}
		ans=max(ans,2*p[i]-1+2*l);
	}
	//printf("%d\n",ans);
	for(int i=1;i<=n;i++)
	{
		l=0;r=n+1;
		while(l+1<r)
		{
			int mid=(l+r)>>1;
			if(i-p[i]+1>b[mid]&&i+p[i]-1<n-mid+1)l=mid;
			else r=mid;
		}
		if(ans==2*p[i]-1+2*l)
		{
			if(l==0)printf("1\n%d %d\n",i-p[i]+1,2*p[i]-1);
			else printf("3\n%d %d\n%d %d\n%d %d\n",b[l]-l+1,l,i-p[i]+1,2*p[i]-1,n-l+1,l);
			return 0;
		}
	}
	return 0;
}
    """
    fingerprint_list_1 = make(code1, kgram, window_size)

    print()

    code2 = """
#include<cstring>
#include<algorithm>
#include<cstdio>
using namespace std;
int n,q,p[maxn],cur,mid,l,r,fail[maxn],a[maxn],b[maxn],ans,nww;
const int maxn=200010;
char s[maxn],t[maxn],rev[maxn];
int main()
{
	scanf("%s",s+1);n=strlen(s+1);
	q=n+1;mid=r=1;
	t[0]='@';for(int i=1;i<=n;i++)t[i]=s[i],b[i]=n+1;t[n+1]='#';
	for(int i=1;i<=q;i++)
	{
		while(t[i-p[i]]==t[i+p[i]])p[i]++;
		if(i<=r)p[i]=min(p[mid+mid-i],r-i+1);
		if(i+p[i]-1>=r)r=i+p[i]-1,mid=i;
	}
	for(int i=1;i<=n;i++)rev[i]=s[n-i+1];
	for(int i=2,j=0;i<=n;i++)
	{
		while(j&&rev[i]!=rev[j+1])j=fail[j];
		if(rev[i]==rev[j+1])j++;
		fail[i]=j;
	}
	for(int i=1,j=0;i<=n;i++)
	{
		while(j&&s[i]!=rev[j+1])j=fail[j];
		if(s[i]==rev[j+1])j++;
		a[i]=j;if(b[j]==n+1)b[j]=i;
	}
	/*
	printf("%s\n",rev+1);
	for(int i=1;i<=n;i++)printf("%d ",fail[i]);printf("\n");
	for(int i=1;i<=n;i++)printf("%d ",a[i]);printf("\n");
	for(int i=1;i<=n;i++)printf("%d ",b[i]);printf("\n");
	*/
	for(int i=1;i<=n;i++)
	{
		l=0;r=n+1;
		while(l+1<r)
		{
			int mid=(l+r)>>1;
			if(i-p[i]+1>b[mid]&&i+p[i]-1<n-mid+1)l=mid;
			else r=mid;
		}
		ans=max(ans,2*p[i]-1+2*l);
	}
	//printf("%d\n",ans);
	for(int i=1;i<=n;i++)
	{
		l=0;r=n+1;
		while(l+1<r)
		{
			int mid=(l+r)>>1;
			if(i-p[i]+1>b[mid]&&i+p[i]-1<n-mid+1)l=mid;
			else r=mid;
		}
		if(ans==2*p[i]-1+2*l)
		{
			if(l==0)printf("1\n%d %d\n",i-p[i]+1,2*p[i]-1);
			else printf("3\n%d %d\n%d %d\n%d %d\n",b[l]-l+1,l,i-p[i]+1,2*p[i]-1,n-l+1,l);
			return 0;
		}
	}
	return 0;
}
    """
    fingerprint_list_2 = make(code2, kgram, window_size)

    # check the fingerprint occurence
    SM = SequenceMatcher(None, ''.join([str(i) for i in sorted(fingerprint_list_1)]),\
                         ''.join([str(i) for i in sorted(fingerprint_list_2)]))
    print(''.join([str(i) for i in sorted(fingerprint_list_1)]))
    print(''.join([str(i) for i in sorted(fingerprint_list_2)]))
    print("simular ratio", SM.ratio())

if __name__ == "__main__":
    main()
