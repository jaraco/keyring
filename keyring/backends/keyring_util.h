/*
 * pykeyring_util.h
 *
 * Some useful function for pykeyring lib
 */
#ifndef PYKEYRING_UTIL_H
#define PYKEYRING_UTIL_H
char *
string_dump(const char *s,int n)
{
    char *res;
    if (s == NULL)
        return NULL;
    res = malloc(n+1);
    memcpy(res,s,n);
    res[n] = '\0';
    return res;
}

#endif //PYKEYRING_UTIL_H
