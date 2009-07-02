/*
 * keyring_util.h
 *
 * Some useful functions for keyring lib
 */
#ifndef KEYRING_UTIL_H
#define KEYRING_UTIL_H
char *
string_dump(const char *s,int n)
{
    char *res;
    if (s == NULL)
        return NULL;
    res = (char*) malloc(n+1);
    memcpy(res,s,n);
    res[n] = '\0';
    return res;
}
#endif //KEYRING_UTIL_H
