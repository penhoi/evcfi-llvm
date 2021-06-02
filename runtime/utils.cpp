#include "utils.h"
#include <ctype.h>
#include <functional>
#include <string>

KVPAIR::KVPAIR(const char *key, const char *val) {
  if (key != NULL)
    K = utils_strdup(key);
  else
    K = NULL;
  if (val != NULL)
    V = utils_strdup(val);
  else
    V = NULL;
}
KVPAIR::~KVPAIR() {
  if (K != NULL)
    free(K);
  if (V != NULL)
    free(V);
}

/**
 * trim the whitespace before and after a string
 * @str: mutable string
 */
char *utils_trimwhitespace(char *str) {
  // assert(str != NULL);
  // Trim leading space
  while (isspace((unsigned char)*str))
    str++;

  if (*str == 0) // All spaces?
    return str;

  // Trim trailing space
  char *end = str + strlen(str) - 1;
  while (end > str && isspace((unsigned char)*end))
    end--;

  // Write new null terminator character
  end[1] = '\0';

  return str;
}

char *utils_trimcomment(char *szLine) {
  // assert(szLine != NULL);
  char *str = utils_trimwhitespace(szLine);

  /* start a comment ? */
  if (*str == '#')
    *str = 0;

  /* append with comment ? */
  char *shap = strchr(str, '#');
  if (shap != NULL)
    *shap = 0;

  return str;
}

/**
 * Nasty thing happeed to use gcc::strdup
 * So implement my own version
 */
char *utils_strdup(const char *s) {
  size_t size = strlen(s) + 4;
  size = (size >> 2) << 2; // 4 bytes align
  char *str = (char *)malloc(size);

  strcpy(str, s);
  return str;
}

uint32_t utils_hashstrs(const char *str) {
  std::size_t h1 = std::hash<std::string>{}(str);
  return (uint32_t)(h1);
}

size_t utils_hashstrs(const char *s1, const char *s2) {
  std::size_t h1 = std::hash<std::string>{}(s1);
  std::size_t h2 = std::hash<std::string>{}(s2);

  return (size_t)(h1 ^ (h2 << 1));
}
