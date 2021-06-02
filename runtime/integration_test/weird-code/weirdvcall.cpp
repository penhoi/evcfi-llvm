#include <stdio.h>
#include <stdlib.h>
#include <string.h>

class FormatterListener {
public:
  virtual void characters(char *chars, int length) = 0;
  virtual void charactersRaw(char *chars, int length) = 0;
};

class FormatterToText : public FormatterListener {
  virtual void characters(char *chars, int length);
  virtual void charactersRaw(char *chars, int length);
};

void FormatterToText::characters(char *chars, int length)
{
  for (int i = 0; i < length; i++)
    chars[i] += 1;
}

void FormatterToText::charactersRaw(char *chars, int length)
{
  characters(chars, length);
  characters(chars, length);
}

class XPath {
public:
  typedef void (FormatterListener::*MemberFunctionPtr)(char *chars, int length);

  char *mBuf;
  int mLen;

  /**
   * Execute the XPath from the provided context.
   *
   * @param context          current source tree context node, which must not be 0
   * @param prefixResolver   prefix resolver to use
   * @param executionContext current execution context
   * @param formatterListener the FormatterListener instance to receive the result
   * @param function A pointer to the member function of FormatterListener to call
   */
  void execute(FormatterListener *formatterListener, MemberFunctionPtr function) const
  {
    (formatterListener->*function)(mBuf, mLen);
  }

  void doTransform(char *Data, int len)
  {
    mLen = len * 2;
    mBuf = (char *)malloc(mLen);
    memcpy(mBuf, Data, len);
  }

  char *getResult() { return mBuf; }
};

int main(int argc, char *argv[])
{
  int choice = strlen(argv[0]);

  FormatterListener *theAdapter = new FormatterToText();
  XPath::MemberFunctionPtr theFunction;

  printf("%s\n", argv[0]);
  if (choice % 2 == 0)
    theFunction = &FormatterListener::characters;
  else
    theFunction = &FormatterListener::charactersRaw;

  XPath *obj = new XPath();
  obj->doTransform(argv[0], choice);
  obj->execute(theAdapter, theFunction);
  printf("%s\n", obj->getResult());

  return 0;
}
