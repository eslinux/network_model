/******************************************************************
 *****                                                        *****
 *****  Name: webconverter.cpp                                *****
 *****  Ver.: 1.0                                             *****
 *****  Date: 07/03/2001                                      *****
 *****  Auth: Andreas Dannenberg                              *****
 *****        HTWK Leipzig                                    *****
 *****        university of applied sciences                  *****
 *****        Germany                                         *****
 *****        adannenb@et.htwk-leipzig.de                     *****
 *****  03/2003  CS  added feature to set custom array names  *****
 *****  Func: converts HTML-code to a C-constant              *****
 *****                                                        *****
 ******************************************************************/

//---------------------------------------------------------------------------
#include <stdio.h>


#pragma hdrstop
//---------------------------------------------------------------------------

int main(int argc, char* argv[])
{
  FILE *in, *out;
  char InChar;

  if (argc < 3)
  {
    fprintf(stdout, "Usage: html2h <infile> <outfile> [name]\r\n");
    fprintf(stdout, "Based on WebConverter by Andreas Dannenberg, modified by Christian Scheurer\r\n");
	

    return 1;
  }

  if ((in = fopen(argv[1], "rb")) == NULL)
  {
    fprintf(stderr, "Cannot open input file.\n");
    return 1;
  }

  if ((out = fopen(argv[2], "wb")) == NULL)
  {
    fprintf(stderr, "Cannot open output file.\n");
    return 1;
  }

  if(argc == 3) {
    fprintf(stdout, "Using default name: WebSide\r\n");
	fprintf(out, "const unsigned char WebSide[] = {\r\n\"");
  }
  else {
    fprintf(stdout, "Using custom name: %s\r\n", argv[3]);
	fprintf(out, "const unsigned char %s[] = {\r\n\"", argv[3]);
  }

  while (!feof(in))
  {
    InChar = fgetc(in);
    switch (InChar)
    {
      case 0x22 : fputc('\\', out);
                  fputc('"', out);
                  break;
      case 0x0D : fputc('\\', out);
                  fputc('r', out);
                  fputc('\\', out);
                  fputc('n', out);
                  fputc('"', out);
                  fprintf(out, "\r\n");
                  fputc('"', out);
                  break;
      case 0x0A : break;
      case EOF  : break;
      default   : fputc(InChar, out);
    }
  }

  fputc('\\', out);
  fputc('r', out);
  fputc('\\', out);
  fputc('n', out);

  fputc('"', out);
  fprintf(out, "};\r\n");

  fclose(in);
  fclose(out);

  return 0;
}
//---------------------------------------------------------------------------
