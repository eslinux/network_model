This is a basic port of the lwIP - A Lightweight TCP/IP Stack by 
Adam Dunkels of the Swedish Institute of Computer Science. The
lwIP web page can be found here: http://www.sics.se/~adam/lwip/

For this demo, only minimal changes have been made on the 
CVS version from 06.03.03.2003 to make it work with the Keil C166 
compiler and Keil MCB167-NET evaluation board. 
All changes in the source code are marked with "*** CS ***" and 
the original code has been left as comment.

The "dumpwebpage" HTTP server is a very primitive example of
a low-level API lwIP program. It is listening at port 80 and
dumps a HTML page after any request command. It can serve one
request at once (Note: this is a limitation of the sample 
HTTP server, lwIP can handle a bigger number of simultaneous
connections over several concurrent network interfaces).

To get familiar with the lwIP stack, please have a look at the
lwIP web page and search the mailing list (linked from the
web page). The configuration of lwIP is mainly done in the
"lwipopts.h" file. The current lwIP port for C166 works only 
in polling mode.

Edit "main.c" to configure IP, netmask and gateway. Attach
the MCB157-NET ethernet port to a 10 BASE-T capable hub or
switch. Now use telnet or your web browser to connect the
running lwIP application.

There are two predefined targets:

  MCB167-NET Hardware      : Settings for Keil MCB167-NET Board,
                             fast with very little debug output
  MCB167-NET Hardware Debug: Settings for Keil MCB167-NET Board,
                             generates a lot of debug infos


