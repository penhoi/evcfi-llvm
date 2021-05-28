## VLOOM-LLVM design

Vloom-llvm adds an extra pass to LLVM. This pass operates at IR-level, and instruments an  inline-assembly code before each vcallsite. 

Vloom-pass can be configured with a lot of environment variables, thus users can flexibly control this pass. For instance, VLOOM_DISABLED is to disable the vloom-pass. Other variables can control the size and content of instrumented NOP sled.



| Environment Variable | Data Type | Value Range | Default Value | Explanation |
| :------------------: | :----------: | :-----------: |:-----------: | :------------------: |
| VLOOM_DISABLED       | BOOL | [1] | false |  |
| VLOOM_MODE           | unsigned | [1, 2,3,4] |1| 1: compatible mode,  or 2: poison mode, 3: flag mode, 4: trace mode |
| VLOOM_SIZE | unsigned | [14 - 256) |64| Bytes of nop-sled |
| VLOOM_SCRATCH | unsigned | [1,2,3] |2| Number of scratch registers |
| VLOOM_REGSET | unsigned | [1,2] |1| 1: rdx, rsi, rdi; 2: r11, r10, r9 |
| VLOOM_PASS_DEBUG | BOOL | Any |false| Generate IR file |






#0  0x000000000059fff3 in xercesc_2_5::XMLString::transcode (toTranscode=0xda83a0 "en_US", toFill=0xabc000 <xercesc_2_5::XMLMsgLoader::fLanguage>, maxChars=2, manager=0xda5760) at XMLString.cpp:611
#1  0x0000000000590d9f in xercesc_2_5::XMLMsgLoader::setLocale (localeToAdopt=0x841f80 <xercesc_2_5::XMLUni::fgXercescDefaultLocale> "en_US") at XMLMsgLoader.cpp:122
#2  0x00000000004ed0bc in xercesc_2_5::XMLPlatformUtils::Initialize (locale=0x841f80 <xercesc_2_5::XMLUni::fgXercescDefaultLocale> "en_US", nlsHome=0x0, panicHandler=<optimized out>, memoryManager=<optimized out>) at PlatformUtils.cpp:353
#3  0x000000000072f500 in xsltMain (argc=4, argv=0x7fffffffdad8) at XalanExe.cpp:810
#4  0x00007ffff6e91b97 in __libc_start_main (main=0x72f770 <main(int, char**)>, argc=4, argv=0x7fffffffdad8, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffdac8) at ../csu/libc-start.c:310
#5  0x0000000000404eea in _start ()

   0x000000000059ff90 <+0>:	mov    %rcx,%r8
   0x000000000059ff93 <+3>:	mov    %edx,%r9d
   0x000000000059ff96 <+6>:	mov    %rsi,%r10
   0x000000000059ff99 <+9>:	mov    %rdi,%rcx
   0x000000000059ff9c <+12>:	mov    0x530965(%rip),%rdi        # 0xad0908 <_ZN11xercesc_2_5L11gTranscoderE>
   0x000000000059ffa3 <+19>:	mov    (%rdi),%rax
   0x000000000059ffa6 <+22>:	data16 nopw 0x0(%rax,%rax,1)
   0x000000000059ffb0 <+32>:	data16 data16 nopw 0x0(%rax,%rax,1)
   0x000000000059ffbb <+43>:	movabs $0x3e4f32310df6aaab,%rdi
   0x000000000059ffc5 <+53>:	imul   %rax,%rdi
   0x000000000059ffc9 <+57>:	xor    %esi,%esi
   0x000000000059ffcb <+59>:	crc32q %rdi,%rsi
   0x000000000059ffd1 <+65>:	movzwl %si,%esi
   0x000000000059ffd4 <+68>:	movabs $0x2000292fe000,%rdx
   0x000000000059ffde <+78>:	testb  $0xff,(%rdx,%rsi,1)
   0x000000000059ffe2 <+82>:	jne    0x59ffe6 <xercesc_2_5::XMLString::transcode(char const*, unsigned short*, unsigned int, xercesc_2_5::MemoryManager*)+86>
   0x000000000059ffe4 <+84>:	ud2    
   0x000000000059ffe6 <+86>:	mov    0x40(%rax),%rax
   0x000000000059ffea <+90>:	mov    %rcx,%rsi
   0x000000000059ffed <+93>:	mov    %r10,%rdx
   0x000000000059fff0 <+96>:	mov    %r9d,%ecx
=> 0x000000000059fff3 <+99>:	jmpq   *%rax

