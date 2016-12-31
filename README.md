What is the GadgetWrecker?
==========================

The GadgetWrecker is an experimental tool that aims to defend against memory corruption exploits that rely on return oriented programming (ROP).
I started writing this tool because of my continued inability to develop 3l33t 0-day 3xpl01t5 and join the cool guys. 
If you can't join them, beat them!
The concept is very simple: return oriented exploits need RETurn instructions to function. Remove, replace or move the majority of RETurn instructions and the exploits start failing.
This experimental tool aims to destroy the coherence between library locations in memory and return instructions.

If the concept is so simple why hasn't is been done before?
===============================================

Maybe it has been, I don't know. The problem with moving arbitrary sequences of instructions of a running program is that other instructions might 'point' or 'branch' into the moved instructions. 
This is not much of a problem if all the pointers and branches were visible at compiletime, sadly the x86/x64 ISA allows for 'free branch' instructions. Which can only be intercepted at runtime. 
This adds a great deal of complexity to the problem. If that wasn't bad enough some of the free-branches are less than 5 bytes in size, which means that they cannot be replaced by a simple static jump.

STILL worse are 'unaligned instructions'. Consider the following instruction:

		774C74A3 | B8 54 C3 12 15                 | mov eax,1512C354                                                                                                                                                                        |                                                                                                                                                              |

Seems legit, no danger here. What can an attacker possibly achieve with this? Well... 
What about this?

		774C74A4 | 54                              | push esp                                                                                                                                                                                     |
		774C74A5 | C3                              | ret                                                                                                                                                                                     |

Oops...

Rewriting these instructions will be beyond the scope of the GadgetWrecker, however all 'aligned' return instructions and branches will be fair game.

All of this has my doubting my sanity already, and there is no doubt in my mind that I will spend hours debugging crashes at locations MILES from the actual bug (has already happened 2x)



What is the 'threat model' this tool operates under?
===========================================

This tool aims to prevent successful exploitation of memory corruption exploits under the following conditions:

This tool is operating on:

	- A 32 bit Windows system targeting a 32 bit Windows application ALREADY protected by both ASLR and DEP
	- A 64 bit Windows system targeting a 32 bit Windows application ALREADY protected by both ASLR and DEP running under WOW.
    
The attacker has full control over: 

    - All registers, including EIP

The attacker knows:

    - The exact location and exact version of all modules
    - The location of the heap and the stack

The attacker can:

    - Write and read from the stack

The attacker cannot:

    - Read an arbitrary amount of memory
    - Write an arbitrary amount of memory

   Milestones
===========================================

    - Partial analysis of arbitrary executables and rewriting RETurn instructions 
    - Partial analysis and interdiction of free branch instructions with a size of 5 bytes and longer                              <====== We are here
    - Partial analysis and interdiction of free bracnh instructions with a size of 2 bytes and longer
    - Partial analysis and interdiction of static branch instructions of any size
    - Best effort analysis and interdiction of branches
    - Caching intercepted calls by writing them to the 'shortlist' (see cGenASM.hpp as of 31/12/2016)
    - 1.0 release (if ever): Running all known vulnerable versions of the firefox browser with at least 20 tabs for 30 minutes without crashing and crashing all public exploits for that version.

