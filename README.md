What is the GadgetWrecker?
==========================

The GadgetWrecker is an experimental defence against memory corruption exploits that rely on return oriented programming (ROP).
I started writing this tool because of my continued inability to develop 3l33t 0-day 3xpl01t5 and join the cool guys. 
If you can't join them, beat them!
The concept is very simple: return oriented exploits need RETurn instructions to function. Remove, replace or move the majority of RETurn instructions and the exploits start failing.
This experimental tool aims to destroy the coherence between library locations in memory and return instructions.

If the concept is so simple why hasn't is been done before?
===============================================

The problem with moving arbitrary sequences of instructions of a running program is that other instructions might 'point' or 'branch' into the moved instructions. 
This is not much of a problem if all the pointers and branches were visible at compiletime, sadly the x86/x64 ISA allows for 'free branch' instructions. Which can only be intercepted at runtime. 
This adds a great deal of complexity to the problem, and if that wasn't bad enough some of the free-branches are less than 5 bytes in size, which means that they cannot be replaced by a simple static jump.

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

The attacked can:
    - Write and read from the stack

The attacker cannot:
    - Read an arbitrary amount of memory
    - Write an arbitrary amount of memory

   Milestones
===========================================

Analysis of arbitrary executables and rewriting RETurn instructions 
Analysis and interdiction of free branch instructions with a size of 5 bytes and longer                              <====== We are here
Analysis and interdiction of free bracnh instructions with a size of 2 bytes and longer
Analysis and interdiction of static branch instructions of any size
Caching intercepted calls by writing them to the 'shortlist' (see cGenASM.hpp as of 31/12/2016)

1.0 release (if ever): Running all known vulnerable versions of the firefox browser with at least 20 tabs for 30 minutes without crashing and crashing all public exploits for that version.

